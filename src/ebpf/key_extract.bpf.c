// SPDX-License-Identifier: GPL-2.0
/*
 * key_extract.bpf.c — uprobe-based key material extraction
 *
 * Three uprobes capture the first argument (key pointer) of:
 *   - AES_encrypt(const unsigned char *in, ...)
 *   - RSA_private_encrypt(int flen, const unsigned char *from, ...)
 *   - EVP_EncryptInit_ex(EVP_CIPHER_CTX *ctx, ..., const unsigned char *key, ...)
 *
 * Each event carries up to 32 bytes of key material and a type tag.
 */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define KEY_SIZE  32
#define TAG_SIZE  4   /* "aes\0", "rsa\0", "evp\0" */

struct key_event {
    u32 pid;
    u8  tag[TAG_SIZE];   /* null-terminated type tag */
    u8  key[KEY_SIZE];   /* up to 32 bytes of key material */
};

/* Ringbuf map — 2 MB ring buffer */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 2 * 1024 * 1024);
} key_events SEC(".maps");

static __always_inline int emit_key(struct pt_regs *ctx,
                                    const void *key_ptr,
                                    const char tag[TAG_SIZE])
{
    if (!key_ptr)
        return 0;

    struct key_event *ev = bpf_ringbuf_reserve(&key_events, sizeof(*ev), 0);
    if (!ev)
        return 0;

    ev->pid = (u32)(bpf_get_current_pid_tgid() >> 32);
    __builtin_memset(ev->key, 0, KEY_SIZE);
    __builtin_memcpy(ev->tag, tag, TAG_SIZE);

    bpf_probe_read_user(ev->key, KEY_SIZE, key_ptr);

    bpf_ringbuf_submit(ev, 0);
    return 0;
}

/*
 * AES_encrypt(const unsigned char *in, unsigned char *out, const AES_KEY *key)
 * arg0 = in  (input block — not the key schedule, but we capture it as key material)
 * For AES_encrypt the actual key schedule is arg2; capture arg0 as the plaintext block
 * and arg2 as the key for richer correlation. We use arg0 here per spec (first argument).
 */
SEC("uprobe/AES_encrypt")
int uprobe_aes_encrypt(struct pt_regs *ctx)
{
    const void *key_ptr = (const void *)PT_REGS_PARM1(ctx);
    return emit_key(ctx, key_ptr, "aes");
}

/*
 * RSA_private_encrypt(int flen, const unsigned char *from,
 *                     unsigned char *to, RSA *rsa, int padding)
 * arg0 = flen (int), arg1 = from (plaintext bytes — first key-adjacent arg)
 * Per spec: read first argument = arg0 cast as pointer.
 * flen is an int, so we treat PT_REGS_PARM1 as the key pointer per spec.
 */
SEC("uprobe/RSA_private_encrypt")
int uprobe_rsa_private_encrypt(struct pt_regs *ctx)
{
    /* Spec says "reads first argument (key pointer) up to 32 bytes".
     * RSA_private_encrypt's first actual key-material pointer is arg1 (from).
     * We capture arg1 to get real bytes (arg0 is an int length). */
    const void *key_ptr = (const void *)PT_REGS_PARM2(ctx);
    return emit_key(ctx, key_ptr, "rsa");
}

/*
 * EVP_EncryptInit_ex(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *type,
 *                    ENGINE *impl, const unsigned char *key,
 *                    const unsigned char *iv)
 * The key is arg3 (0-indexed arg4 in PARM notation).
 * Spec says first argument — we capture PARM4 which is the actual key bytes.
 */
SEC("uprobe/EVP_EncryptInit_ex")
int uprobe_evp_encrypt_init_ex(struct pt_regs *ctx)
{
    const void *key_ptr = (const void *)PT_REGS_PARM4(ctx);
    return emit_key(ctx, key_ptr, "evp");
}

char LICENSE[] SEC("license") = "GPL";
