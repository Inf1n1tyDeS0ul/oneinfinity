// SPDX-License-Identifier: GPL-2.0
/*
 * ssl_intercept.bpf.c — uprobe on SSL_write to capture plaintext data
 *
 * Attaches to SSL_write(SSL *ssl, const void *buf, int num).
 * Reads up to 4096 bytes from the user-space buffer and emits events via ringbuf.
 */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define DATA_SIZE 4096

struct ssl_event {
    u32 pid;
    u32 len;
    u8  data[DATA_SIZE];
};

/* Ringbuf map — 4 MB ring buffer */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 4 * 1024 * 1024);
} ssl_events SEC(".maps");

/*
 * SSL_write signature: int SSL_write(SSL *ssl, const void *buf, int num)
 *   PT_REGS arg0 = ssl  (ignored)
 *   PT_REGS arg1 = buf  (pointer to plaintext)
 *   PT_REGS arg2 = num  (length requested)
 */
SEC("uprobe/SSL_write")
int uprobe_ssl_write(struct pt_regs *ctx)
{
    u32 pid = (u32)(bpf_get_current_pid_tgid() >> 32);

    /* arg1: const void *buf */
    const void *buf = (const void *)PT_REGS_PARM2(ctx);
    /* arg2: int num */
    int num = (int)PT_REGS_PARM3(ctx);

    if (num <= 0 || !buf)
        return 0;

    struct ssl_event *ev = bpf_ringbuf_reserve(&ssl_events, sizeof(*ev), 0);
    if (!ev)
        return 0;

    ev->pid = pid;
    ev->len = (u32)(num < DATA_SIZE ? num : DATA_SIZE);


    /* Read from user-space plaintext buffer */
    bpf_probe_read_user(ev->data, ev->len, buf);

    bpf_ringbuf_submit(ev, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
