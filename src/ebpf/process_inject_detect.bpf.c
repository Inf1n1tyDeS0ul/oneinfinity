// SPDX-License-Identifier: GPL-2.0
/*
 * process_inject_detect.bpf.c — detect process injection attempts
 *
 * Monitors two injection vectors:
 *   1. ptrace(2) — kprobe on __x64_sys_ptrace to catch PTRACE_POKETEXT /
 *      PTRACE_POKEDATA / PTRACE_SETREGS and similar write requests.
 *   2. process_vm_writev(2) / process_vm_readv(2) — tracepoints on
 *      sys_enter_process_vm_writev and sys_enter_process_vm_readv.
 *
 * All events are emitted via ringbuf for oi-ebpf-trace userspace consumer.
 */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

/* Inject operation tags — kept small so the event struct stays cache-friendly */
#define INJECT_OP_PTRACE_WRITE  1
#define INJECT_OP_PTRACE_READ   2
#define INJECT_OP_PTRACE_OTHER  3
#define INJECT_OP_VM_WRITEV     4
#define INJECT_OP_VM_READV      5

/*
 * ptrace request codes we care about (from <sys/ptrace.h>).
 * We keep them here to avoid dependency on uapi headers at BPF compile time.
 */
#define PTRACE_PEEKTEXT   1
#define PTRACE_PEEKDATA   2
#define PTRACE_POKETEXT   4
#define PTRACE_POKEDATA   5
#define PTRACE_GETREGS   12
#define PTRACE_SETREGS   13

struct inject_event {
    __u32 attacker_pid;
    __u32 victim_pid;
    __u32 op;
    __u64 size;
    char  comm[16];
};

/* Ringbuf map — 4096*64 bytes = 256 KB ring buffer */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 4096 * 64);
} oi_ebpf_trace_inject SEC(".maps");

/* Helper: fill and submit an inject event */
static __always_inline int emit_inject(__u32 victim_pid, __u32 op, __u64 sz)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();

    struct inject_event *ev =
        bpf_ringbuf_reserve(&oi_ebpf_trace_inject, sizeof(*ev), 0);
    if (!ev)
        return 0;

    ev->attacker_pid = (__u32)(pid_tgid >> 32);
    ev->victim_pid   = victim_pid;
    ev->op           = op;
    ev->size         = sz;
    bpf_get_current_comm(ev->comm, sizeof(ev->comm));

    bpf_ringbuf_submit(ev, 0);
    return 0;
}

/* ── kprobe: ptrace syscall ─────────────────────────────────── */
/*
 * Prototype: long ptrace(long request, long pid, unsigned long addr,
 *                        unsigned long data)
 * arg0 = request  (PT_REGS_PARM1)
 * arg1 = pid      (PT_REGS_PARM2)
 */
SEC("kprobe/__x64_sys_ptrace")
int kprobe_ptrace(struct pt_regs *ctx)
{
    /* On x86-64 the syscall args live in the nested pt_regs pointed to by
     * the first argument of the syscall wrapper. */
    struct pt_regs *inner = (struct pt_regs *)PT_REGS_PARM1(ctx);

    long request = 0, pid_arg = 0;
    bpf_probe_read_kernel(&request, sizeof(request), &inner->di);
    bpf_probe_read_kernel(&pid_arg, sizeof(pid_arg),  &inner->si);

    __u32 op;
    if (request == PTRACE_POKETEXT || request == PTRACE_POKEDATA ||
        request == PTRACE_SETREGS)
        op = INJECT_OP_PTRACE_WRITE;
    else if (request == PTRACE_PEEKTEXT || request == PTRACE_PEEKDATA ||
             request == PTRACE_GETREGS)
        op = INJECT_OP_PTRACE_READ;
    else
        op = INJECT_OP_PTRACE_OTHER;

    return emit_inject((__u32)pid_arg, op, 0);
}

/* ── tracepoint: process_vm_writev ──────────────────────────── */
/*
 * sys_enter_process_vm_writev args:
 *   args[0] = pid   (remote pid)
 *   args[1] = local_iov
 *   args[2] = liovcnt
 *   args[3] = remote_iov
 *   args[4] = riovcnt
 *   args[5] = flags
 * We capture args[0] = remote pid and args[4] = riovcnt as a proxy for
 * the number of remote memory regions written (size field).
 */
SEC("tracepoint/syscalls/sys_enter_process_vm_writev")
int tp_process_vm_writev(struct trace_event_raw_sys_enter *ctx)
{
    __u32 remote_pid = (__u32)ctx->args[0];
    __u64 riovcnt    = (__u64)ctx->args[4];
    return emit_inject(remote_pid, INJECT_OP_VM_WRITEV, riovcnt);
}

/* ── tracepoint: process_vm_readv ───────────────────────────── */
/*
 * Same layout as process_vm_writev.
 */
SEC("tracepoint/syscalls/sys_enter_process_vm_readv")
int tp_process_vm_readv(struct trace_event_raw_sys_enter *ctx)
{
    __u32 remote_pid = (__u32)ctx->args[0];
    __u64 riovcnt    = (__u64)ctx->args[4];
    return emit_inject(remote_pid, INJECT_OP_VM_READV, riovcnt);
}

char _license[] SEC("license") = "GPL";
