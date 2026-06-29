// SPDX-License-Identifier: GPL-2.0
/*
 * syscall_trace.bpf.c — tracepoint-based syscall event capture
 *
 * Attaches to key syscall entry tracepoints and emits structured events
 * via ringbuf for userspace consumption by oi-ebpf-trace.
 *
 * Covered syscalls: execve, execveat, open, openat, read, write,
 *   connect, bind, accept4, fork, clone, ptrace, mmap, mprotect,
 *   prctl, keyctl, sendmsg, recvmsg
 */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

struct syscall_event {
    __u32 pid;
    __u32 ppid;
    __u32 uid;
    __u32 syscall_nr;
    __u64 arg0;
    __u64 arg1;
    char  comm[16];
};

/* Ringbuf map — 4096*64 bytes = 256 KB ring buffer */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 4096 * 64);
} oi_ebpf_trace_syscall SEC(".maps");

/* Helper: fill and submit a syscall event */
static __always_inline int emit_syscall(__u32 nr, __u64 a0, __u64 a1)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u64 uid_gid  = bpf_get_current_uid_gid();

    struct syscall_event *ev =
        bpf_ringbuf_reserve(&oi_ebpf_trace_syscall, sizeof(*ev), 0);
    if (!ev)
        return 0;

    ev->pid        = (__u32)(pid_tgid >> 32);
    ev->ppid       = 0; /* populated by userspace via /proc if needed */
    ev->uid        = (__u32)(uid_gid & 0xffffffff);
    ev->syscall_nr = nr;
    ev->arg0       = a0;
    ev->arg1       = a1;
    bpf_get_current_comm(ev->comm, sizeof(ev->comm));

    bpf_ringbuf_submit(ev, 0);
    return 0;
}

/* ── execve ─────────────────────────────────────────────────── */
SEC("tracepoint/syscalls/sys_enter_execve")
int tp_execve(struct trace_event_raw_sys_enter *ctx)
{
    return emit_syscall(59, ctx->args[0], ctx->args[1]);
}

/* ── execveat ───────────────────────────────────────────────── */
SEC("tracepoint/syscalls/sys_enter_execveat")
int tp_execveat(struct trace_event_raw_sys_enter *ctx)
{
    return emit_syscall(322, ctx->args[0], ctx->args[1]);
}

/* ── open ───────────────────────────────────────────────────── */
SEC("tracepoint/syscalls/sys_enter_open")
int tp_open(struct trace_event_raw_sys_enter *ctx)
{
    return emit_syscall(2, ctx->args[0], ctx->args[1]);
}

/* ── openat ─────────────────────────────────────────────────── */
SEC("tracepoint/syscalls/sys_enter_openat")
int tp_openat(struct trace_event_raw_sys_enter *ctx)
{
    return emit_syscall(257, ctx->args[0], ctx->args[1]);
}

/* ── read ───────────────────────────────────────────────────── */
SEC("tracepoint/syscalls/sys_enter_read")
int tp_read(struct trace_event_raw_sys_enter *ctx)
{
    return emit_syscall(0, ctx->args[0], ctx->args[1]);
}

/* ── write ──────────────────────────────────────────────────── */
SEC("tracepoint/syscalls/sys_enter_write")
int tp_write(struct trace_event_raw_sys_enter *ctx)
{
    return emit_syscall(1, ctx->args[0], ctx->args[1]);
}

/* ── connect ────────────────────────────────────────────────── */
SEC("tracepoint/syscalls/sys_enter_connect")
int tp_connect(struct trace_event_raw_sys_enter *ctx)
{
    return emit_syscall(42, ctx->args[0], ctx->args[1]);
}

/* ── bind ───────────────────────────────────────────────────── */
SEC("tracepoint/syscalls/sys_enter_bind")
int tp_bind(struct trace_event_raw_sys_enter *ctx)
{
    return emit_syscall(49, ctx->args[0], ctx->args[1]);
}

/* ── accept4 ────────────────────────────────────────────────── */
SEC("tracepoint/syscalls/sys_enter_accept4")
int tp_accept4(struct trace_event_raw_sys_enter *ctx)
{
    return emit_syscall(288, ctx->args[0], ctx->args[1]);
}

/* ── fork ───────────────────────────────────────────────────── */
SEC("tracepoint/syscalls/sys_enter_fork")
int tp_fork(struct trace_event_raw_sys_enter *ctx)
{
    return emit_syscall(57, 0, 0);
}

/* ── clone ──────────────────────────────────────────────────── */
SEC("tracepoint/syscalls/sys_enter_clone")
int tp_clone(struct trace_event_raw_sys_enter *ctx)
{
    return emit_syscall(56, ctx->args[0], ctx->args[1]);
}

/* ── ptrace ─────────────────────────────────────────────────── */
SEC("tracepoint/syscalls/sys_enter_ptrace")
int tp_ptrace(struct trace_event_raw_sys_enter *ctx)
{
    /* arg0 = request, arg1 = pid */
    return emit_syscall(101, ctx->args[0], ctx->args[1]);
}

/* ── mmap ───────────────────────────────────────────────────── */
SEC("tracepoint/syscalls/sys_enter_mmap")
int tp_mmap(struct trace_event_raw_sys_enter *ctx)
{
    /* arg0 = addr, arg1 = length */
    return emit_syscall(9, ctx->args[0], ctx->args[1]);
}

/* ── mprotect ───────────────────────────────────────────────── */
SEC("tracepoint/syscalls/sys_enter_mprotect")
int tp_mprotect(struct trace_event_raw_sys_enter *ctx)
{
    /* arg0 = addr, arg1 = len */
    return emit_syscall(10, ctx->args[0], ctx->args[1]);
}

/* ── prctl ──────────────────────────────────────────────────── */
SEC("tracepoint/syscalls/sys_enter_prctl")
int tp_prctl(struct trace_event_raw_sys_enter *ctx)
{
    /* arg0 = option, arg1 = arg2 */
    return emit_syscall(157, ctx->args[0], ctx->args[1]);
}

/* ── keyctl ─────────────────────────────────────────────────── */
SEC("tracepoint/syscalls/sys_enter_keyctl")
int tp_keyctl(struct trace_event_raw_sys_enter *ctx)
{
    /* arg0 = operation, arg1 = key */
    return emit_syscall(250, ctx->args[0], ctx->args[1]);
}

/* ── sendmsg ────────────────────────────────────────────────── */
SEC("tracepoint/syscalls/sys_enter_sendmsg")
int tp_sendmsg(struct trace_event_raw_sys_enter *ctx)
{
    /* arg0 = fd, arg1 = msg */
    return emit_syscall(46, ctx->args[0], ctx->args[1]);
}

/* ── recvmsg ────────────────────────────────────────────────── */
SEC("tracepoint/syscalls/sys_enter_recvmsg")
int tp_recvmsg(struct trace_event_raw_sys_enter *ctx)
{
    /* arg0 = fd, arg1 = msg */
    return emit_syscall(47, ctx->args[0], ctx->args[1]);
}

char _license[] SEC("license") = "GPL";
