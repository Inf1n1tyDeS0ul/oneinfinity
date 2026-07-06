// SPDX-License-Identifier: GPL-2.0
// syscall_tracer.bpf.c — Traces suspicious syscalls (execve, connect, openat)
// from scanned processes to detect container escape / malicious behaviour.
//
// Attaches kprobes on:
//   - sys_execve / execve: command execution (shell injection detection)
//   - sys_connect / connect: outbound connection (SSRF/C2 callback detection)
//   - sys_openat / openat: file open events (sensitive file access)
//
// Events are emitted via a BPF ring buffer to userspace.
// Each event: {pid, ppid, comm, syscall_name, arg0/filename/addr, ts_ns}
//
// Load: sudo bpftool prog load syscall_tracer.bpf.o /sys/fs/bpf/syscall_tracer
// Or via Python loader: python3 syscall_tracer_loader.py --pids <pid,...>

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define TASK_COMM_LEN   16
#define ARG_LEN         256
#define MAX_PATH_LEN    256

// ── Event structure ────────────────────────────────────────────────────────────

struct event {
    __u32 pid;
    __u32 ppid;
    __u32 uid;
    __u32 gid;
    char  comm[TASK_COMM_LEN];
    char  syscall[16];
    char  arg0[ARG_LEN];         // filename for execve/openat, IP:port for connect
    __u64 ts_ns;                 // ktime_get_ns()
    __u32 retval;
    __u8  is_suspicious;         // 1 if matches suspicious pattern
};

// ── BPF maps ───────────────────────────────────────────────────────────────────

// Ring buffer for events → userspace
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);  // 16 MB
} events SEC(".maps");

// PID filter map: set of PIDs to monitor (empty = monitor all)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);
    __type(value, __u8);
} pid_filter SEC(".maps");

// ── Helper: check if PID should be traced ─────────────────────────────────────

static __always_inline int should_trace(__u32 pid)
{
    // If the filter map is empty, trace all pids.
    // If it has entries, only trace those pids.
    __u8 *val = bpf_map_lookup_elem(&pid_filter, &pid);
    return val != NULL;
}

static __always_inline int pid_filter_empty(void)
{
    // We can't enumerate a BPF map in kernel; trust userspace to populate it.
    // Return 1 (trace all) when a special key 0 has value 0xFF.
    __u32 key = 0;
    __u8 *flag = bpf_map_lookup_elem(&pid_filter, &key);
    return (flag && *flag == 0xFF);
}

// ── Suspicious pattern detection ──────────────────────────────────────────────

// Check if an execve command looks like a shell injection vector
static __always_inline __u8 is_suspicious_exec(const char *comm, const char *filename)
{
    // Heuristic: shells, wget/curl called from non-interactive process
    // (BPF can't do full string match; we check first 4 bytes as a prefix hint)
    char c0 = 0, c1 = 0, c2 = 0, c3 = 0;
    bpf_probe_read_user(&c0, 1, filename);
    bpf_probe_read_user(&c1, 1, filename + 1);
    bpf_probe_read_user(&c2, 1, filename + 2);
    bpf_probe_read_user(&c3, 1, filename + 3);

    // /bin/sh → '/', 'b', 'i', 'n'  — flag /bin/sh /bin/bash /bin/dash /usr/bin/*sh
    if (c0 == '/' && c1 == 'b' && c2 == 'i' && c3 == 'n') return 1;
    if (c0 == '/' && c1 == 'u' && c2 == 's' && c3 == 'r') return 1;
    // wget / curl / nc / python / perl invocations
    if (c0 == 'w' && c1 == 'g' && c2 == 'e') return 1;  // wget
    if (c0 == 'c' && c1 == 'u' && c2 == 'r') return 1;  // curl
    if (c0 == 'n' && c1 == 'c' && c2 == 0)   return 1;  // nc
    if (c0 == 'p' && c1 == 'y' && c2 == 't') return 1;  // python
    if (c0 == 'p' && c1 == 'e' && c2 == 'r') return 1;  // perl
    return 0;
}

static __always_inline __u8 is_suspicious_open(const char *filename)
{
    char c0 = 0, c1 = 0, c2 = 0, c3 = 0, c4 = 0;
    bpf_probe_read_user(&c0, 1, filename);
    bpf_probe_read_user(&c1, 1, filename + 1);
    bpf_probe_read_user(&c2, 1, filename + 2);
    bpf_probe_read_user(&c3, 1, filename + 3);
    bpf_probe_read_user(&c4, 1, filename + 4);

    // /etc/passwd, /etc/shadow, /etc/hosts, /proc/*/mem, /var/run/docker.sock
    if (c0 == '/' && c1 == 'e' && c2 == 't' && c3 == 'c') return 1;
    if (c0 == '/' && c1 == 'p' && c2 == 'r' && c3 == 'o') return 1;  // /proc
    if (c0 == '/' && c1 == 'v' && c2 == 'a' && c3 == 'r') return 1;  // /var (docker.sock)
    if (c0 == '/' && c1 == 'r' && c2 == 'o' && c3 == 'o') return 1;  // /root
    return 0;
}

// ── Tracepoints: execve ────────────────────────────────────────────────────────

SEC("tracepoint/syscalls/sys_enter_execve")
int trace_execve(struct trace_event_raw_sys_enter *ctx)
{
    __u32 pid  = bpf_get_current_pid_tgid() >> 32;
    __u32 tgid = (__u32)bpf_get_current_pid_tgid();

    if (!pid_filter_empty() && !should_trace(pid))
        return 0;

    struct event *e = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
    if (!e) return 0;

    e->pid    = pid;
    e->uid    = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    e->gid    = bpf_get_current_uid_gid() >> 32;
    e->ts_ns  = bpf_ktime_get_ns();

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    e->ppid = BPF_CORE_READ(task, real_parent, tgid);

    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    // arg0 = pathname (user pointer)
    const char *filename = (const char *)ctx->args[0];
    bpf_probe_read_user_str(&e->arg0, sizeof(e->arg0), filename);

    __builtin_memcpy(&e->syscall, "execve\0\0\0\0\0\0\0\0\0\0", 16);
    e->is_suspicious = is_suspicious_exec(e->comm, filename);
    e->retval = 0;  // filled in sys_exit if needed

    bpf_ringbuf_submit(e, 0);
    return 0;
}

// ── Tracepoints: openat ────────────────────────────────────────────────────────

SEC("tracepoint/syscalls/sys_enter_openat")
int trace_openat(struct trace_event_raw_sys_enter *ctx)
{
    __u32 pid = bpf_get_current_pid_tgid() >> 32;

    if (!pid_filter_empty() && !should_trace(pid))
        return 0;

    const char *filename = (const char *)ctx->args[1];  // openat(dfd, filename, ...)
    if (!is_suspicious_open(filename))
        return 0;

    struct event *e = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
    if (!e) return 0;

    e->pid   = pid;
    e->uid   = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    e->gid   = bpf_get_current_uid_gid() >> 32;
    e->ts_ns = bpf_ktime_get_ns();

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    e->ppid = BPF_CORE_READ(task, real_parent, tgid);

    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    bpf_probe_read_user_str(&e->arg0, sizeof(e->arg0), filename);
    __builtin_memcpy(&e->syscall, "openat\0\0\0\0\0\0\0\0\0\0", 16);
    e->is_suspicious = 1;
    e->retval = 0;

    bpf_ringbuf_submit(e, 0);
    return 0;
}

// ── Tracepoints: connect ───────────────────────────────────────────────────────

SEC("tracepoint/syscalls/sys_enter_connect")
int trace_connect(struct trace_event_raw_sys_enter *ctx)
{
    __u32 pid = bpf_get_current_pid_tgid() >> 32;

    if (!pid_filter_empty() && !should_trace(pid))
        return 0;

    struct event *e = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
    if (!e) return 0;

    e->pid   = pid;
    e->uid   = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    e->gid   = bpf_get_current_uid_gid() >> 32;
    e->ts_ns = bpf_ktime_get_ns();

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    e->ppid = BPF_CORE_READ(task, real_parent, tgid);

    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    // arg1 = struct sockaddr* — try to extract IP:port for IPv4
    const struct sockaddr *sa = (const struct sockaddr *)ctx->args[1];
    __u16 family = 0;
    bpf_probe_read_kernel(&family, sizeof(family), &sa->sa_family);

    if (family == 2) {  // AF_INET
        struct sockaddr_in sin;
        bpf_probe_read_kernel(&sin, sizeof(sin), sa);
        __u8 *ip = (__u8 *)&sin.sin_addr.s_addr;
        __u16 port = __builtin_bswap16(sin.sin_port);

        // Format as "ddd.ddd.ddd.ddd:ppppp" — BPF can't use sprintf; write bytes
        // Emit raw bytes; loader will decode
        __u8 buf[8];
        buf[0] = ip[0]; buf[1] = ip[1]; buf[2] = ip[2]; buf[3] = ip[3];
        buf[4] = (port >> 8) & 0xFF; buf[5] = port & 0xFF;
        buf[6] = 2; buf[7] = 0;  // family=AF_INET marker
        __builtin_memcpy(&e->arg0, buf, 8);
    } else {
        // IPv6 or other — store family byte
        e->arg0[0] = (char)family;
        e->arg0[1] = 0;
    }

    __builtin_memcpy(&e->syscall, "connect\0\0\0\0\0\0\0\0\0", 16);
    // Mark all outbound connections as worth recording
    e->is_suspicious = 1;
    e->retval = 0;

    bpf_ringbuf_submit(e, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
