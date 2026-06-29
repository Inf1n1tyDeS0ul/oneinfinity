/* vmlinux.h — minimal stub for BPF type definitions */
/* Generated in container: bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h */
/* This stub provides types + arch detection so BPF programs compile without
 * a full BTF-generated vmlinux.h or linux/types.h dependencies. */

#ifndef __VMLINUX_H__
#define __VMLINUX_H__

/* ------------------------------------------------------------------ */
/* Basic integer types — no asm/types.h dependency                     */
/* ------------------------------------------------------------------ */
#ifndef __u8
typedef unsigned char      __u8;
#endif
#ifndef __u16
typedef unsigned short     __u16;
#endif
#ifndef __u32
typedef unsigned int       __u32;
#endif
#ifndef __u64
typedef unsigned long long __u64;
#endif
#ifndef __s8
typedef signed char        __s8;
#endif
#ifndef __s16
typedef signed short       __s16;
#endif
#ifndef __s32
typedef signed int         __s32;
#endif
#ifndef __s64
typedef signed long long   __s64;
#endif

/* Endian-annotated aliases (used by bpf_helper_defs.h) */
#ifndef __be16
typedef __u16 __be16;
#endif
#ifndef __be32
typedef __u32 __be32;
#endif
#ifndef __be64
typedef __u64 __be64;
#endif
#ifndef __le16
typedef __u16 __le16;
#endif
#ifndef __le32
typedef __u32 __le32;
#endif
#ifndef __le64
typedef __u64 __le64;
#endif

/* __wsum is used by bpf_helper_defs.h checksum helpers */
#ifndef __wsum
typedef __u32 __wsum;
#endif

/* Short-name aliases */
typedef __u8  u8;
typedef __u16 u16;
typedef __u32 u32;
typedef __u64 u64;
typedef __s8  s8;
typedef __s16 s16;
typedef __s32 s32;
typedef __s64 s64;

/* ------------------------------------------------------------------ */
/* Architecture detection — sets __TARGET_ARCH_xxx for bpf_tracing.h  */
/* ------------------------------------------------------------------ */
#if defined(__x86_64__) && !defined(__TARGET_ARCH_x86)
# define __TARGET_ARCH_x86
#endif
#if defined(__aarch64__) && !defined(__TARGET_ARCH_arm64)
# define __TARGET_ARCH_arm64
#endif
#if defined(__arm__) && !defined(__TARGET_ARCH_arm)
# define __TARGET_ARCH_arm
#endif
#if defined(__riscv) && !defined(__TARGET_ARCH_riscv)
# define __TARGET_ARCH_riscv
#endif
#if defined(__s390x__) && !defined(__TARGET_ARCH_s390)
# define __TARGET_ARCH_s390
#endif
#if defined(__powerpc64__) && !defined(__TARGET_ARCH_powerpc)
# define __TARGET_ARCH_powerpc
#endif
#if defined(__mips__) && !defined(__TARGET_ARCH_mips)
# define __TARGET_ARCH_mips
#endif
/* When compiling with -target bpf (sets __bpf__ only), default to x86
 * if no TARGET_ARCH was specified on the command line.  This matches the
 * most common BPF development environment (x86_64 containers).
 * Override at compile time with -D__TARGET_ARCH_arm64 etc. */
#if defined(__bpf__) && \
    !defined(__TARGET_ARCH_x86) && \
    !defined(__TARGET_ARCH_arm64) && \
    !defined(__TARGET_ARCH_arm) && \
    !defined(__TARGET_ARCH_riscv) && \
    !defined(__TARGET_ARCH_s390) && \
    !defined(__TARGET_ARCH_powerpc) && \
    !defined(__TARGET_ARCH_mips)
# define __TARGET_ARCH_x86
#endif
/* ------------------------------------------------------------------ */
/* struct pt_regs per-arch definitions                                  */
/* bpf_tracing.h accesses register fields directly on the struct        */
/* ------------------------------------------------------------------ */
#ifdef __TARGET_ARCH_x86
/* Field names must match what bpf_tracing.h's __KERNEL__ / __VMLINUX_H__ path
 * accesses: .di .si .dx .cx .r8 .r9 .r10 .r11 .ax .sp .bp .ip etc. */
struct pt_regs {
    /* callee-preserved */
    unsigned long r15;
    unsigned long r14;
    unsigned long r13;
    unsigned long r12;
    unsigned long bp;    /* rbp */
    unsigned long bx;    /* rbx */
    /* callee-clobbered */
    unsigned long r11;
    unsigned long r10;
    unsigned long r9;
    unsigned long r8;
    unsigned long ax;    /* rax */
    unsigned long cx;    /* rcx */
    unsigned long dx;    /* rdx */
    unsigned long si;    /* rsi */
    unsigned long di;    /* rdi */
    unsigned long orig_ax;
    /* return frame for iretq */
    unsigned long ip;    /* rip */
    unsigned long cs;
    unsigned long flags;
    unsigned long sp;    /* rsp */
    unsigned long ss;
};
#endif /* __TARGET_ARCH_x86 */

#ifdef __TARGET_ARCH_arm64
struct pt_regs {
    unsigned long long regs[31];
    unsigned long long sp;
    unsigned long long pc;
    unsigned long long pstate;
    unsigned long long orig_x0;
    unsigned long long syscallno;
};
#endif /* __TARGET_ARCH_arm64 */



/* ------------------------------------------------------------------ */
/* XDP types                                                            */
/* ------------------------------------------------------------------ */
enum xdp_action {
    XDP_ABORTED  = 0,
    XDP_DROP     = 1,
    XDP_PASS     = 2,
    XDP_TX       = 3,
    XDP_REDIRECT = 4,
};

struct xdp_md {
    __u32 data;
    __u32 data_end;
    __u32 data_meta;
    __u32 ingress_ifindex;
    __u32 rx_queue_index;
    __u32 egress_ifindex;
};

/* Minimal __sk_buff stub needed by some bpf_helper_defs.h signatures */
struct __sk_buff;

/* ------------------------------------------------------------------ */
/* BPF map type constants (subset) — avoids needing linux/bpf.h        */
/* ------------------------------------------------------------------ */
#ifndef BPF_MAP_TYPE_RINGBUF
# define BPF_MAP_TYPE_RINGBUF 27
#endif

#endif /* __VMLINUX_H__ */
