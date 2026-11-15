/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Kernel integer types for programs that read no kernel structs. Programs
 * that do (CO-RE field access) include a generated vmlinux.h instead. */
#pragma once

typedef unsigned char __u8;
typedef signed char __s8;
typedef unsigned short __u16;
typedef signed short __s16;
typedef unsigned int __u32;
typedef signed int __s32;
typedef unsigned long long __u64;
typedef signed long long __s64;
typedef __u16 __be16;
typedef __u32 __be32;
typedef __u64 __be64;
typedef __u32 __wsum;

enum bpf_map_type {
	BPF_MAP_TYPE_PERCPU_ARRAY = 6,
	BPF_MAP_TYPE_LRU_HASH = 9,
	BPF_MAP_TYPE_RINGBUF = 27,
};

/* bpf_map_update_elem flags. */
#define BPF_ANY 0
#define BPF_NOEXIST 1

/* Context of raw tracepoint programs: the tracepoint's arguments. */
struct bpf_raw_tracepoint_args {
	__u64 args[0];
};

/* Context of kprobe programs. Only the first-argument and return-value
 * registers are read (ARG1, RET), so only the layout up to them has to
 * match the kernel's. */
#if defined(__TARGET_ARCH_x86)
struct pt_regs {
	unsigned long r15, r14, r13, r12, bp, bx, r11, r10, r9, r8;
	unsigned long ax, cx, dx, si, di;
};
#define ARG1(ctx) ((ctx)->di)
#define RET(ctx) ((ctx)->ax)
#elif defined(__TARGET_ARCH_arm64)
struct pt_regs {
	__u64 regs[31];
};
#define ARG1(ctx) ((ctx)->regs[0])
#define RET(ctx) ((ctx)->regs[0])
#endif
