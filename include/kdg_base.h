/* SPDX-License-Identifier: GPL-2.0 */
/*
 * kdg_base.h —— 双态构建基座。
 *
 * 存在的唯一理由：让 DNS wire 校验器（kdg_wire.c）与它的小工具既能编进
 * 内核，也能被**宿主 gcc** 直接编译，从而在本机跑语料/模糊测试。
 *
 * 为什么这件事值得多一层头文件：本内核 CONFIG_KUNIT=m，而 KUnit 的 Kconfig
 * 要求 KUNIT=y 才会编入用例（见本树 lib/kunit/Kconfig），也就是说设备构建
 * 里 KUnit 用例**根本不会被编译**。而 DNS 解析的安全性完全取决于对畸形输入
 * （压缩指针自环、标签长度溢出、计数不一致、报文截断）的处置，这类代码不跑
 * 几百条语料就等于没验证。双态编译让同一份源文件在宿主上能用 ASan/UBSan
 * 跑，是投入产出比最高的做法；zstd/lz4 在内核里也是同样的套路。
 *
 * 纪律：本头文件只提供**类型与控制流原语**的最小替身，不模拟内核语义。
 * kdg_wire.c 里除 kdg_base.h 之外不得包含其它内核头，否则双态编译立刻失效。
 */
#ifndef _KDG_BASE_H
#define _KDG_BASE_H

#ifdef __KERNEL__

#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/errno.h>

#define KDG_WARN_ONCE(cond, fmt, ...)	WARN_ONCE(cond, fmt, ##__VA_ARGS__)
#define KDG_PR_ERR(fmt, ...)		pr_err(fmt, ##__VA_ARGS__)

#else /* 宿主态：只给 kdg_wire.c 用到的最小子集 */

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <string.h>

typedef uint8_t  u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;
typedef int8_t   s8;
typedef int16_t  s16;
typedef int32_t  s32;
typedef int64_t  s64;

#ifndef __packed
#define __packed	__attribute__((packed))
#endif
#ifndef __maybe_unused
#define __maybe_unused	__attribute__((unused))
#endif
#ifndef ARRAY_SIZE
#define ARRAY_SIZE(a)	(sizeof(a) / sizeof((a)[0]))
#endif
#ifndef BUILD_BUG_ON
#define BUILD_BUG_ON(cond)	((void)sizeof(char[1 - 2 * !!(cond)]))
#endif

/* 宿主态下这些诊断只在测试里被引用，给成空实现避免污染测试输出；
 * 真正需要断言的场合测试自己会用 assert。 */
#define KDG_WARN_ONCE(cond, fmt, ...)	((void)(cond))
#define KDG_PR_ERR(fmt, ...)		((void)0)

#endif /* __KERNEL__ */

#endif /* _KDG_BASE_H */
