/* SPDX-License-Identifier: GPL-2.0 */
/*
 * 内核态 limits.h shim。
 *
 * ⚠️ 关键点：内核的 <linux/limits.h> 把 SIZE_MAX 定义成 `(~(size_t)0)`
 * —— 一个 **C 表达式**。而 mbedTLS 会写 `#if SIZE_MAX > 0xFFFFFFFF`
 * （asn1write.c:26），预处理器不认识类型名，直接报
 * "token is not a valid binary operator in a preprocessor subexpression"。
 *
 * 所以这里必须 **#undef 后重定义** 成纯常量形式。用 #ifndef 保护是不行的：
 * 内核已经定义了它，保护会让我们什么都不做，错误照旧。
 * `(~0UL)` 在 #if 中合法，且在本平台（LP64）语义与内核定义一致。
 */
#ifndef _KDG_SHIM_LIMITS_H
#define _KDG_SHIM_LIMITS_H

#include <linux/limits.h>
#include <linux/kernel.h>
#include "_kdg_common.h"

#undef SIZE_MAX
#define SIZE_MAX  (~0UL)

#ifndef UINT_MAX
#define UINT_MAX  (~0U)
#endif
#ifndef INT_MAX
#define INT_MAX   2147483647
#endif
#ifndef ULONG_MAX
#define ULONG_MAX (~0UL)
#endif
#ifndef CHAR_BIT
#define CHAR_BIT  8
#endif

#endif /* _KDG_SHIM_LIMITS_H */
