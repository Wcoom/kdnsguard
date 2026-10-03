/* SPDX-License-Identifier: GPL-2.0 */
/*
 * 内核态 stdint.h shim。
 *
 * 内核的 <linux/types.h> 提供 __uN/__sN 但没有 C99 的定宽别名与极值宏，
 * mbedTLS 两者都用（bignum_core.c 用 UINT64_MAX，多处用 uint32_t 等）。
 *
 * 极值宏一律写成**纯常量**形式：它们会出现在 #if 中，写成 C 表达式
 * （如 ((uint64_t)-1)）会触发 "token is not a valid binary operator
 * in a preprocessor subexpression"。这条教训来自 limits.h 的 SIZE_MAX。
 */
#ifndef _KDG_SHIM_STDINT_H
#define _KDG_SHIM_STDINT_H

#include <linux/types.h>
#include <linux/kernel.h>
#include "_kdg_common.h"

typedef __u8   uint8_t;
typedef __u16  uint16_t;
typedef __u32  uint32_t;
typedef __u64  uint64_t;
typedef __s8   int8_t;
typedef __s16  int16_t;
typedef __s32  int32_t;
typedef __s64  int64_t;

typedef __u8   uint_least8_t;
typedef __u16  uint_least16_t;
typedef __u32  uint_least32_t;
typedef __u64  uint_least64_t;
typedef __u8   uint_fast8_t;
typedef __u16  uint_fast16_t;
typedef __u32  uint_fast32_t;
typedef __u64  uint_fast64_t;

/* 刻意不定义 uintptr_t / intptr_t / intmax_t / uintmax_t：内核的
 * <linux/types.h> 已经定义了前两者（分别是 unsigned long / long），
 * 我们用 __u64/__s64 去定义会得到 "typedef redefinition with different
 * types ('unsigned long long' vs 'unsigned long')"。
 * 而 intmax_t / uintmax_t 内核没有，需要我们自己提供。 */
typedef __s64  intmax_t;
typedef __u64  uintmax_t;

/* 极值：常量形式，可用于 #if */
#define INT8_MAX    127
#define INT16_MAX   32767
#define INT32_MAX   2147483647
#define INT64_MAX   9223372036854775807LL

#define UINT8_MAX   255U
#define UINT16_MAX  65535U
#define UINT32_MAX  4294967295U
#define UINT64_MAX  18446744073709551615ULL

#define INT8_MIN    (-128)
#define INT16_MIN   (-32768)
#define INT32_MIN   (-INT32_MAX - 1)
#define INT64_MIN   (-INT64_MAX - 1LL)
#define UINT8_MIN   0U
#define UINT16_MIN  0U
#define UINT32_MIN  0U
#define UINT64_MIN  0ULL

/* 定宽格式串中的长度修饰符（部分平台代码会用到） */
#define INT8_C(x)   (x)
#define INT16_C(x)  (x)
#define INT32_C(x)  (x)
#define INT64_C(x)  (x##LL)
#define UINT8_C(x)  (x##U)
#define UINT16_C(x) (x##U)
#define UINT32_C(x) (x##U)
#define UINT64_C(x) (x##ULL)

#endif /* _KDG_SHIM_STDINT_H */
