/* SPDX-License-Identifier: GPL-2.0 */
/*
 * 内核宏污染清理 —— 所有 shim 头都必须最先 include 本文件。
 *
 * 背景：内核大量使用「函数式宏 / C 表达式宏」来实现类型安全或访问器，
 * 而这些名字在普通 C 代码里是再平凡不过的标识符。第三方库搬进内核时，
 * 这类冲突会以**完全看不出根因**的方式爆发（报错往往落在库自己的文件里）。
 *
 * 三例实测（全部已在 mbedTLS 3.6.7 上撞到）：
 *   current    <asm/current.h> `#define current get_current()`
 *              → mbedTLS constant_time.c 的局部变量 `current` 被展开，
 *                报 "conflicting types for 'get_current'" / "illegal initializer"
 *   INT_MAX    <vdso/limits.h> `((int)(~0U >> 1))`（C 表达式）
 *              → mbedTLS `#if (INT_MAX < INT32_MAX)` 报
 *                "token is not a valid binary operator in a preprocessor subexpression"
 *   SIZE_MAX   <linux/limits.h> `(~(size_t)0)`（C 表达式）→ 同上
 *
 * 清理原则：只 **#undef / 重定义为纯常量**，不改变任何内核函数的语义。
 * 本文件只被 mbedTLS 的翻译单元与 kdg_mbedtls.c 经过，不影响内核其它代码。
 */
/*
 * ⚠️ **本文件刻意没有 include guard**。
 *
 * 清理动作必须**幂等且可重入**：mbedTLS 的文件常常先 include "common.h"
 * （经我们的 shim 触发一次清理），随后又 include <limits.h>/<string.h>
 * （再次触发）。若加了 guard，第二次就是空操作，而这一期间某个内核头可能
 * 已把 current 之类的宏重新定义回来 —— 实测 constant_time.c 正是如此，
 * 表现为 #undef 明明写了却依旧报 "conflicting types for 'get_current'"。
 *
 * 反复 include 的代价可忽略：里面的内核头自身有 guard，本文件剩下的
 * 只是一串 #undef / #define。
 */

#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/limits.h>
#include <linux/string.h>
#include <linux/stddef.h>

/* ── 1. 访问器宏：与普通标识符冲突 ───────────────────────────────── */
#undef current			/* : get_current() */
#undef smp_processor_id		/* 保留语义由调用方自行使用内核 API，mbedTLS 不需要 */

/* ── 2. 极值宏：内核用 C 表达式定义，无法用于 #if ─────────────────── */
#undef SIZE_MAX
#define SIZE_MAX	(~0UL)

#undef INT_MAX
#define INT_MAX		2147483647
#undef INT_MIN
#define INT_MIN		(-INT_MAX - 1)

/*
 * 🔴 UINT_MAX 必须写成**字面常量**，不能写 (~0U)。
 *
 * 这一条曾让整个 TLS 链路瘫痪，值得完整记录：
 *   C 预处理器里的整数一律按 intmax_t/uintmax_t 运算（本机 64 位）。
 *   于是 `(~0U)` 在 #if 里求值成 0xFFFFFFFFFFFFFFFF，**不是** 32 位的
 *   0xFFFFFFFF。而 mbedTLS 的 bignum_core.c 正是这么选 clz 实现的：
 *       #if (MBEDTLS_MPI_UINT_MAX == UINT_MAX)   -> __builtin_clz  (32 位!)
 *       #elif (MBEDTLS_MPI_UINT_MAX == ULONG_MAX) -> __builtin_clzl
 *   两者都被算成 0xFFFFFFFFFFFFFFFF，于是 64 位肢体被错判为 32 位，
 *   选中 __builtin_clz -> 高位被截断 -> mbedtls_mpi_bitlen() 结果错误
 *   -> mbedtls_mpi_size(P) 错误 -> 一切基于它的运算全错。
 *
 * 表现极具迷惑性：P-256 挂、P-384 不挂 —— 因为 P-384 的最高 limb 是
 * 全 1，截断后 clz 恰好仍为 0。**它不是没坏，是这个输入掩盖了 bug。**
 */
#undef UINT_MAX
#define UINT_MAX	4294967295U

#undef LONG_MAX
#define LONG_MAX	(~0UL >> 1)
#undef LONG_MIN
#define LONG_MIN	(-LONG_MAX - 1L)

#undef ULONG_MAX
#define ULONG_MAX	(~0UL)

/*
 * ⚠️ 不再重定义 CHAR_MIN/CHAR_MAX/UCHAR_MAX/SHRT_MAX 等。
 *
 * 曾经它们也在重定义之列，其中 CHAR_MIN 被我写成 -128 —— 而 **ARM64 上
 * char 默认是无符号的**，正确值是 0。这是「顺手把一组合并处理」引入的
 * 错误：真正需要重定义的只有内核用 **C 表达式**（如 SIZE_MAX = (~(size_t)0)）
 * 定义、因而无法出现在 #if 里的那几个；其余保留内核的即可。
 */

