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

#undef UINT_MAX
#define UINT_MAX	(~0U)

#undef LONG_MAX
#define LONG_MAX	(~0UL >> 1)
#undef LONG_MIN
#define LONG_MIN	(-LONG_MAX - 1L)

#undef ULONG_MAX
#define ULONG_MAX	(~0UL)

#undef SHRT_MAX
#define SHRT_MAX	32767
#undef SHRT_MIN
#define SHRT_MIN	(-32768)

#undef USHRT_MAX
#define USHRT_MAX	65535U

#undef CHAR_MAX
#define CHAR_MAX	127
#undef CHAR_MIN
#define CHAR_MIN	(-128)

#undef UCHAR_MAX
#define UCHAR_MAX	255U

