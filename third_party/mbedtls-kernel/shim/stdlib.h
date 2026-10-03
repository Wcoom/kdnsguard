/* SPDX-License-Identifier: GPL-2.0 */
/*
 * 内核态 stdlib.h shim。
 *
 * 提供三类东西：
 *   1. 类型与 NULL
 *   2. calloc/free 的函数式宏（仅 KDG_SHIM_TU）—— mbedTLS 走注入点
 *   3. abort() 与 qsort() —— nghttp2 需要
 */
#ifndef _KDG_SHIM_STDLIB_H
#define _KDG_SHIM_STDLIB_H

#include <linux/types.h>
#include <linux/stddef.h>
#include <linux/slab.h>
#include <linux/kernel.h>
#include <linux/bug.h>
#include <linux/sort.h>

void *kdg_mbedtls_calloc(size_t n, size_t size);
void  kdg_mbedtls_free(void *p);

/*
 * ⚠️ calloc/free/malloc/realloc 一律用 **static inline 函数**，绝不用函数式宏。
 *
 * 宏会连**成员访问**一起改写：nghttp2_mem.c 里的
 *     mem->free(ptr, mem->mem_user_data);
 * 会被 `#define free(p) ...` 改写成单参数形式，报 "too many arguments
 * provided to function-like macro invocation"。`mem->calloc(nmemb, size, ud)`
 * 同理。编译器对成员访问里的 `free` 做的是查找而不是替换，所以函数声明是对的
 * 做法，宏不是。
 */
#if defined(KDG_SHIM_TU)
void *kdg_mbedtls_malloc(size_t n);
void *kdg_mbedtls_realloc(void *p, size_t n);

static inline void *calloc(size_t n, size_t size)
{
	return kdg_mbedtls_calloc(n, size);
}

static inline void free(void *p)
{
	kdg_mbedtls_free(p);
}

static inline void *malloc(size_t n)
{
	return kdg_mbedtls_malloc(n);
}

static inline void *realloc(void *p, size_t n)
{
	return kdg_mbedtls_realloc(p, n);
}
#endif

/*
 * abort()：与 assert() 的处置**刻意不同**。
 *
 * 上游对这两者是两种语义：assert 是调试检查（NDEBUG 下会被编掉），
 * abort 是**无条件终止**。nghttp2_session.c 里紧跟着 abort() 的那行注释
 * 原话是「if NDEBUG is set」—— 即 assert 被编掉时仍要终止。
 * （此处刻意不复述那行的完整字面量：它含有 C 注释的结束符，
 *   写进注释里会把外层注释提前终止，这个坑本文件已经踩过一次。）
 *
 * 因此内核态也分开处置：
 *   assert  -> 只告警（127 处，做成致命等于把「畸形输入」升级成「远程重启」）
 *   abort   -> 遵从「绝不返回」的契约，告警后停止（13 处，全部是穷举 switch
 *              的 default 与 NDEBUG-else 这类**构造上不可达**的位置）
 *
 * 为什么不返回、不用 __builtin_unreachable：返回会让模块在「不可能的状态」
 * 下继续执行，在内核里那就是内存损坏；__builtin_unreachable 只是把这个 UB
 * 告诉编译器，并没有消除它。受控停止比两者都安全。
 */
static inline void __noreturn kdg_abort_shim(void)
{
	WARN(1, "第三方库走到了 abort()：这是构造上不可达的路径，请记录此现场\n");
	BUG();
}

#define abort() kdg_abort_shim()

/*
 * qsort()：nghttp2 用它给 HPACK 的名字/值对排序（nghttp2_nv_array_sort）。
 * 内核已导出 sort()，签名只差一个 swap 回调，转接即可 —— 不自己写排序，
 * 免得引入一个需要单独验证的组件。
 */
static inline void kdg_qsort_swap(void *a, void *b, int size)
{
	u8 *x = a, *y = b;
	int i;

	for (i = 0; i < size; i++) {
		u8 t = x[i];

		x[i] = y[i];
		y[i] = t;
	}
}

static inline void kdg_qsort(void *base, size_t nmemb, size_t size,
			     int (*compar)(const void *, const void *))
{
	/* sort() 的 num 是元素个数，与 qsort 一致；元素大小为 0 时直接返回
	 * （sort() 内部对 num<=1 已短路，但 size==0 会让交换无意义）。 */
	if (!base || nmemb < 2 || size == 0)
		return;
	sort(base, nmemb, size, (cmp_func_t)compar, kdg_qsort_swap);
}

#define qsort(b, n, s, c) kdg_qsort((b), (n), (s), (c))

#endif /* _KDG_SHIM_STDLIB_H */
