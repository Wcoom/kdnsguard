/* SPDX-License-Identifier: GPL-2.0 */
/* 内核态没有 stdlib。MBEDTLS_PLATFORM_MEMORY + NO_STD_FUNCTIONS 会把
 * calloc/free 改成经 mbedtls_platform_set_calloc_free 注入的函数指针，
 * 此处只提供类型与 NULL，不提供任何实现。 */
#ifndef _KDG_SHIM_STDLIB_H
#define _KDG_SHIM_STDLIB_H
#include <linux/types.h>
#include <linux/stddef.h>
#include <linux/slab.h>
#include "_kdg_common.h"
void *kdg_mbedtls_calloc(size_t n, size_t size);
void  kdg_mbedtls_free(void *p);
#define calloc(n, s)  kdg_mbedtls_calloc((n), (s))
#define free(p)       kdg_mbedtls_free(p)
#endif
