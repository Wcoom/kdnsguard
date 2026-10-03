/* SPDX-License-Identifier: GPL-2.0 */
/*
 * 内核态 stdio shim。
 *
 * 只提供两样东西：
 *   1. 不透明的 FILE 类型 —— MBEDTLS_PLATFORM_FPRINTF_ALT 分支下
 *      platform.h 会 `#include <stdio.h>` 并声明
 *      `int (*mbedtls_fprintf)(FILE *stream, const char *, ...)`。
 *   2. 我们自己的四个入口的声明（供本模块其它文件引用）。
 *
 * ⚠️ **刻意不定义 `snprintf`/`vsnprintf` 宏**。曾经定义过，那会让本文件一旦
 * 被某个翻译单元 include，该单元里所有（含内核头 inline 函数中的）snprintf
 * 都被改名；更糟的是我们自己的实现体内再调 vsnprintf 会展开成自己 -> 无限递归。
 * 实测 mbedTLS 3.6.7 没有任何裸 snprintf 调用（仅 Windows 的
 * MBEDTLS_PLATFORM_HAS_NON_CONFORMING_VSNPRINTF 分支与 MPS trace 用到，
 * 两者在本项目均未启用），故无需这层宏。
 */
#ifndef _KDG_SHIM_STDIO_H
#define _KDG_SHIM_STDIO_H

#include <linux/types.h>
#include <linux/stddef.h>
#include <linux/stdarg.h>
#include <linux/kernel.h>

/* 不透明的流句柄。内核态没有真正的流对象，调试输出一律走 printk，
 * 因此这个类型永远不会被解引用；定义成不完整类型正是要保证这一点。 */
struct kdg_kernel_FILE;
typedef struct kdg_kernel_FILE FILE;

int kdg_mbedtls_snprintf(char *s, size_t n, const char *fmt, ...);
int kdg_mbedtls_vsnprintf(char *s, size_t n, const char *fmt, va_list ap);
int kdg_mbedtls_printf(const char *fmt, ...);
int kdg_mbedtls_fprintf(FILE *stream, const char *fmt, ...);

/*
 * fprintf/stderr：nghttp2 的调试输出走 stderr。内核态没有流对象，
 * 把 stderr 定义成一个空指针常量、fprintf 定义为打印到 printk ——
 * 调用点写法不用改，且永不接触真实的 FILE。
 */
#define stderr ((FILE *)0)
#define fprintf(stream, ...) kdg_mbedtls_fprintf((stream), __VA_ARGS__)

#endif /* _KDG_SHIM_STDIO_H */
