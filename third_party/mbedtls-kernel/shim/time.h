/* SPDX-License-Identifier: GPL-2.0 */
/*
 * 内核态 time.h shim。
 *
 * 必须提供 time_t：mbedTLS 的 platform_time.h 在**没有**定义
 * MBEDTLS_PLATFORM_TIME_TYPE_MACRO 时会 `#include <time.h>` 并
 * `typedef time_t mbedtls_time_t;`。而那个宏与 MBEDTLS_PLATFORM_TIME_ALT
 * 互斥（check_config.h:530），我们要用 ALT，所以只能把 time_t 供出来。
 *
 * 语义：内核的 ktime_get_real_seconds() 返回自 Unix 纪元起的秒数，
 * 正好是 POSIX time_t 在 64 位平台上的语义。
 */
#ifndef _KDG_SHIM_TIME_H
#define _KDG_SHIM_TIME_H

#include <linux/types.h>
#include <linux/timekeeping.h>
#include <linux/time.h>
#include "_kdg_common.h"

typedef long time_t;

/* 所有日期转换调用方复用内核 struct tm，避免与 libc 布局混用。 */

/*
 * time()：nghttp2 的 nghttp2_time.c 在不定义 HAVE_CLOCK_GETTIME 时走
 * 这条回退路径。给它墙上时间（与 mbedTLS 侧的 kdg_mbedtls_time 同源）。
 */
static inline time_t time(time_t *t)
{
	time_t now = (time_t)ktime_get_real_seconds();

	if (t)
		*t = now;
	return now;
}

#endif /* _KDG_SHIM_TIME_H */
