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
#include "_kdg_common.h"

typedef long time_t;

/* 刻意**不**定义 struct tm：内核自己的 <linux/time.h> 已经定义了一个
 * （字段名相同但布局不同），重复定义会直接撞车。
 * MBEDTLS_HAVE_TIME_DATE 已在本项目配置里关闭 —— 证书只比较 time_t 数值，
 * 不做日期字符串格式化 —— 所以这里不需要 tm 的任何东西。 */

#endif /* _KDG_SHIM_TIME_H */
