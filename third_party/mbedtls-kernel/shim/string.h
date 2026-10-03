/* SPDX-License-Identifier: GPL-2.0 */
/* 内核态 shim：mbedTLS 大量使用 memcpy/memset/memcmp/strlen，内核都有同名实现。 */
#ifndef _KDG_SHIM_STRING_H
#define _KDG_SHIM_STRING_H
#include <linux/string.h>
#include <linux/kernel.h>   /* ARRAY_SIZE 等 mbedTLS 偶尔会用到 */
#include "_kdg_common.h"
#endif
