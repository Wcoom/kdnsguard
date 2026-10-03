/* SPDX-License-Identifier: GPL-2.0 */
/*
 * 内核态 inttypes.h shim。
 *
 * 来源：platform_time.h 无条件 include <stdint.h> 与 <inttypes.h> 来定义
 * mbedtls_ms_time_t（int64_t）。内核没有 inttypes.h，只能自备。
 * 只声明 mbedTLS 实际会用到的格式化宏。
 */
#ifndef _KDG_SHIM_INTTYPES_H
#define _KDG_SHIM_INTTYPES_H

#include <linux/types.h>

#define PRId8   "d"
#define PRId16  "d"
#define PRId32  "d"
#define PRId64  "lld"
#define PRIu8   "u"
#define PRIu16  "u"
#define PRIu32  "u"
#define PRIu64  "llu"
#define PRIx64  "llx"
#define PRIX64  "llX"

#endif /* _KDG_SHIM_INTTYPES_H */
