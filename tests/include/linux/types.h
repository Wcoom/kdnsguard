/* SPDX-License-Identifier: GPL-2.0 */
/*
 * 宿主态 linux/types.h 替身。
 *
 * 只为了让 include/uapi/kdnsguard.h 能在宿主上被解析——内核树里这个文件
 * 由 include/uapi/linux/types.h 提供。这里**不复刻内核类型**，只声明 UAPI
 * 头实际用到的 __uN/__sN。这么做的前提是 kdnsguard.h 的宿主可用性是刻意
 * 维持的：只有 UAPI 的布局能在宿主上 round-trip，才能写 ABI 布局断言。
 */
#ifndef _KDG_HOST_LINUX_TYPES_H
#define _KDG_HOST_LINUX_TYPES_H

#include <stdint.h>

typedef uint8_t  __u8;
typedef uint16_t __u16;
typedef uint32_t __u32;
typedef uint64_t __u64;
typedef int8_t   __s8;
typedef int16_t  __s16;
typedef int32_t  __s32;
typedef int64_t  __s64;

#ifndef __user
#define __user
#endif

#endif /* _KDG_HOST_LINUX_TYPES_H */
