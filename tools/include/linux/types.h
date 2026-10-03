/* SPDX-License-Identifier: GPL-2.0 */
/*
 * freestanding 构建用的 linux/types.h 替身。
 *
 * kdgctl 不链接任何 libc（见 kdgctl.c 头注），所以不能借 stdint.h 定义这些
 * 类型，只能自带。这里只声明 UAPI 头用到的 __uN/__sN，不模拟任何内核语义。
 */
#ifndef _KDG_FREESTANDING_LINUX_TYPES_H
#define _KDG_FREESTANDING_LINUX_TYPES_H

typedef unsigned char      __u8;
typedef unsigned short     __u16;
typedef unsigned int       __u32;
typedef unsigned long      __u64;
typedef signed char        __s8;
typedef signed short       __s16;
typedef signed int         __s32;
typedef signed long        __s64;

#endif
