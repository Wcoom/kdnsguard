/* SPDX-License-Identifier: GPL-2.0 */
/* 内核态 sys/types.h shim。nghttp2 的 sfparse.h 会 include 它取 ssize_t。 */
#ifndef _KDG_SHIM_SYS_TYPES_H
#define _KDG_SHIM_SYS_TYPES_H

#include <linux/types.h>

typedef __kernel_ssize_t ssize_t;
typedef __kernel_off_t   off_t;

#endif
