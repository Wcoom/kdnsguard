/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _KDG_SHIM_ASSERT_H
#define _KDG_SHIM_ASSERT_H
#include <linux/kernel.h>
#include <linux/bug.h>
#define assert(x) do { if (unlikely(!(x))) { WARN_ONCE(1, "mbedtls assert: %s\n", #x); } } while (0)
#endif
