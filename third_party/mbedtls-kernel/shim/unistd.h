/* SPDX-License-Identifier: GPL-2.0 */
/*
 * 内核态 unistd.h shim。
 *
 * 内核态没有 POSIX unistd，但 mbedTLS 会把本平台判为
 * MBEDTLS_PLATFORM_IS_UNIXLIKE（library/common.h:30 依据 __unix__ 等宏），
 * 于是 psa_crypto_random.c 会 include <unistd.h> 并调用 getpid()。
 *
 * 那里用 getpid() 是为了 **fork 保护**：子进程若继承了父进程的 DRBG 状态，
 * 父子会产出相同的随机流，所以要「pid 变了就重新播种」。
 *
 * 内核模块不会被 fork —— DRBG 状态是内核全局的，不存在父子分裂。因此
 * 返回一个恒定值在语义上是**正确**的（保护逻辑永不触发），而不是权宜之计。
 * 用 1 而非 0：0 在部分约定里表示「无效/未设置」，容易被误读为异常值。
 */
#ifndef _KDG_SHIM_UNISTD_H
#define _KDG_SHIM_UNISTD_H

#include <linux/types.h>

static inline int getpid(void)
{
	return 1;
}

#endif /* _KDG_SHIM_UNISTD_H */
