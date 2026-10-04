/* SPDX-License-Identifier: GPL-2.0 */
/*
 * 宿主替身：把 <linux/kernel.h> 指向 hostshim.h。
 *
 * 之所以一个文件一件事而不是一个 linux.h 全搞定：内核源码写的是
 * `#include <linux/wait.h>` 这类真实路径，替身必须按同样的路径存在，
 * 否则就要改被测源码 —— 而「同一份源文件两种编译形态」是这个
 * 测试能成立的前提。
 */
#ifndef _KDG_HOSTLINUX_KERNEL_H
#define _KDG_HOSTLINUX_KERNEL_H

#include "../hostshim.h"

#endif /* _KDG_HOSTLINUX_KERNEL_H */
