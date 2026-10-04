/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _KDG_LISTENER_H
#define _KDG_LISTENER_H

#include <linux/types.h>

/* Prepare starts loopback UDP/TCP listeners without claiming port 53. */
int kdg_listener_init_state(void);
int kdg_listener_prepare(void);
void kdg_listener_stop(void);
bool kdg_listener_ready(void);

/* 解析模块参数 client_ifaces（逗号分隔的候选接口名）。返回 0 恒成立；
 * 空串表示禁用客户端入口接管。kdg_main.c 在 kdg_init 里调用一次。 */
int kdg_listener_client_config(const char *spec);

/* 已建 listener 的客户端入口数（诊断）。 */
u32 kdg_listener_client_count(void);

#endif /* _KDG_LISTENER_H */
