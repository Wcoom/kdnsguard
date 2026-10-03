/* SPDX-License-Identifier: GPL-2.0 */
/*
 * kdg_sock.h —— 内核态 TCP socket 薄封装（阻塞式，带超时）。
 *
 * 设计取舍：
 *  - **阻塞式**而不是事件驱动。方案 §6.2 要求在「可睡眠的 kernel worker 上
 *    驱动握手与 I/O」；本阶段调用方是 genl doit（进程上下文，可睡眠），
 *    因此阻塞语义最简单也最不易错。等到 P2 引入独立 kthread + 事件循环时，
 *    本层的接口不变，只是调用点换人。
 *  - 超时**必须**显式设置。内核 socket 的默认 sk_rcvtimeo 是
 *    MAX_SCHEDULE_TIMEOUT（无限等待），一条静默的黑洞连接会把内核线程永久挂住。
 *    §9.3 要求「正常查询 deadline 3 秒初值」，本层把这作为默认值。
 *  - 不自建 TCP/IP：复用内核协议栈（方案 §3 明确列为复用项）。
 */
#ifndef _KDG_SOCK_H
#define _KDG_SOCK_H

#include "kdg_base.h"

#define KDG_SOCK_DEFAULT_TIMEOUT_MS	3000

struct kdg_sock {
	struct socket *sock;
	bool connected;
	u32 timeout_ms;
	u64 tx_bytes;
	u64 rx_bytes;
	/* 诊断用：最近一次失败的 errno。0 表示无。 */
	int last_errno;
};

/* 创建 TCP socket（内核态、init_net）。返回 0 或负 errno。 */
int kdg_sock_open(struct kdg_sock *ks);

/* 设置收发超时（毫秒）。会同时作用于后续的 connect/send/recv。 */
void kdg_sock_set_timeout(struct kdg_sock *ks, u32 timeout_ms);

/* 连接到 IPv4 地址（网络字节序）。阻塞至连接建立或超时。 */
int kdg_sock_connect4(struct kdg_sock *ks, u32 addr_be, u16 port_be);

/* 阻塞发送全部 len 字节。返回 0，或负 errno（-ETIMEDOUT/-ECONNRESET/...）。 */
int kdg_sock_send_all(struct kdg_sock *ks, const void *buf, size_t len);

/* 阻塞接收至多 len 字节。返回实际收到的字节数（>0），0 表示对端正常关闭，
 * 或负 errno。注意：**不保证收满 len**，调用方需自行累积。 */
int kdg_sock_recv_some(struct kdg_sock *ks, void *buf, size_t len);

/* 关闭并释放。幂等。 */
void kdg_sock_close(struct kdg_sock *ks);

#endif /* _KDG_SOCK_H */
