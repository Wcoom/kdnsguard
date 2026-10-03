/* SPDX-License-Identifier: GPL-2.0 */
/*
 * kdg_sock.c —— 内核态 TCP socket 实现。设计与约束见 kdg_sock.h。
 */
#define pr_fmt(fmt)	KBUILD_MODNAME ": " fmt

#include <linux/kernel.h>
#include <linux/net.h>
#include <linux/socket.h>
#include <linux/in.h>
#include <linux/inet.h>
#include <linux/tcp.h>
#include <linux/jiffies.h>
#include <net/net_namespace.h>
#include <net/sock.h>

#include "kdg_sock.h"

/*
 * 让新建的内核 socket 处于「阻塞 + 有界超时」状态。
 *
 * 用 init_net 是 P1 的有意选择：本阶段的验收目标是「不改全局网络、
 * 通过 API 完成一次 DoH 查询」，还没有网络上下文（netId/fwmark）的输入面。
 * 方案 §5.3 要求网络适配层传入经过 Android 网络栈验证的 fwmark 与掩码，
 * 那是 P3 的活；届时本函数增加一个 net/fwmark 参数即可，调用方不变。
 */
int kdg_sock_open(struct kdg_sock *ks)
{
	struct socket *sock = NULL;
	int ret;

	if (!ks)
		return -EINVAL;

	memset(ks, 0, sizeof(*ks));
	ks->timeout_ms = KDG_SOCK_DEFAULT_TIMEOUT_MS;

	ret = sock_create_kern(&init_net, AF_INET, SOCK_STREAM, IPPROTO_TCP,
			       &sock);
	if (ret) {
		pr_err("sock_create_kern 失败: %d\n", ret);
		ks->last_errno = ret;
		return ret;
	}
	ks->sock = sock;

	/* 内核 socket 的默认超时是 MAX_SCHEDULE_TIMEOUT（无限等待）。
	 * 一条静默黑洞连接会把调用线程永久挂住 —— 必须显式设界。 */
	kdg_sock_set_timeout(ks, ks->timeout_ms);

	/* 握手与 I/O 都在可睡眠上下文，分配用 GFP_KERNEL。 */
	sock->sk->sk_allocation = GFP_KERNEL;

	/* TCP_NODELAY：DoH 是小请求小响应，等 Nagle 合包只会徒增延迟。
	 * 用导出的 tcp_sock_set_nodelay() 而不是直接戳 tcp_sk(sk)->nonagle —— 
	 * 后者依赖内核内部常量（TCP_NAGLE_OFF 在 include/net/tcp.h，不在 uapi），
	 * 是会被内核内部重构打断的写法；kernel_setsockopt 本内核又未导出。 */
	tcp_sock_set_nodelay(sock->sk);

	return 0;
}

void kdg_sock_set_timeout(struct kdg_sock *ks, u32 timeout_ms)
{
	if (!ks || !ks->sock || !ks->sock->sk)
		return;

	ks->timeout_ms = timeout_ms;
	ks->sock->sk->sk_rcvtimeo = msecs_to_jiffies(timeout_ms);
	ks->sock->sk->sk_sndtimeo = msecs_to_jiffies(timeout_ms);
}

int kdg_sock_connect4(struct kdg_sock *ks, u32 addr_be, u16 port_be)
{
	struct sockaddr_in sa;
	int ret;

	if (!ks || !ks->sock)
		return -EINVAL;

	memset(&sa, 0, sizeof(sa));
	sa.sin_family = AF_INET;
	sa.sin_port = port_be;
	sa.sin_addr.s_addr = addr_be;

	/* kernel_connect 的 flags 用 0：内核 socket 没有 file 描述符，
	 * 非阻塞语义由 sk_rcvtimeo/sk_sndtimeo 表达。 */
	ret = kernel_connect(ks->sock, (struct sockaddr *)&sa, sizeof(sa), 0);
	if (ret) {
		ks->last_errno = ret;
		return ret;
	}

	ks->connected = true;
	return 0;
}

int kdg_sock_send_all(struct kdg_sock *ks, const void *buf, size_t len)
{
	size_t sent = 0;

	if (!ks || !ks->sock || !ks->connected)
		return -ENOTCONN;

	while (sent < len) {
		struct kvec vec = {
			.iov_base = (void *)((const u8 *)buf + sent),
			.iov_len = len - sent,
		};
		struct msghdr msg = { .msg_flags = MSG_NOSIGNAL };

		int ret = kernel_sendmsg(ks->sock, &msg, &vec, 1,
					 len - sent);

		if (ret < 0) {
			/* -EAGAIN/-EWOULDBLOCK 在设置了 sk_sndtimeo 的阻塞
			 * socket 上就是「超时」，不是「稍后再试」。 */
			if (ret == -EAGAIN || ret == -EWOULDBLOCK)
				ret = -ETIMEDOUT;
			ks->last_errno = ret;
			return ret;
		}
		if (ret == 0)
			return -EPIPE;	/* 无法推进，避免死循环 */

		sent += (size_t)ret;
		ks->tx_bytes += (size_t)ret;
	}

	return 0;
}

int kdg_sock_recv_some(struct kdg_sock *ks, void *buf, size_t len)
{
	struct kvec vec = { .iov_base = buf, .iov_len = len };
	struct msghdr msg = { 0 };
	int ret;

	if (!ks || !ks->sock || !ks->connected)
		return -ENOTCONN;

	ret = kernel_recvmsg(ks->sock, &msg, &vec, 1, len, 0);
	if (ret < 0) {
		if (ret == -EAGAIN || ret == -EWOULDBLOCK)
			ret = -ETIMEDOUT;
		ks->last_errno = ret;
		return ret;
	}

	ks->rx_bytes += (size_t)ret;
	return ret;	/* 0 = 对端正常关闭 */
}

void kdg_sock_close(struct kdg_sock *ks)
{
	if (!ks || !ks->sock)
		return;

	/* 先 shutdown 再 release：让对端立刻收到 FIN，而不是等 socket
	 * 引用计数归零。TLS 的 close_notify 已在上层发过。 */
	if (ks->connected)
		kernel_sock_shutdown(ks->sock, SHUT_RDWR);

	sock_release(ks->sock);
	ks->sock = NULL;
	ks->connected = false;
}
