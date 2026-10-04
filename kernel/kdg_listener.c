/* SPDX-License-Identifier: GPL-2.0 */
/*
 * kdg_listener.c —— loopback DNS listener for PREPARE/COMMIT.
 *
 * The listener is deliberately bound to 127.0.0.1/[::1]:1054. Port 53 remains
 * owned by the existing network until the NAT ownership transaction commits.
 * UDP and TCP share kdg_resolve(), so wire validation/cache/singleflight have
 * one implementation. All socket I/O runs in kthreads, never in a Netfilter hook.
 */
#define pr_fmt(fmt) KBUILD_MODNAME ": listener: " fmt

#include <linux/delay.h>
#include <linux/kthread.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/net.h>
#include <linux/slab.h>
#include <linux/socket.h>
#include <linux/wait.h>
#include <linux/in.h>
#include <linux/in6.h>
#include <net/sock.h>

#include "kdg.h"
#include "kdg_doh.h"
#include "kdg_resolve.h"
#include "kdg_wire.h"
#include "kdg_listener.h"

#define KDG_LISTEN_BACKLOG 16
#define KDG_LISTENER_RX_MAX KDG_MAX_WIRE_MSG

struct kdg_listener {
	struct socket *udp4;
	struct socket *udp6;
	struct socket *tcp4;
	struct socket *tcp6;
	struct task_struct *udp4_task;
	struct task_struct *udp6_task;
	struct task_struct *tcp4_task;
	struct task_struct *tcp6_task;
	struct kdg_doh_cfg cfg;
	struct mutex lock;
	bool ready;
	bool stopping;
};

static struct kdg_listener g_listener;

static int kdg_listener_set_timeout(struct socket *sock, u32 ms)
{
	if (!sock || !sock->sk)
		return -EINVAL;
	sock->sk->sk_rcvtimeo = msecs_to_jiffies(ms);
	sock->sk->sk_sndtimeo = msecs_to_jiffies(ms);
	return 0;
}

static int kdg_listener_bind_udp(struct socket **out, int family)
{
	struct socket *sock;
	int ret;

	ret = sock_create_kern(&init_net, family, SOCK_DGRAM, IPPROTO_UDP, &sock);
	if (ret)
		return ret;
	if (family == AF_INET) {
		struct sockaddr_in addr = {
			.sin_family = AF_INET,
			.sin_port = htons(KDG_DEFAULT_LISTEN_PORT),
			.sin_addr.s_addr = htonl(INADDR_LOOPBACK),
		};
		ret = kernel_bind(sock, (struct sockaddr *)&addr, sizeof(addr));
	} else {
		struct sockaddr_in6 addr = {
			.sin6_family = AF_INET6,
			.sin6_port = htons(KDG_DEFAULT_LISTEN_PORT),
			.sin6_addr = IN6ADDR_LOOPBACK_INIT,
		};
		ret = kernel_bind(sock, (struct sockaddr *)&addr, sizeof(addr));
	}
	if (ret) {
		sock_release(sock);
		return ret;
	}
	kdg_listener_set_timeout(sock, KDG_DEFAULT_DEADLINE_MS);
	*out = sock;
	return 0;
}

static int kdg_listener_bind_tcp(struct socket **out, int family)
{
	struct socket *sock;
	int ret;

	ret = sock_create_kern(&init_net, family, SOCK_STREAM, IPPROTO_TCP, &sock);
	if (ret)
		return ret;
	if (family == AF_INET) {
		struct sockaddr_in addr = {
			.sin_family = AF_INET,
			.sin_port = htons(KDG_DEFAULT_LISTEN_PORT),
			.sin_addr.s_addr = htonl(INADDR_LOOPBACK),
		};
		ret = kernel_bind(sock, (struct sockaddr *)&addr, sizeof(addr));
	} else {
		struct sockaddr_in6 addr = {
			.sin6_family = AF_INET6,
			.sin6_port = htons(KDG_DEFAULT_LISTEN_PORT),
			.sin6_addr = IN6ADDR_LOOPBACK_INIT,
		};
		ret = kernel_bind(sock, (struct sockaddr *)&addr, sizeof(addr));
	}
	if (!ret)
		ret = kernel_listen(sock, KDG_LISTEN_BACKLOG);
	if (ret) {
		sock_release(sock);
		return ret;
	}
	kdg_listener_set_timeout(sock, KDG_DEFAULT_DEADLINE_MS);
	*out = sock;
	return 0;
}

static int kdg_listener_query(const struct kdg_doh_cfg *cfg,
			      const u8 *query, size_t qlen,
			      u8 *reply, size_t *reply_len)
{
	struct kdg_resolve_req req = {
		.cfg = cfg,
		.net_id = 0,
		.profile_gen = READ_ONCE(kdg_cfg.generation),
	};
	enum kdg_source source;

	return kdg_resolve(&req, query, qlen, reply, reply_len, &source);
}

static int kdg_listener_recv_udp(struct socket *sock, struct kdg_doh_cfg *cfg)
{
	u8 *query = kmalloc(KDG_LISTENER_RX_MAX, GFP_KERNEL);
	u8 *reply = kmalloc(KDG_LISTENER_RX_MAX, GFP_KERNEL);
	struct sockaddr_storage peer = { 0 };
	int peer_len = sizeof(peer);
	struct kvec in_vec = { .iov_base = query, .iov_len = KDG_LISTENER_RX_MAX };
	struct kvec out_vec = { .iov_base = reply, .iov_len = KDG_LISTENER_RX_MAX };
	struct msghdr in_msg = {
		.msg_name = &peer,
		.msg_namelen = peer_len,
	};
	struct msghdr out_msg = {
		.msg_name = &peer,
		.msg_namelen = peer_len,
	};
	int ret;
	size_t reply_len;

	if (!query || !reply) {
		kfree(query);
		kfree(reply);
		return -ENOMEM;
	}
	ret = kernel_recvmsg(sock, &in_msg, &in_vec, 1, KDG_LISTENER_RX_MAX, 0);
	peer_len = in_msg.msg_namelen;
	if (ret <= 0)
		goto out;
	reply_len = KDG_LISTENER_RX_MAX;
	ret = kdg_listener_query(cfg, query, ret, reply, &reply_len);
	if (!ret) {
		out_vec.iov_len = reply_len;
		ret = kernel_sendmsg(sock, &out_msg, &out_vec, 1, reply_len);
	}
out:
	kfree(query);
	kfree(reply);
	return ret;
}

static int kdg_listener_udp_thread(void *arg)
{
	struct socket *sock = arg;

	while (!kthread_should_stop()) {
		int ret = kdg_listener_recv_udp(sock, &g_listener.cfg);

		if (ret == -EINTR || ret == -ERESTARTSYS || ret == -EAGAIN || ret == -ETIMEDOUT)
			continue;
		if (ret < 0 && kthread_should_stop())
			break;
	}
	return 0;
}

static int kdg_listener_recv_exact(struct socket *sock, u8 *buf, size_t len)
{
	size_t off = 0;

	while (off < len) {
		struct kvec vec = { .iov_base = buf + off, .iov_len = len - off };
		struct msghdr msg = { 0 };
		int ret = kernel_recvmsg(sock, &msg, &vec, 1, len - off, 0);

		if (ret <= 0)
			return ret ? ret : -ECONNRESET;
		off += ret;
	}
	return 0;
}

static int kdg_listener_tcp_connection(struct socket *sock)
{
	u8 *query = kmalloc(KDG_LISTENER_RX_MAX, GFP_KERNEL);
	u8 *reply = kmalloc(KDG_LISTENER_RX_MAX, GFP_KERNEL);
	u8 prefix[2];
	struct kvec vec;
	struct msghdr msg = { 0 };
	size_t reply_len;
	int ret;

	if (!query || !reply) {
		ret = -ENOMEM;
		goto out;
	}
	ret = kdg_listener_recv_exact(sock, prefix, sizeof(prefix));
	if (ret)
		goto out;
	{
		u16 qlen = ((u16)prefix[0] << 8) | prefix[1];
		if (!qlen || qlen > KDG_LISTENER_RX_MAX) {
			ret = -EMSGSIZE;
			goto out;
		}
		ret = kdg_listener_recv_exact(sock, query, qlen);
		if (ret)
			goto out;
		reply_len = KDG_LISTENER_RX_MAX;
		ret = kdg_listener_query(&g_listener.cfg, query, qlen, reply, &reply_len);
		if (ret)
			goto out;
		if (reply_len > 0xffff) {
			ret = -EMSGSIZE;
			goto out;
		}
		prefix[0] = (u8)(reply_len >> 8);
		prefix[1] = (u8)reply_len;
		vec.iov_base = prefix;
		vec.iov_len = sizeof(prefix);
		ret = kernel_sendmsg(sock, &msg, &vec, 1, sizeof(prefix));
		if (ret != sizeof(prefix))
			goto out;
		vec.iov_base = reply;
		vec.iov_len = reply_len;
		ret = kernel_sendmsg(sock, &msg, &vec, 1, reply_len);
	}
out:
	kfree(query);
	kfree(reply);
	return ret;
}

static int kdg_listener_tcp_thread(void *arg)
{
	struct socket *listen = arg;

	while (!kthread_should_stop()) {
		struct socket *client = NULL;
		int ret = kernel_accept(listen, &client, 0);

		if (ret < 0) {
			if (kthread_should_stop())
				break;
			continue;
		}
		kdg_listener_set_timeout(client, KDG_DEFAULT_DEADLINE_MS);
		kdg_listener_tcp_connection(client);
		kernel_sock_shutdown(client, SHUT_RDWR);
		sock_release(client);
	}
	return 0;
}

static void kdg_listener_shutdown_socket(struct socket *sock)
{
	if (sock)
		kernel_sock_shutdown(sock, SHUT_RDWR);
}

static void kdg_listener_release_socket(struct socket **sock)
{
	if (*sock) {
		sock_release(*sock);
		*sock = NULL;
	}
}

bool kdg_listener_ready(void)
{
	return READ_ONCE(g_listener.ready);
}

static int kdg_listener_probe_upstream(void)
{
	static const u8 query[] = {
		0x4b, 0x44, 0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0,
		7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0,
		0, 1, 0, 1,
	};
	struct kdg_doh_cfg cfg;
	u8 *reply;
	size_t reply_len = KDG_DOH_RX_MAX;
	int ret;

	if (!kdg_tls_ca_count())
		return -EAGAIN;
	reply = kmalloc(KDG_DOH_RX_MAX, GFP_KERNEL);
	if (!reply)
		return -ENOMEM;
	kdg_doh_default_cfg(&cfg);
	ret = kdg_doh_query(&cfg, query, sizeof(query), reply, &reply_len);
	if (!ret)
		ret = kdg_wire_match_response(query, sizeof(query), reply,
					      reply_len, &(struct kdg_summary){ 0 });
	kfree(reply);
	return ret;
}

int kdg_listener_prepare(void)
{
	int ret;

	mutex_lock(&g_listener.lock);
	if (g_listener.ready) {
		mutex_unlock(&g_listener.lock);
		return 0;
	}
	if (g_listener.stopping) {
		mutex_unlock(&g_listener.lock);
		return -ESHUTDOWN;
	}
	kdg_doh_default_cfg(&g_listener.cfg);
	ret = kdg_listener_bind_udp(&g_listener.udp4, AF_INET);
	if (ret)
		goto fail;
	ret = kdg_listener_bind_udp(&g_listener.udp6, AF_INET6);
	if (ret)
		goto fail;
	ret = kdg_listener_bind_tcp(&g_listener.tcp4, AF_INET);
	if (ret)
		goto fail;
	ret = kdg_listener_bind_tcp(&g_listener.tcp6, AF_INET6);
	if (ret)
		goto fail;
	ret = kdg_listener_probe_upstream();
	if (ret)
		goto fail;
	g_listener.udp4_task = kthread_run(kdg_listener_udp_thread, g_listener.udp4,
					   "kdg-udp4");
	if (IS_ERR(g_listener.udp4_task)) {
		ret = PTR_ERR(g_listener.udp4_task);
		g_listener.udp4_task = NULL;
		goto fail;
	}
	g_listener.udp6_task = kthread_run(kdg_listener_udp_thread, g_listener.udp6,
					   "kdg-udp6");
	if (IS_ERR(g_listener.udp6_task)) {
		ret = PTR_ERR(g_listener.udp6_task);
		g_listener.udp6_task = NULL;
		goto fail;
	}
	g_listener.tcp4_task = kthread_run(kdg_listener_tcp_thread, g_listener.tcp4,
					   "kdg-tcp4");
	if (IS_ERR(g_listener.tcp4_task)) {
		ret = PTR_ERR(g_listener.tcp4_task);
		g_listener.tcp4_task = NULL;
		goto fail;
	}
	g_listener.tcp6_task = kthread_run(kdg_listener_tcp_thread, g_listener.tcp6,
					   "kdg-tcp6");
	if (IS_ERR(g_listener.tcp6_task)) {
		ret = PTR_ERR(g_listener.tcp6_task);
		g_listener.tcp6_task = NULL;
		goto fail;
	}
	WRITE_ONCE(g_listener.ready, true);
	mutex_unlock(&g_listener.lock);
	pr_info("UDP/TCP loopback listener ready on port %u\n",
		KDG_DEFAULT_LISTEN_PORT);
	return 0;
fail:
	g_listener.stopping = true;
	kdg_listener_shutdown_socket(g_listener.udp4);
	kdg_listener_shutdown_socket(g_listener.udp6);
	kdg_listener_shutdown_socket(g_listener.tcp4);
	kdg_listener_shutdown_socket(g_listener.tcp6);
	{
		struct task_struct *tasks[] = {
			g_listener.udp4_task, g_listener.udp6_task,
			g_listener.tcp4_task, g_listener.tcp6_task,
		};
		int i;
		g_listener.udp4_task = NULL;
		g_listener.udp6_task = NULL;
		g_listener.tcp4_task = NULL;
		g_listener.tcp6_task = NULL;
		mutex_unlock(&g_listener.lock);
		for (i = 0; i < ARRAY_SIZE(tasks); i++)
			if (tasks[i])
				kthread_stop(tasks[i]);
	}
	mutex_lock(&g_listener.lock);
	kdg_listener_release_socket(&g_listener.udp4);
	kdg_listener_release_socket(&g_listener.udp6);
	kdg_listener_release_socket(&g_listener.tcp4);
	kdg_listener_release_socket(&g_listener.tcp6);
	g_listener.stopping = false;
	mutex_unlock(&g_listener.lock);
	return ret;
}

void kdg_listener_stop(void)
{
	struct task_struct *tasks[4];
	int i;

	mutex_lock(&g_listener.lock);
	g_listener.stopping = true;
	tasks[0] = g_listener.udp4_task;
	tasks[1] = g_listener.udp6_task;
	tasks[2] = g_listener.tcp4_task;
	tasks[3] = g_listener.tcp6_task;
	g_listener.udp4_task = NULL;
	g_listener.udp6_task = NULL;
	g_listener.tcp4_task = NULL;
	g_listener.tcp6_task = NULL;
	WRITE_ONCE(g_listener.ready, false);
	kdg_listener_shutdown_socket(g_listener.udp4);
	kdg_listener_shutdown_socket(g_listener.udp6);
	kdg_listener_shutdown_socket(g_listener.tcp4);
	kdg_listener_shutdown_socket(g_listener.tcp6);
	mutex_unlock(&g_listener.lock);
	for (i = 0; i < ARRAY_SIZE(tasks); i++)
		if (tasks[i] && !IS_ERR(tasks[i]))
			kthread_stop(tasks[i]);
	mutex_lock(&g_listener.lock);
	kdg_listener_release_socket(&g_listener.udp4);
	kdg_listener_release_socket(&g_listener.udp6);
	kdg_listener_release_socket(&g_listener.tcp4);
	kdg_listener_release_socket(&g_listener.tcp6);
	g_listener.stopping = false;
	mutex_unlock(&g_listener.lock);
}

	int kdg_listener_init_state(void)
{
	mutex_init(&g_listener.lock);
	return 0;
}

