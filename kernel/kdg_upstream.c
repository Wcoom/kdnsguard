/* SPDX-License-Identifier: GPL-2.0 */
/*
 * kdg_upstream.c —— 一条上游连接（TCP + TLS + H2）的实现。契约见 kdg_upstream.h。
 */
#define pr_fmt(fmt)	KBUILD_MODNAME ": up: " fmt

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/in.h>

#include "kdg.h"
#include "kdg_upstream.h"
#include "kdg_sock.h"
#include "kdg_tls.h"
#include "kdg_h2.h"

struct kdg_upstream {
	struct kdg_sock		sock;
	struct kdg_tls		tls;
	struct kdg_h2_session  *h2;
	bool			sock_open;
	bool			tls_open;
};

int kdg_upstream_open(struct kdg_upstream **out, const struct kdg_doh_cfg *cfg,
		      u32 deadline_ms)
{
	struct kdg_upstream *u;
	const char *alpn;
	int ret;

	if (!out || !cfg)
		return -EINVAL;

	u = kzalloc(sizeof(*u), GFP_KERNEL);
	if (!u)
		return -ENOMEM;

	if (!deadline_ms)
		deadline_ms = KDG_DEFAULT_DEADLINE_MS;

	ret = kdg_sock_open(&u->sock);
	if (ret)
		goto err;
	u->sock_open = true;

	/* 握手期间用完整 deadline 作为**单次**收发上限：握手要多个往返，
	 * 拿滴答当上限会把正常的网络抖动当成失败。 */
	kdg_sock_set_timeout(&u->sock, deadline_ms);

	ret = kdg_sock_connect4(&u->sock, cfg->ip_be, cfg->port_be);
	if (ret) {
		pr_warn("TCP 连接失败: %d\n", ret);
		goto err;
	}

	ret = kdg_tls_session_open(&u->tls, &u->sock, cfg->hostname);
	if (ret)
		goto err;
	u->tls_open = true;

	/*
	 * 与 kdg_tls_add_ca()/clear_ca() 互斥：信任锚链是共享可变状态，
	 * 握手期间它被读、加载信任锚时它被写。持的是那把模块级锁，因此也
	 * 顺带把 H1 兼容路径排开了 —— 那条路径的握手拿的是同一把锁。
	 *
	 * 稳态的 DRBG 访问**不**靠这把锁：那会让一条长期存在的连接一直占着
	 * 它。稳态由 kdg_tls 内部的 RNG 包装串行化（每次取随机数短暂持锁）。
	 */
	kdg_tls_lock();
	ret = kdg_tls_handshake(&u->tls);
	kdg_tls_unlock();
	if (ret) {
		pr_warn("TLS 握手失败: %d\n", ret);
		goto err;
	}

	alpn = kdg_tls_alpn(&u->tls);
	if (!alpn || strcmp(alpn, "h2") != 0) {
		pr_warn("上游 ALPN=%s（非 h2）\n", alpn ? alpn : "(未协商)");
		ret = -EPROTONOSUPPORT;
		goto err;
	}

	ret = kdg_h2_session_new(&u->h2, &u->tls, cfg->hostname, cfg->path);
	if (ret)
		goto err;

	/* 稳态接收换回滴答：它只决定「多久回来扫一遍」，不是失败判据。 */
	kdg_sock_set_rcv_timeout(&u->sock, KDG_UPSTREAM_TICK_MS);

	pr_info("上游连接就绪（%s:%u，ALPN h2）\n",
		cfg->hostname, ntohs(cfg->port_be));
	*out = u;
	return 0;

err:
	kdg_upstream_close(u);
	return ret;
}

void kdg_upstream_close(struct kdg_upstream *u)
{
	if (!u)
		return;

	/* 顺序是硬的：先会话、再 TLS、最后 socket。会话的析构可能还
	 * 需要往 TLS 写（比如发个 RST），反过来就是写已释放对象。 */
	if (u->h2) {
		kdg_h2_session_free(u->h2);
		u->h2 = NULL;
	}
	if (u->tls_open) {
		kdg_tls_session_close(&u->tls);
		u->tls_open = false;
	}
	if (u->sock_open) {
		kdg_sock_close(&u->sock);
		u->sock_open = false;
	}
	kfree(u);
}

int kdg_upstream_submit(struct kdg_upstream *u, const u8 *body, size_t len,
			struct kdg_h2_stream *st, int32_t *stream_id)
{
	if (!u || !u->h2)
		return -ENOTCONN;
	return kdg_h2_session_submit(u->h2, body, len, st, stream_id);
}

int kdg_upstream_read(struct kdg_upstream *u, u8 *buf, size_t cap)
{
	int n;

	if (!u || !u->tls_open)
		return -ENOTCONN;

	n = kdg_tls_read(&u->tls, buf, cap);
	if (n < 0) {
		if (n == -EAGAIN)
			return -EAGAIN;	/* 滴答到期，不是错误 */
		return -EIO;
	}
	if (n == 0)
		return -EIO;		/* 对端关闭 = 这条连接没了 */

	if (u->h2) {
		if (kdg_h2_session_feed(u->h2, buf, (size_t)n) != 0)
			return -EIO;
		if (kdg_h2_session_flush(u->h2) != 0)
			return -EIO;
	}
	return n;
}

int kdg_upstream_flush(struct kdg_upstream *u)
{
	if (!u || !u->h2)
		return -ENOTCONN;
	return kdg_h2_session_flush(u->h2);
}

void kdg_upstream_reset_stream(struct kdg_upstream *u, int32_t stream_id)
{
	if (!u || !u->h2)
		return;
	kdg_h2_session_reset_stream(u->h2, stream_id);
}

bool kdg_upstream_dead(const struct kdg_upstream *u)
{
	return !u || !u->h2 || kdg_h2_session_dead(u->h2);
}

int kdg_upstream_err(const struct kdg_upstream *u)
{
	if (!u || !u->h2)
		return -ENOTCONN;
	return kdg_h2_session_err(u->h2);
}

u32 kdg_upstream_stream_limit(const struct kdg_upstream *u)
{
	u32 peer;

	if (!u || !u->h2)
		return 0;

	peer = kdg_h2_session_peer_max_streams(u->h2);
	if (peer == 0)
		return KDG_UPSTREAM_STREAMS_INIT;	/* 对端还没发 SETTINGS */

	return clamp_val(peer, 1, (u32)KDG_UPSTREAM_STREAMS_MAX);
}
