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
#include "kdg_h3.h"
#include "kdg_sock.h"
#include "kdg_tls.h"
#include <linux/ktime.h>
#include "kdg_sock.h"
#include "kdg_tls.h"
#include "kdg_h2.h"

struct kdg_upstream {
	struct kdg_sock		sock;
	struct kdg_tls		tls;
	struct kdg_h2_session  *h2;
	bool			sock_open;
	bool			tls_open;

	/* ── H3（HTTP/3 over QUIC）路径 ──────────────────────────────────
	 * 与 H2 路径互斥：同一个句柄要么走 TCP+TLS+H2，要么走 UDP+QUIC+H3。
	 * 两个都开会让「这条连接现在什么状态」变成没人能回答的问题。 */
	bool			is_h3;
	struct kdg_sock		usock;
	bool			usock_open;
	struct kdg_h3		*h3;
	char			path[256];
	/* 槽位 → 调用方的收集结构；NULL 表示该槽空闲 */
	struct kdg_h2_stream   *st_of[KDG_H3_RSTATES];
};

/* QUIC 的时钟是毫秒单调时钟。ktime_get_ns() 是导出的，且与调度无关。 */
static u64 kdg_up_now_ms(void)
{
	return div_u64(ktime_get_ns(), 1000000ULL);
}

/* 「暂时别试 H3」的截止时刻（见 kdg_upstream_open 里的说明）。 */
static u64 kdg_h3_retry_after_ms;

static u64 now_ms(void)
{
	return kdg_up_now_ms();
}

/* 把 H3 层已完成的请求搬进调用方的 kdg_h2_stream。 */
static void kdg_up_h3_collect(struct kdg_upstream *u)
{
	unsigned int i;

	for (i = 0; i < KDG_H3_RSTATES; i++) {
		struct kdg_h3_req *r = kdg_h3_req_at(u->h3, i);
		struct kdg_h2_stream *st = u->st_of[i];

		if (!st || !r)
			continue;
		if (r->state == H3R_DONE) {
			if (r->status != 200 || !r->ct_ok)
				st->err = -EPROTO;
			else if (r->body_len > st->resp_cap)
				st->err = -EMSGSIZE;
			else {
				memcpy(st->resp, r->body, r->body_len);
				st->resp_len = r->body_len;
			}
			st->status = (u32)r->status;
			st->status_seen = true;
			st->ct_ok = r->ct_ok;
			st->done = true;
			st->in_flight = false;
			u->st_of[i] = NULL;
			kdg_h3_req_release(r);		/* 还回 64 KiB 请求体 */
		} else if (r->state == H3R_FAILED) {
			st->err = r->err ? r->err : -EIO;
			st->done = true;
			st->in_flight = false;
			u->st_of[i] = NULL;
			kdg_h3_req_release(r);
		}
	}
}

static int kdg_upstream_open_h3(struct kdg_upstream *u,
				const struct kdg_doh_cfg *cfg, u32 deadline_ms)
{
	struct kdg_qtp tp;
	const struct mbedtls_x509_crt *ca = kdg_tls_ca_chain();
	u8 pkt[KDG_QC_RX_MAX];		/* 收也用它：见 KDG_QC_RX_MAX 的说明 */
	u64 t0;
	int ret, n;

	if (!ca)
		return -EKEYREJECTED;		/* 没有信任锚就不握手 */

	ret = kdg_sock_open_udp(&u->usock);
	if (ret)
		return ret;
	u->usock_open = true;
	kdg_sock_set_timeout(&u->usock, 100);	/* 握手期短超时，便于轮询重传 */
	ret = kdg_sock_connect4(&u->usock, cfg->ip_be, cfg->port_be);
	if (ret)
		return ret;

	kdg_qtp_defaults(&tp);
	tp.max_idle_timeout = 30000;
	tp.max_udp_payload = 1200;		/* 不做 PMTU 探测 */
	tp.initial_max_data = 1 << 20;
	tp.initial_max_stream_data_bidi_local = 1 << 16;
	tp.initial_max_stream_data_bidi_remote = 1 << 16;
	tp.initial_max_stream_data_uni = 1 << 16;
	tp.initial_max_streams_bidi = KDG_H3_RSTATES;
	tp.initial_max_streams_uni = 3;
	tp.active_cid_limit = 2;

	/* kvmalloc 而不是 kzalloc：struct kdg_h3 内嵌整个 QUIC 连接状态
	 * （包号空间的收发缓冲、流表），尺寸在 200 KiB 量级 —— 真机实测
	 * kmalloc 直接返回 -ENOMEM（并触发一次内核告警），于是 H3 永远建不起来。 */
	u->h3 = kvmalloc(sizeof(*u->h3), GFP_KERNEL);
	if (!u->h3)
		return -ENOMEM;
	ret = kdg_h3_init(u->h3, cfg->hostname, "h3", &tp, ca,
			  kdg_tls_rng_export, NULL, kdg_up_now_ms());
	if (ret)
		return ret;

	/* 握手：QUIC 的丢包恢复要自己驱动，所以这里是「发→收→超时」的循环，
	 * 不是一次阻塞读。
	 *
	 * 计数是**排障必需**：超时到底是「包没出去」「回包没进来」还是
	 * 「进来了但没解开」，三种情况的处理完全不同，光看一个 -ETIMEDOUT
	 * 分不出（真机上第一次跑就遇到这个分不清的处境）。 */
	{
		u32 sent = 0, got = 0, send_err = 0;
		int last_err = 0;

		t0 = kdg_up_now_ms();
		while (kdg_up_now_ms() - t0 < deadline_ms) {
			u64 now = kdg_up_now_ms();
			u64 timer;

			n = (int)kdg_h3_send(u->h3, pkt, sizeof(pkt), now);
			if (n > 0) {
				ret = kdg_sock_send_all(&u->usock, pkt,
							(size_t)n);
				if (ret) {
					send_err++;
					last_err = ret;
					break;
				}
				sent++;
			}
			n = kdg_sock_recv_some(&u->usock, pkt, sizeof(pkt));
			if (n > 0) {
				got++;
				kdg_h3_recv(u->h3, pkt, (size_t)n,
					    kdg_up_now_ms());
				if (kdg_h3_ready(u->h3))
					return 0;
			} else if (n != -ETIMEDOUT && n != -EAGAIN) {
				last_err = n;
				break;
			}
			if (u->h3->qc.state >= QC_CLOSING)
				return -ECONNREFUSED;
			timer = kdg_h3_next_timer(u->h3);
			if (timer && kdg_up_now_ms() >= timer)
				kdg_h3_timeout(u->h3, kdg_up_now_ms());
		}
		pr_info("H3 握手未完成：发出 %u 收 %u 发送失败 %u，解密失败 %llu 丢弃 %llu，最后错误 %d（qc=%d，逾 %ums）\n",
			sent, got, send_err,
			(unsigned long long)u->h3->qc.rx_undecryptable,
			(unsigned long long)u->h3->qc.rx_ignored,
			last_err, (int)u->h3->qc.state,
			(u32)(kdg_up_now_ms() - t0));
	}
	return -ETIMEDOUT;
}


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
	snprintf(u->path, sizeof(u->path), "%s", cfg->path);

	/*
	 * 先试 H3，失败回落 H2。**回落是有意的产品行为**：QUIC 会因中间网络
	 * 封 UDP/443 而失败，而那种网络下 H2 仍然可用。回落只在**建连阶段**
	 * 发生 —— 已经跑起来的 H3 连接中途坏掉，是「这条连接坏了」，换协议
	 * 重试属于池层重建连接的职责，不是这里的。
	 */
	/*
	 * H3 最近失败过就暂时跳过它。
	 *
	 * 为什么必须这样：UDP/443 被封的网络里，每次 H3 尝试都要耗掉整个
	 * deadline（默认 3 秒）才失败 —— 而这个代价发生在**重建连接**时，
	 * 正是 DNS 最不能等的时刻。真机实测：不跳过时重建循环能把
	 * pool_connects 在十几秒里推到 45。60 秒的窗口足够让一次网络切换
	 * 重新被尝到，又不至于让每次重建都白等。
	 */
	if (cfg->allow_h3 && now_ms() >= kdg_h3_retry_after_ms) {
		ret = kdg_upstream_open_h3(u, cfg, deadline_ms);
		if (ret)
			kdg_h3_retry_after_ms = now_ms() + 60000;
		if (!ret) {
			u->is_h3 = true;
			pr_info("上游已连接：HTTP/3（QUIC）\n");
			*out = u;
			return 0;
		}
		pr_info("H3 失败（%d），回落 HTTP/2\n", ret);
		/* 清干净 H3 留下的东西再走 H2 路径 */
		if (u->h3) {
			kdg_h3_fini(u->h3);
			kvfree(u->h3);
			u->h3 = NULL;
		}
		if (u->usock_open) {
			kdg_sock_close(&u->usock);
			u->usock_open = false;
		}
	}

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
	if (u->is_h3) {
		if (u->h3) {
			kdg_h3_fini(u->h3);
			kvfree(u->h3);
			u->h3 = NULL;
		}
		if (u->usock_open) {
			kdg_sock_close(&u->usock);
			u->usock_open = false;
		}
		kfree(u);
		return;
	}
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
	if (!u)
		return -ENOTCONN;
	if (u->is_h3) {
		int slot;

		if (!u->h3)
			return -ENOTCONN;
		for (slot = 0; slot < KDG_H3_RSTATES; slot++)
			if (!u->st_of[slot])
				break;
		if (slot == KDG_H3_RSTATES)
			return -EBUSY;
		{
			int rc = kdg_h3_post(u->h3, u->path, body, len);

			if (rc < 0)
				return rc;
			slot = rc;
		}
		u->st_of[slot] = st;
		st->in_flight = true;
		/* 流号约定：H3 用 1..KDG_H3_RSTATES 表示槽位，0 留给 H2 */
		*stream_id = (int32_t)(slot + 1);
		return 0;
	}
	if (!u->h2)
		return -ENOTCONN;
	return kdg_h2_session_submit(u->h2, body, len, st, stream_id);
}

int kdg_upstream_read(struct kdg_upstream *u, u8 *buf, size_t cap)
{
	int n;

	if (!u)
		return -ENOTCONN;
	if (u->is_h3) {
		u8 rxpkt[KDG_QC_RX_MAX];
		u64 now;

		if (!u->h3 || !u->usock_open)
			return -ENOTCONN;
		/* 必须收进足够大的缓冲：调用方给的 buf 可能只有 MTU 那么大，
		 * 而握手期服务器会发更大的数据报（见 KDG_QC_RX_MAX）。 */
		(void)buf;
		(void)cap;
		n = kdg_sock_recv_some(&u->usock, rxpkt, sizeof(rxpkt));
		now = kdg_up_now_ms();
		if (n < 0) {
			/* UDP 上没有「对端关闭」，收不到就是这一刻没数据 */
			if (n == -EAGAIN || n == -ETIMEDOUT) {
				kdg_h3_timeout(u->h3, now);
				kdg_up_h3_collect(u);
				return -EAGAIN;
			}
			return -EIO;
		}
		if (n == 0)
			return -EAGAIN;
		kdg_h3_recv(u->h3, rxpkt, (size_t)n, now);
		kdg_h3_timeout(u->h3, now);
		kdg_up_h3_collect(u);
		return n;
	}
	if (!u->tls_open)
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
	if (!u)
		return -ENOTCONN;
	if (u->is_h3) {
		u8 pkt[KDG_QC_MTU];
		int n, total = 0;

		if (!u->h3 || !u->usock_open)
			return -ENOTCONN;
		for (;;) {
			n = (int)kdg_h3_send(u->h3, pkt, sizeof(pkt),
					     kdg_up_now_ms());
			if (n <= 0)
				break;
			if (kdg_sock_send_all(&u->usock, pkt, (size_t)n))
				return -EIO;
			total += n;
			if (total > 8 * KDG_QC_MTU)
				break;		/* 一次 flush 不无限发包 */
		}
		kdg_up_h3_collect(u);
		return 0;
	}
	if (!u->h2)
		return -ENOTCONN;
	return kdg_h2_session_flush(u->h2);
}

void kdg_upstream_reset_stream(struct kdg_upstream *u, int32_t stream_id)
{
	if (!u)
		return;
	if (u->is_h3) {
		unsigned int slot = (unsigned int)stream_id - 1;

		if (stream_id <= 0 || slot >= KDG_H3_RSTATES || !u->h3)
			return;
		/* 取消：丢掉该流的重组状态并让对端别再发（QUIC 的 RESET_STREAM
		 * 需要新增发送路径，这里先做「本地不再收」，语义上等价于把这条
		 * 请求忘掉；池层随后会让槽位可复用）。 */
		if (u->st_of[slot]) {
			struct kdg_h3_req *r = kdg_h3_req_at(u->h3, slot);

			u->st_of[slot]->done = true;
			u->st_of[slot]->err = -ECANCELED;
			u->st_of[slot]->in_flight = false;
			u->st_of[slot] = NULL;
			if (r) {
				kdg_qc_stream_free(&u->h3->qc, r->sid);
				kdg_h3_req_release(r);
			}
		}
		return;
	}
	if (!u->h2)
		return;
	kdg_h2_session_reset_stream(u->h2, stream_id);
}

bool kdg_upstream_dead(const struct kdg_upstream *u)
{
	if (!u)
		return true;
	if (u->is_h3)
		return !u->h3 || u->h3->qc.state >= QC_CLOSING ||
		       u->h3->goaway_seen;
	return !u->h2 || kdg_h2_session_dead(u->h2);
}

int kdg_upstream_err(const struct kdg_upstream *u)
{
	if (!u)
		return -ENOTCONN;
	if (u->is_h3) {
		if (!u->h3)
			return -ENOTCONN;
		return u->h3->qc.state >= QC_CLOSING ? -EIO : 0;
	}
	if (!u->h2)
		return -ENOTCONN;
	return kdg_h2_session_err(u->h2);
}

u32 kdg_upstream_stream_limit(const struct kdg_upstream *u)
{
	u32 peer;

	if (!u)
		return 0;
	if (u->is_h3) {
		u32 lim = u->h3 ? (u32)u->h3->qc.peer.initial_max_streams_bidi : 0;

		if (!lim)
			lim = KDG_H3_RSTATES;
		return clamp_val(lim, 1, (u32)KDG_H3_RSTATES);
	}
	if (!u->h2)
		return 0;

	peer = kdg_h2_session_peer_max_streams(u->h2);
	if (peer == 0)
		return KDG_UPSTREAM_STREAMS_INIT;	/* 对端还没发 SETTINGS */

	return clamp_val(peer, 1, (u32)KDG_UPSTREAM_STREAMS_MAX);
}
