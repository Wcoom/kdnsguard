/* SPDX-License-Identifier: GPL-2.0 */
/*
 * kdg_doh.c —— DoH 上游查询实现。设计与约束见 kdg_doh.h。
 */
#define pr_fmt(fmt)	KBUILD_MODNAME ": " fmt

#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/inet.h>
#include <linux/in.h>
#include <linux/timekeeping.h>
#include <linux/ktime.h>

#include "kdg.h"
#include "kdg_doh.h"
#include "kdg_http.h"
#include "kdg_h2.h"

/* KDG_DOH_REQ_MAX / KDG_DOH_RX_MAX 见 kdg_doh.h —— 编排层也在用。
 * 接收缓冲之所以要这么大：方案 §7.4 要求这类大缓冲走有界堆分配、
 * 不放在 kernel stack（两者相加 12 KiB，16 KiB 的栈放不下）。 */

static struct kdg_doh_stats g_stats;

void kdg_doh_get_stats(struct kdg_doh_stats *out)
{
	if (out)
		*out = g_stats;
}

void kdg_doh_default_cfg(struct kdg_doh_cfg *cfg)
{
	if (!cfg)
		return;

	memset(cfg, 0, sizeof(*cfg));
	scnprintf(cfg->hostname, sizeof(cfg->hostname), "%s", KDG_UPSTREAM_HOST);
	scnprintf(cfg->path, sizeof(cfg->path), "%s", KDG_UPSTREAM_PATH);
	cfg->ip_be = in_aton(KDG_BOOTSTRAP_IPV4);
	cfg->port_be = htons(KDG_UPSTREAM_PORT);
	cfg->deadline_ms = KDG_DEFAULT_DEADLINE_MS;
}

/*
 * 构造 DoH POST 请求（RFC 8484 §4.1）。
 *
 * 用 Connection: close 而不是 keep-alive：本阶段一次查询一条连接，
 * 关闭式分帧省掉「响应边界靠 Content-Length 判断」之外的持久连接状态机，
 * 连接的收尾由对端 FIN 或我們的 shutdown 明确表达。P2 的连池会改成 keep-alive。
 */
static int kdg_doh_build_request(const struct kdg_doh_cfg *cfg,
				 const u8 *q, size_t qlen,
				 u8 *buf, size_t cap, size_t *outlen)
{
	int n = scnprintf(buf, cap,
			  "POST %s HTTP/1.1\r\n"
			  "Host: %s\r\n"
			  "User-Agent: kdnsguard/0.1\r\n"
			  "Accept: application/dns-message\r\n"
			  "Content-Type: application/dns-message\r\n"
			  "Content-Length: %zu\r\n"
			  "Connection: close\r\n"
			  "\r\n",
			  cfg->path, cfg->hostname, qlen);

	if (n <= 0 || (size_t)n >= cap)
		return -EMSGSIZE;
	if ((size_t)n + qlen > cap)
		return -EMSGSIZE;

	memcpy(buf + n, q, qlen);
	*outlen = (size_t)n + qlen;
	return 0;
}

/*
 * 收完整个响应，产出正文。
 * 返回 0 或负 errno；*status 回填 HTTP 状态码（无论成败，便于诊断）。
 *
 * 三条与方案 §8 对应的拒绝规则（都在这里落地）：
 *  1. 状态码非 200 一律当失败 —— 不把 3xx 的重定向正文或 4xx 的错误页
 *     当作 DNS 报文去解析；
 *  2. Content-Type 必须是 application/dns-message；
 *  3. 正文长度以 Content-Length/chunked 为准并有硬上限，绝不按声明值预分配。
 */
static int kdg_doh_read_response(struct kdg_tls *tls, u8 *rx, size_t cap,
				 const u8 **body, size_t *bodylen,
				 u32 *status)
{
	struct kdg_http_response hr;
	size_t got = 0;
	bool head_done = false;
	int ret;

	memset(&hr, 0, sizeof(hr));

	for (;;) {
		if (got >= cap) {
			pr_warn("响应超出缓冲上限 %zu\n", cap);
			return -EMSGSIZE;
		}

		ret = kdg_tls_read(tls, rx + got, cap - got);
		if (ret < 0)
			return ret;
		if (ret == 0)
			break;			/* 对端关闭 */
		got += (size_t)ret;

		if (!head_done) {
			int pr = kdg_http_parse_response_head(rx, got, &hr);

			if (pr == KDG_H_NEED_MORE)
				continue;
			if (pr != KDG_H_OK) {
				pr_warn("HTTP 响应头非法: %d\n", pr);
				return -EIO;
			}
			head_done = true;
			*status = (u32)hr.status;

			if (hr.status != 200) {
				pr_warn("DoH 上游返回 HTTP %d\n", hr.status);
				return -EIO;
			}
			if (!hr.ctype_is_dns) {
				pr_warn("Content-Type 不是 application/dns-message\n");
				return -EIO;
			}
			/* 重复的 Content-Length 是响应走私的经典载体 */
			if (kdg_http_count_header(rx, hr.hdr_end,
						  "content-length") > 1) {
				pr_warn("重复的 Content-Length\n");
				return -EIO;
			}
		}

		if (hr.chunked) {
			size_t olen = 0;
			int dr = kdg_http_chunk_decode(rx + hr.hdr_end,
						       got - hr.hdr_end,
						       (u8 *)(rx + hr.hdr_end),
						       cap - hr.hdr_end, &olen);

			if (dr == KDG_H_NEED_MORE)
				continue;
			if (dr == KDG_H_ENOSPC)
				return -EMSGSIZE;
			if (dr != KDG_H_OK) {
				pr_warn("chunked 正文非法: %d\n", dr);
				return -EIO;
			}
			/* 就地解码：产出短于输入，直接指过去即可 */
			*body = rx + hr.hdr_end;
			*bodylen = olen;
			return 0;
		}

		if (hr.has_content_length) {
			size_t have = got - hr.hdr_end;

			if (have >= hr.content_length) {
				*body = rx + hr.hdr_end;
				*bodylen = hr.content_length;
				return 0;
			}
		}
	}

	/* 走到这里说明对端先关了连接。没有 Content-Length 也没有 chunked 时
	 * 「读到 EOF」就是合法的分帧方式；有声明值却没读够则是截断。 */
	if (!head_done) {
		pr_warn("对端在响应头之前关闭了连接\n");
		return -EIO;
	}
	if (hr.has_content_length) {
		size_t have = got - hr.hdr_end;

		if (have < hr.content_length) {
			pr_warn("响应被截断: 声明 %u 实收 %zu\n",
				hr.content_length, have);
			return -EIO;
		}
		*body = rx + hr.hdr_end;
		*bodylen = hr.content_length;
		return 0;
	}
	if (hr.chunked) {
		pr_warn("chunked 响应在结束块之前中断\n");
		return -EIO;
	}

	/* 无 CL 无 chunked：整个剩余部分即正文 */
	*body = rx + hr.hdr_end;
	*bodylen = got - hr.hdr_end;
	return 0;
}

int kdg_doh_query(const struct kdg_doh_cfg *cfg,
		  const u8 *qwire, size_t qlen,
		  u8 *rwire, size_t *rlen)
{
	struct kdg_sock sock;
	struct kdg_tls tls;
	struct kdg_doh_stats *st = &g_stats;
	u8 *tx = NULL, *rx = NULL;
	const u8 *body = NULL;
	size_t bodylen = 0, txlen = 0;
	u32 status = 0;
	ktime_t t0;
	int ret;
	bool sock_open = false, tls_open = false;

	if (!cfg || !qwire || !rwire || !rlen)
		return -EINVAL;
	if (qlen == 0 || qlen > KDG_MAX_WIRE_MSG)
		return -EMSGSIZE;

	st->queries++;
	t0 = ktime_get();

	/* 信任锚为空时立刻拒绝：与其发起一次注定验证失败的握手，不如给出
	 * 明确的 -EAGAIN，让上层知道「是没配置，不是上游坏了」。 */
	if (kdg_tls_ca_count() == 0) {
		pr_warn_ratelimited("信任锚未配置，拒绝发起 DoH 查询\n");
		st->last_errno = -EAGAIN;
		return -EAGAIN;
	}

	/* 方案 §6.2 的「单一执行者」：整个会话（建连→握手→请求→响应→关闭）
	 * 期间独占，避免并发进入 mbedTLS 的共享 DRBG 与 CA 链。 */
	kdg_tls_lock();

	tx = kmalloc(KDG_DOH_REQ_MAX, GFP_KERNEL);
	rx = kmalloc(KDG_DOH_RX_MAX, GFP_KERNEL);
	if (!tx || !rx) {
		ret = -ENOMEM;
		goto out;
	}

	ret = kdg_doh_build_request(cfg, qwire, qlen, tx, KDG_DOH_REQ_MAX,
				    &txlen);
	if (ret)
		goto out;

	ret = kdg_sock_open(&sock);
	if (ret)
		goto out;
	sock_open = true;
	kdg_sock_set_timeout(&sock, cfg->deadline_ms);

	ret = kdg_sock_connect4(&sock, cfg->ip_be, cfg->port_be);
	if (ret) {
		st->net_fail++;
		goto out;
	}

	ret = kdg_tls_session_open(&tls, &sock, cfg->hostname);
	if (ret)
		goto out;
	tls_open = true;

	ret = kdg_tls_handshake(&tls);
	if (ret) {
		st->tls_fail++;
		goto out;
	}

	/*
	 * 传输选择：按 ALPN 协商结果在 H2 与 H1 之间选（方案 §6.3/§6.4）。
	 * H2 是主线目标，H1 是兼容路径 —— 服务端不支持 h2 时自动回落，
	 * 不需要额外探测：ALPN 没协商出 h2 就说明它只支持 1.1。
	 */
	{
		const char *alpn = kdg_tls_alpn(&tls);

	/* ALPN 未协商出任何协议时 kdg_tls_alpn 返回 NULL —— 直接 strcmp 会崩。
	 * 此时按 H1 处理是安全默认：H1 不需要 ALPN 协商即可工作。 */
	if (alpn && strcmp(alpn, "h2") == 0) {
		size_t hl = *rlen;

		ret = kdg_h2_doh_request(&tls, cfg->hostname, cfg->path,
					 qwire, qlen, rwire, hl, &hl);
		if (ret) {
			st->http_fail++;
			st->last_errno = (u32)ret;
			goto out;
		}
		*rlen = hl;
		st->ok++;
		st->last_errno = 0;
		st->last_http_status = 200;
		goto out;
	}
	}

	/* H1 兼容路径 */
	ret = kdg_tls_write(&tls, tx, txlen);
	if (ret) {
		st->net_fail++;
		goto out;
	}

	ret = kdg_doh_read_response(&tls, rx, KDG_DOH_RX_MAX, &body, &bodylen,
				    &status);
	st->last_http_status = status;
	if (ret) {
		st->http_fail++;
		goto out;
	}

	if (bodylen > *rlen) {
		ret = -EMSGSIZE;
		goto out;
	}
	/* body 与 rx 有重叠的可能（chunked 就地解码），用 memmove 而非 memcpy。 */
	memmove(rwire, body, bodylen);
	*rlen = bodylen;

	st->ok++;
	st->last_errno = 0;
	ret = 0;

out:
	if (ret)
		st->last_errno = (u32)ret;
	if (tls_open)
		kdg_tls_session_close(&tls);
	if (sock_open)
		kdg_sock_close(&sock);
	kfree(tx);
	kfree(rx);
	st->last_rtt_ms = (u32)ktime_ms_delta(ktime_get(), t0);
	kdg_tls_unlock();
	return ret;
}
