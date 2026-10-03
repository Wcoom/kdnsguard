/* SPDX-License-Identifier: GPL-2.0 */
/*
 * kdg_h2.c —— 内核态 HTTP/2 DoH 客户端实现。设计与边界见 kdg_h2.h。
 */
#define pr_fmt(fmt)	KBUILD_MODNAME ": h2: " fmt

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/slab.h>

#include <nghttp2/nghttp2.h>

#include "kdg_h2.h"

/* 接收缓冲。**必须堆分配**：16 KiB 的内核栈放不下，方案 §7.4 也要求
 * 「64 KiB DNS/TLS 等大缓冲按需走有界堆分配」。 */
#define KDG_H2_IN_BUF	4096

struct kdg_h2_ctx {
	struct kdg_tls	       *tls;
	/* 请求正文（由 data provider 分块喂给 nghttp2） */
	const u8	       *body;
	size_t			body_len;
	size_t			body_off;
	/* 响应收集 */
	u8		       *resp;
	size_t			resp_cap;
	size_t			resp_len;
	int			status;		/* HTTP 状态码 */
	bool			status_seen;
	bool			ct_ok;
	bool			done;
	int			err;		/* 首个错误（负 errno） */
	u32			stream_close_err;
};

static struct kdg_h2_stats g_stat;

void kdg_h2_get_stats(struct kdg_h2_stats *out)
{
	if (out)
		*out = g_stat;
}

/* ── 回调 ────────────────────────────────────────────────────────────── */

static ssize_t h2_send_cb(nghttp2_session *session, const uint8_t *data,
			  size_t length, int flags, void *user_data)
{
	struct kdg_h2_ctx *c = user_data;
	int ret;

	(void)session;
	(void)flags;

	ret = kdg_tls_write(c->tls, data, length);
	if (ret)
		return NGHTTP2_ERR_CALLBACK_FAILURE;
	return (ssize_t)length;
}

static int h2_header_cb(nghttp2_session *session, const nghttp2_frame *frame,
			const uint8_t *name, size_t namelen,
			const uint8_t *value, size_t valuelen,
			uint8_t flags, void *user_data)
{
	struct kdg_h2_ctx *c = user_data;

	(void)session;
	(void)flags;

	/* 只关心响应头；请求头的回调不该出现（我们是客户端）。 */
	if (frame->hd.type != NGHTTP2_HEADERS ||
	    frame->headers.cat != NGHTTP2_HCAT_RESPONSE)
		return 0;

	if (namelen == 7 && memcmp(name, ":status", 7) == 0) {
		unsigned int v = 0;
		size_t i;

		for (i = 0; i < valuelen; i++) {
			if (value[i] < '0' || value[i] > '9')
				return 0;
			v = v * 10 + (unsigned int)(value[i] - '0');
			if (v > 999)
				return 0;
		}
		c->status = (int)v;
		c->status_seen = true;
		g_stat.last_status = (u32)v;
	} else if (namelen == 12 &&
		   memcmp(name, "content-type", 12) == 0) {
		/* 只在带参数前的主类型上比较（"application/dns-message;..."） */
		if (valuelen >= 23 &&
		    memcmp(value, "application/dns-message", 23) == 0)
			c->ct_ok = true;
	}

	return 0;
}

static int h2_data_chunk_cb(nghttp2_session *session, uint8_t flags,
			    int32_t stream_id, const uint8_t *data, size_t len,
			    void *user_data)
{
	struct kdg_h2_ctx *c = user_data;

	(void)session;
	(void)flags;
	(void)stream_id;

	if (c->resp_len + len > c->resp_cap) {
		/* 明确失败而不是截断：截断的 DNS 响应会被上层的 wire 校验
		 * 当成畸形报文，不如在这里就报清楚。 */
		c->err = -EMSGSIZE;
		return NGHTTP2_ERR_TEMPORAL_CALLBACK_FAILURE;
	}

	memcpy(c->resp + c->resp_len, data, len);
	c->resp_len += len;
	return 0;
}

static int h2_frame_recv_cb(nghttp2_session *session,
			    const nghttp2_frame *frame, void *user_data)
{
	struct kdg_h2_ctx *c = user_data;

	(void)session;

	switch (frame->hd.type) {
	case NGHTTP2_HEADERS:
	case NGHTTP2_DATA:
		/* END_STREAM 表示这条响应到此为止 */
		if (frame->hd.flags & NGHTTP2_FLAG_END_STREAM)
			c->done = true;
		break;
	case NGHTTP2_GOAWAY:
		/* 连接级终止：本次请求不可能再有响应了 */
		c->err = -ECONNRESET;
		c->done = true;
		break;
	default:
		break;
	}
	return 0;
}

static int h2_stream_close_cb(nghttp2_session *session, int32_t stream_id,
			      uint32_t error_code, void *user_data)
{
	struct kdg_h2_ctx *c = user_data;

	(void)session;
	(void)stream_id;

	if (error_code != NGHTTP2_NO_ERROR) {
		c->stream_close_err = error_code;
		g_stat.stream_resets++;
		/* 流被重置时若还没拿到完整响应，就是失败。 */
		if (!c->done && !c->err)
			c->err = -ECONNRESET;
	}
	c->done = true;
	return 0;
}

/* 把请求正文分块喂给 nghttp2。 */
static ssize_t h2_body_read_cb(nghttp2_session *session, int32_t stream_id,
			       uint8_t *buf, size_t length,
			       uint32_t *data_flags,
			       nghttp2_data_source *source, void *user_data)
{
	struct kdg_h2_ctx *c = user_data;
	size_t n;

	(void)session;
	(void)stream_id;
	(void)source;

	n = c->body_len - c->body_off;
	if (n > length)
		n = length;

	if (n) {
		memcpy(buf, c->body + c->body_off, n);
		c->body_off += n;
	}

	if (c->body_off >= c->body_len)
		*data_flags |= NGHTTP2_DATA_FLAG_EOF;

	return (ssize_t)n;
}

/* ── 主流程 ──────────────────────────────────────────────────────────── */

static ssize_t h2_len(const char *s)
{
	return (ssize_t)strlen(s);
}

int kdg_h2_doh_request(struct kdg_tls *tls, const char *hostname,
		       const char *path,
		       const u8 *body, size_t body_len,
		       u8 *resp, size_t resp_cap, size_t *resp_len)
{
	nghttp2_session_callbacks *cbs = NULL;
	nghttp2_session *session = NULL;
	nghttp2_data_provider prd;
	nghttp2_settings_entry iv[1];
	nghttp2_nv nva[6];
	struct kdg_h2_ctx ctx;
	u8 *inbuf = NULL;
	char clen[24];
	int32_t stream_id;
	int ret = 0;
	unsigned int rounds = 0;

	if (!tls || !hostname || !path || !body || !resp || !resp_len)
		return -EINVAL;

	*resp_len = 0;
	g_stat.requests++;

	memset(&ctx, 0, sizeof(ctx));
	ctx.tls = tls;
	ctx.body = body;
	ctx.body_len = body_len;
	ctx.resp = resp;
	ctx.resp_cap = resp_cap;

	inbuf = kmalloc(KDG_H2_IN_BUF, GFP_KERNEL);
	if (!inbuf)
		return -ENOMEM;

	ret = nghttp2_session_callbacks_new(&cbs);
	if (ret != 0) {
		ret = -ENOMEM;
		goto out;
	}

	nghttp2_session_callbacks_set_send_callback(cbs, h2_send_cb);
	nghttp2_session_callbacks_set_on_header_callback(cbs, h2_header_cb);
	nghttp2_session_callbacks_set_on_data_chunk_recv_callback(
		cbs, h2_data_chunk_cb);
	nghttp2_session_callbacks_set_on_frame_recv_callback(cbs,
							     h2_frame_recv_cb);
	nghttp2_session_callbacks_set_on_stream_close_callback(
		cbs, h2_stream_close_cb);

	ret = nghttp2_session_client_new(&session, cbs, &ctx);
	/* 回调容器用完即可释放：nghttp2 会把需要的内容拷进会话。 */
	nghttp2_session_callbacks_del(cbs);
	cbs = NULL;

	if (ret != 0) {
		g_stat.proto_errors++;
		g_stat.last_nghttp2_err = (u32)ret;
		pr_warn("session_client_new 失败: %d\n", ret);
		ret = -EBADMSG;
		goto out;
	}
	g_stat.sessions++;

	/*
	 * 方案 §6.3「限制 header list / HPACK 内存」：把自己的
	 * SETTINGS_MAX_HEADER_LIST_SIZE 告诉对端。
	 * server push 无需显式关闭 —— nghttp2 作为客户端在初始 SETTINGS 里
	 * 就把 ENABLE_PUSH 置 0 了（这是它的既有行为，不是我们加的）。
	 */
	iv[0].settings_id = NGHTTP2_SETTINGS_MAX_HEADER_LIST_SIZE;
	iv[0].value = KDG_H2_MAX_HEADER_BYTES;
	ret = nghttp2_submit_settings(session, NGHTTP2_FLAG_NONE, iv, 1);
	if (ret != 0) {
		g_stat.proto_errors++;
		g_stat.last_nghttp2_err = (u32)ret;
		ret = -EBADMSG;
		goto out;
	}

	/* 构造请求头。伪头必须在前（RFC 9113 §8.3）。 */
	scnprintf(clen, sizeof(clen), "%zu", body_len);
	nva[0] = (nghttp2_nv){ (uint8_t *)":method", (uint8_t *)"POST", 7, 4,
			       NGHTTP2_NV_FLAG_NONE };
	nva[1] = (nghttp2_nv){ (uint8_t *)":scheme", (uint8_t *)"https", 7, 5,
			       NGHTTP2_NV_FLAG_NONE };
	nva[2] = (nghttp2_nv){ (uint8_t *)":authority", (uint8_t *)hostname,
			       10, (size_t)h2_len(hostname),
			       NGHTTP2_NV_FLAG_NONE };
	nva[3] = (nghttp2_nv){ (uint8_t *)":path", (uint8_t *)path, 5,
			       (size_t)h2_len(path), NGHTTP2_NV_FLAG_NONE };
	nva[4] = (nghttp2_nv){ (uint8_t *)"content-type",
			       (uint8_t *)"application/dns-message", 12, 23,
			       NGHTTP2_NV_FLAG_NONE };
	nva[5] = (nghttp2_nv){ (uint8_t *)"accept",
			       (uint8_t *)"application/dns-message", 6, 23,
			       NGHTTP2_NV_FLAG_NONE };
	/* content-length 由 nghttp2 依 data provider 自动补，无需显式给；
	 * 给了反而可能与分块喂入的实际长度不一致。 */
	(void)clen;

	prd.source.ptr = NULL;
	prd.read_callback = h2_body_read_cb;

	stream_id = nghttp2_submit_request(session, NULL, nva, 6, &prd, NULL);
	if (stream_id < 0) {
		g_stat.proto_errors++;
		g_stat.last_nghttp2_err = (u32)stream_id;
		pr_warn("submit_request 失败: %d\n", stream_id);
		ret = -EBADMSG;
		goto out;
	}

	/* 先把请求刷出去 */
	ret = nghttp2_session_send(session);
	if (ret != 0) {
		g_stat.proto_errors++;
		g_stat.last_nghttp2_err = (u32)ret;
		ret = -EBADMSG;
		goto out;
	}

	/*
	 * 收发循环。上界由底层 TLS socket 的超时（cfg->deadline_ms）保证：
	 * kdg_tls_read 超时会返回 -ETIMEDOUT，不会永久挂住。
	 * rounds 只是防呆上界，避免对端持续发无意义帧把这里变成 CPU 占用点。
	 */
	while (!ctx.done && !ctx.err && rounds++ < 256) {
		ssize_t n, rv;

		n = kdg_tls_read(tls, inbuf, KDG_H2_IN_BUF);
		if (n < 0) {
			ret = (int)n;	/* 含 -ETIMEDOUT */
			goto out;
		}
		if (n == 0) {
			/* 对端关闭。若响应已收齐由 ctx.done 处理，否则算失败。 */
			if (!ctx.done) {
				ret = -ECONNRESET;
				goto out;
			}
			break;
		}

		rv = nghttp2_session_mem_recv(session, inbuf, (size_t)n);
		if (rv < 0) {
			g_stat.proto_errors++;
			g_stat.last_nghttp2_err = (u32)rv;
			pr_warn("mem_recv 失败: %zd\n", rv);
			ret = -EBADMSG;
			goto out;
		}

		/* recv 可能排入了要回的帧（SETTINGS 的 ACK、WINDOW_UPDATE 等） */
		rv = nghttp2_session_send(session);
		if (rv != 0) {
			g_stat.proto_errors++;
			g_stat.last_nghttp2_err = (u32)rv;
			ret = -EBADMSG;
			goto out;
		}
	}

	if (ctx.err) {
		ret = ctx.err;
		goto out;
	}
	if (!ctx.done) {
		pr_warn("H2 响应在轮次上限内未收齐\n");
		ret = -ETIMEDOUT;
		goto out;
	}
	if (!ctx.status_seen) {
		pr_warn("H2 响应缺少 :status\n");
		ret = -EBADMSG;
		goto out;
	}

	/* 与 H1 路径同一套验收标准（方案 §8）：非 200 不当 DNS 用。 */
	if (ctx.status != 200) {
		g_stat.non_200++;
		pr_warn("H2 DoH 上游返回 %d\n", ctx.status);
		ret = -EPROTO;
		goto out;
	}
	if (!ctx.ct_ok) {
		pr_warn("H2 Content-Type 不是 application/dns-message\n");
		ret = -EBADMSG;
		goto out;
	}

	*resp_len = ctx.resp_len;
	g_stat.ok++;
	ret = 0;

out:
	if (ret) {
		g_stat.failed++;
		if (ret == -ECONNRESET && ctx.stream_close_err)
			pr_warn("流被重置，error_code=%u\n", ctx.stream_close_err);
	}
	if (session)
		nghttp2_session_del(session);
	if (cbs)
		nghttp2_session_callbacks_del(cbs);
	kfree(inbuf);
	return ret;
}
