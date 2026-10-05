/* SPDX-License-Identifier: GPL-2.0 */
/*
 * kdg_h2.c —— 内核态 HTTP/2 会话实现。设计与边界见 kdg_h2.h。
 *
 * 与旧版（每查询一条连接）的关键差别在**回调怎么找到自己的流**：
 *   旧版把「本次请求的收集缓冲」放在会话级 user_data 里，因为一次只有一条流；
 *   新版把 `struct kdg_h2_stream *` 作为 `stream_user_data` 交给 nghttp2，
 *   回调按 `stream_id` 反查出来。这样 N 条流各自的响应互不串台。
 *
 * ⚠️ 线程纪律（整份实现的前提）：**同一时刻只有一个线程能进本文件的任何函数**。
 * nghttp2 的会话不是线程安全的，它的内部缓冲、HPACK 表、流表都假定单线程
 * 驱动。这一条由 kdg_pool.c 的驱动线程保证 —— 本层不做任何加锁，因为
 * 「谁在驱动」这件事在上层已经唯一确定了，在这里再加一层锁只会掩盖设计错误。
 */
#define pr_fmt(fmt)	KBUILD_MODNAME ": h2: " fmt

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/slab.h>

#include <nghttp2/nghttp2.h>

#include "kdg_h2.h"
#include "kdg_tls.h"

/*
 * 连接级接收窗口。HTTP/2 的**默认连接窗口只有 65535 字节**，而方案 §6.3 允许
 * 32–64 条流同时在途：64 条 4 KiB 的 DNS 响应合计 256 KiB，远超它。
 * 默认值下服务端会在发出 64 KiB 后停下等我们的 WINDOW_UPDATE —— 功能正确但
 * 白白多出几个往返（每个往返一次 RTT）。把窗口一次提到 1 MiB，一批爆发就能
 * 一口气发完。
 *
 * 这不是「调大缓冲区」式的盲目加码：它只影响对端的发送节奏，不预分配任何
 * 内存（nghttp2 的窗口是记账，不是缓冲）。
 */
#define KDG_H2_RECV_WINDOW	(1024 * 1024)

/* 我们在 SETTINGS 里宣告的**每流**接收窗口。单条 DNS 响应 ≤ 4 KiB，
 * 每流窗口本来够用；显式声明是为了不让对端按 64 KiB 的默认值做流控推算。 */
#define KDG_H2_STREAM_WINDOW	(256 * 1024)

struct kdg_h2_session {
	struct kdg_tls	*tls;
	nghttp2_session	*sess;
	/* 上游身份。**存在会话里而不是每次提交时由调用方传**：`:authority`
	 * 必须与 TLS 的 SNI/证书校验用的主机名一致，把两者绑在同一个对象里
	 * 就不可能出现「证书验的是 A、请求发的是 B」这种错配。 */
	char		 hostname[256];
	char		 path[256];
	/* 会话级致命错误（GOAWAY、协议错误）。一旦非 0，本会话不能再提交新流。 */
	int		 conn_err;
	bool		 goaway;
	int32_t		 goaway_last_stream;
	int32_t		 goaway_err_code;
	/* 是否收到过对端的 SETTINGS。**必须单独记**：nghttp2 把
	 * remote_settings.max_concurrent_streams 预置成 RFC 默认的 100，
	 * 单看那个值分不清「对端声明了 100」与「对端还什么都没说」。 */
	bool		 peer_settings_seen;
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
	struct kdg_h2_session *s = user_data;
	int ret;

	(void)session;
	(void)flags;

	ret = kdg_tls_write(s->tls, data, length);
	if (ret)
		return NGHTTP2_ERR_CALLBACK_FAILURE;
	return (ssize_t)length;
}

/* 按对端的流号取回我们挂上去的收集结构。取不到就返回 NULL —— 调用方必须容忍：
 * 服务端对我们已 RST 的流继续发帧、或发起 push 时都会走到这里。 */
static struct kdg_h2_stream *h2_stream_of(nghttp2_session *session,
					  int32_t stream_id)
{
	return nghttp2_session_get_stream_user_data(session, stream_id);
}

static int h2_header_cb(nghttp2_session *session, const nghttp2_frame *frame,
			const uint8_t *name, size_t namelen,
			const uint8_t *value, size_t valuelen,
			uint8_t flags, void *user_data)
{
	struct kdg_h2_stream *st;

	(void)flags;
	(void)user_data;

	/* 只关心响应头；请求头的回调不该出现（我们是客户端）。 */
	if (frame->hd.type != NGHTTP2_HEADERS ||
	    frame->headers.cat != NGHTTP2_HCAT_RESPONSE)
		return 0;

	st = h2_stream_of(session, frame->hd.stream_id);
	if (!st)
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
		st->status = (u32)v;
		st->status_seen = true;
		g_stat.last_status = (u32)v;
	} else if (namelen == 12 &&
		   memcmp(name, "content-type", 12) == 0) {
		/* 只在带参数前的主类型上比较（"application/dns-message;..."） */
		if (valuelen >= 23 &&
		    memcmp(value, "application/dns-message", 23) == 0)
			st->ct_ok = true;
	}

	return 0;
}

static int h2_data_chunk_cb(nghttp2_session *session, uint8_t flags,
			    int32_t stream_id, const uint8_t *data, size_t len,
			    void *user_data)
{
	struct kdg_h2_stream *st;

	(void)flags;
	(void)user_data;

	st = h2_stream_of(session, stream_id);
	if (!st)
		return 0;	/* 已取消的流，丢弃即可 */

	if (st->resp_len + len > st->resp_cap) {
		/* 明确失败而不是截断：截断的 DNS 响应会被上层的 wire 校验
		 * 当成畸形报文，不如在这里就报清楚。
		 * TEMPORAL_CALLBACK_FAILURE 只毁掉这条流，连接与其他流不受影响。 */
		st->err = -EMSGSIZE;
		return NGHTTP2_ERR_TEMPORAL_CALLBACK_FAILURE;
	}

	memcpy(st->resp + st->resp_len, data, len);
	st->resp_len += len;
	return 0;
}

static int h2_frame_recv_cb(nghttp2_session *session,
			    const nghttp2_frame *frame, void *user_data)
{
	struct kdg_h2_session *s = user_data;
	struct kdg_h2_stream *st;

	switch (frame->hd.type) {
	case NGHTTP2_HEADERS:
	case NGHTTP2_DATA:
		st = h2_stream_of(session, frame->hd.stream_id);
		/* END_STREAM 表示这条响应到此为止 */
		if (st && (frame->hd.flags & NGHTTP2_FLAG_END_STREAM))
			st->done = true;
		break;
	case NGHTTP2_SETTINGS:
		/* 只认对端发来的 SETTINGS（带 ACK 的是它对我们 SETTINGS 的回应） */
		if (!(frame->hd.flags & NGHTTP2_FLAG_ACK))
			s->peer_settings_seen = true;
		break;
	case NGHTTP2_GOAWAY:
		/*
		 * 连接级终止：本会话不能再用于任何新请求。
		 *
		 * 语义上 GOAWAY 带 last_stream_id：大于它的流**没被处理过**，
		 * 重试是安全的（RFC 9113 §6.8）。本层只如实记录，不在这里重试
		 * —— 重试是编排层的决策，它才知道同名合并与配额的状态。
		 */
		s->goaway = true;
		s->goaway_last_stream = frame->goaway.last_stream_id;
		s->goaway_err_code = (int32_t)frame->goaway.error_code;
		if (!s->conn_err)
			s->conn_err = -ECONNRESET;
		g_stat.goaways++;
		break;
	default:
		break;
	}
	return 0;
}

static int h2_stream_close_cb(nghttp2_session *session, int32_t stream_id,
			      uint32_t error_code, void *user_data)
{
	struct kdg_h2_stream *st;

	(void)user_data;

	st = h2_stream_of(session, stream_id);
	if (!st)
		return 0;

	st->in_flight = false;
	if (error_code != NGHTTP2_NO_ERROR) {
		st->stream_close_err = error_code;
		g_stat.stream_resets++;
		/* 流被重置时若还没拿到完整响应，就是失败。 */
		if (!st->done && !st->err)
			st->err = -ECONNRESET;
	} else if (st->done && !st->err) {
		/*
		 * 「协议层干净关闭」。
		 *
		 * ⚠️ 它与「这次 DoH 请求成功」**不是一回事**：后者还要 200 与
		 * content-type，那由池层判定（KDG_HA_POOL_* 那一组）。这里只是
		 * 会话视角下唯一有意义的成功量。
		 *
		 * 这行是补回来的：旧版 `h2_ok` 的 `g_stat.ok++` 长在「一次请求
		 * 一个会话」的那条路径上，那个路径被删掉之后它**再也没被写过**，
		 * 于是 GET_HEALTH 里 `h2_ok` 恒为 0 —— 一个永远报 0 的诊断量比
		 * 没有这个量更糟，它会被当成「一次都没成功」。
		 */
		g_stat.ok++;
	}
	st->done = true;
	return 0;
}

/* 把请求正文分块喂给 nghttp2。source->ptr 是提交时挂上去的流对象。 */
static ssize_t h2_body_read_cb(nghttp2_session *session, int32_t stream_id,
			       uint8_t *buf, size_t length,
			       uint32_t *data_flags,
			       nghttp2_data_source *source, void *user_data)
{
	struct kdg_h2_stream *st = source->ptr;
	size_t n;

	(void)session;
	(void)stream_id;
	(void)user_data;

	if (!st)
		return NGHTTP2_ERR_TEMPORAL_CALLBACK_FAILURE;

	n = st->body_len - st->body_off;
	if (n > length)
		n = length;

	if (n) {
		memcpy(buf, st->body + st->body_off, n);
		st->body_off += n;
	}

	if (st->body_off >= st->body_len)
		*data_flags |= NGHTTP2_DATA_FLAG_EOF;

	return (ssize_t)n;
}

/* ── 会话 ────────────────────────────────────────────────────────────── */

static ssize_t h2_len(const char *s)
{
	return (ssize_t)strlen(s);
}

int kdg_h2_session_new(struct kdg_h2_session **out, struct kdg_tls *tls,
		       const char *hostname, const char *path)
{
	nghttp2_session_callbacks *cbs = NULL;
	nghttp2_settings_entry iv[2];
	struct kdg_h2_session *s;
	int ret;

	if (!out || !tls || !hostname || !path)
		return -EINVAL;

	s = kzalloc(sizeof(*s), GFP_KERNEL);
	if (!s)
		return -ENOMEM;
	s->tls = tls;

	/* 用 scnprintf 而不是 strscpy：这里要的是「超长就截断」而不是
	 * 「超长报错」—— 上游主机名/路径来自编入设备或事务下发的配置，
	 * 长度由各自的生成方保证；本层只需保证不会越界。 */
	scnprintf(s->hostname, sizeof(s->hostname), "%s", hostname);
	scnprintf(s->path, sizeof(s->path), "%s", path);

	ret = nghttp2_session_callbacks_new(&cbs);
	if (ret != 0) {
		ret = -ENOMEM;
		goto fail;
	}

	nghttp2_session_callbacks_set_send_callback(cbs, h2_send_cb);
	nghttp2_session_callbacks_set_on_header_callback(cbs, h2_header_cb);
	nghttp2_session_callbacks_set_on_data_chunk_recv_callback(
		cbs, h2_data_chunk_cb);
	nghttp2_session_callbacks_set_on_frame_recv_callback(cbs,
							     h2_frame_recv_cb);
	nghttp2_session_callbacks_set_on_stream_close_callback(
		cbs, h2_stream_close_cb);

	ret = nghttp2_session_client_new(&s->sess, cbs, s);
	/* 回调容器用完即可释放：nghttp2 会把需要的内容拷进会话。 */
	nghttp2_session_callbacks_del(cbs);
	cbs = NULL;

	if (ret != 0) {
		g_stat.proto_errors++;
		g_stat.last_nghttp2_err = (u32)ret;
		pr_warn("session_client_new 失败: %d\n", ret);
		ret = -EBADMSG;
		goto fail;
	}

	/*
	 * 方案 §6.3「限制 header list / HPACK 内存」：把自己的
	 * SETTINGS_MAX_HEADER_LIST_SIZE 告诉对端。
	 * server push 无需显式关闭 —— nghttp2 作为客户端在初始 SETTINGS 里
	 * 就把 ENABLE_PUSH 置 0 了（这是它的既有行为，不是我们加的）。
	 */
	iv[0].settings_id = NGHTTP2_SETTINGS_MAX_HEADER_LIST_SIZE;
	iv[0].value = KDG_H2_MAX_HEADER_BYTES;
	iv[1].settings_id = NGHTTP2_SETTINGS_INITIAL_WINDOW_SIZE;
	iv[1].value = KDG_H2_STREAM_WINDOW;
	ret = nghttp2_submit_settings(s->sess, NGHTTP2_FLAG_NONE, iv,
				      ARRAY_SIZE(iv));
	if (ret != 0) {
		g_stat.proto_errors++;
		g_stat.last_nghttp2_err = (u32)ret;
		ret = -EBADMSG;
		goto fail;
	}

	/* 连接级窗口不受 SETTINGS 控制，得单独调（见 KDG_H2_RECV_WINDOW）。 */
	ret = nghttp2_session_set_local_window_size(s->sess, NGHTTP2_FLAG_NONE,
						    0, KDG_H2_RECV_WINDOW);
	if (ret != 0) {
		g_stat.proto_errors++;
		g_stat.last_nghttp2_err = (u32)ret;
		ret = -EBADMSG;
		goto fail;
	}

	/* 会话级的 :authority/:path 已在上面按配置拷入。 */
	g_stat.sessions++;
	*out = s;
	return 0;

fail:
	if (s->sess)
		nghttp2_session_del(s->sess);
	if (cbs)
		nghttp2_session_callbacks_del(cbs);
	kfree(s);
	return ret;
}

void kdg_h2_session_free(struct kdg_h2_session *s)
{
	if (!s)
		return;
	if (s->sess)
		nghttp2_session_del(s->sess);
	kfree(s);
}

int kdg_h2_session_submit(struct kdg_h2_session *s,
			  const u8 *body, size_t len,
			  struct kdg_h2_stream *st, int32_t *stream_id)
{
	nghttp2_data_provider prd;
	nghttp2_nv nva[6];
	int32_t id;

	if (!s || !s->sess || !body || !st || !stream_id)
		return -EINVAL;
	if (s->conn_err)
		return s->conn_err;

	/* 每次提交都重置消费进度，让同一个 stream 结构可以被复用。 */
	st->body = body;
	st->body_len = len;
	st->body_off = 0;
	st->done = false;
	st->err = 0;
	st->status = 0;
	st->status_seen = false;
	st->ct_ok = false;
	st->resp_len = 0;
	st->stream_close_err = 0;
	st->in_flight = true;

	/* 伪头必须在前（RFC 9113 §8.3）。
	 * nva[] 里指向 hostname/path 的指针由 nghttp2 在 submit 内部按长度
	 * 拷贝进 HPACK 表，调用方不必保证它们在请求结束前一直有效。 */
	nva[0] = (nghttp2_nv){ (uint8_t *)":method", (uint8_t *)"POST", 7, 4,
			       NGHTTP2_NV_FLAG_NONE };
	nva[1] = (nghttp2_nv){ (uint8_t *)":scheme", (uint8_t *)"https", 7, 5,
			       NGHTTP2_NV_FLAG_NONE };
	nva[2] = (nghttp2_nv){ (uint8_t *)":authority", (uint8_t *)s->hostname,
			       10, (size_t)h2_len(s->hostname),
			       NGHTTP2_NV_FLAG_NONE };
	nva[3] = (nghttp2_nv){ (uint8_t *)":path", (uint8_t *)s->path, 5,
			       (size_t)h2_len(s->path), NGHTTP2_NV_FLAG_NONE };
	nva[4] = (nghttp2_nv){ (uint8_t *)"content-type",
			       (uint8_t *)"application/dns-message", 12, 23,
			       NGHTTP2_NV_FLAG_NONE };
	nva[5] = (nghttp2_nv){ (uint8_t *)"accept",
			       (uint8_t *)"application/dns-message", 6, 23,
			       NGHTTP2_NV_FLAG_NONE };
	/* content-length 由 nghttp2 依 data provider 自动补，无需显式给；
	 * 给了反而可能与分块喂入的实际长度不一致。 */

	prd.source.ptr = st;
	prd.read_callback = h2_body_read_cb;

	id = nghttp2_submit_request(s->sess, NULL, nva, ARRAY_SIZE(nva),
				    &prd, st);
	if (id < 0) {
		st->in_flight = false;
		g_stat.proto_errors++;
		g_stat.last_nghttp2_err = (u32)id;
		pr_warn("submit_request 失败: %d\n", id);
		return -EBADMSG;
	}

	*stream_id = id;
	g_stat.requests++;
	return 0;
}

int kdg_h2_session_feed(struct kdg_h2_session *s, const u8 *buf, size_t len)
{
	ssize_t rv;

	if (!s || !s->sess)
		return -EINVAL;

	rv = nghttp2_session_mem_recv(s->sess, buf, len);
	if (rv < 0) {
		g_stat.proto_errors++;
		g_stat.last_nghttp2_err = (u32)rv;
		pr_warn("mem_recv 失败: %zd\n", rv);
		if (!s->conn_err)
			s->conn_err = -EBADMSG;
		return -EBADMSG;
	}
	return 0;
}

int kdg_h2_session_flush(struct kdg_h2_session *s)
{
	int ret;

	if (!s || !s->sess)
		return -EINVAL;

	ret = nghttp2_session_send(s->sess);
	if (ret != 0) {
		g_stat.proto_errors++;
		g_stat.last_nghttp2_err = (u32)ret;
		if (!s->conn_err)
			s->conn_err = -EBADMSG;
		return -EBADMSG;
	}
	return 0;
}

void kdg_h2_session_reset_stream(struct kdg_h2_session *s, int32_t stream_id)
{
	if (!s || !s->sess)
		return;

	/* CANCEL 是「我们主动不要这个响应了」，与对端侧的错误区分开 ——
	 * 诊断时「上游慢」和「上游坏」是两件事。 */
	nghttp2_submit_rst_stream(s->sess, NGHTTP2_FLAG_NONE, stream_id,
				  NGHTTP2_CANCEL);
}

bool kdg_h2_session_dead(const struct kdg_h2_session *s)
{
	return !s || !s->sess || s->conn_err != 0;
}

int kdg_h2_session_err(const struct kdg_h2_session *s)
{
	return s ? s->conn_err : -EINVAL;
}

u32 kdg_h2_session_peer_max_streams(const struct kdg_h2_session *s)
{
	if (!s || !s->sess || !s->peer_settings_seen)
		return 0;
	return nghttp2_session_get_remote_settings(
		s->sess, NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS);
}

bool kdg_h2_session_peer_settings_seen(const struct kdg_h2_session *s)
{
	return s && s->peer_settings_seen;
}
