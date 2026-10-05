// SPDX-License-Identifier: GPL-2.0
/*
 * kdg_h3.c —— 精简 HTTP/3 客户端（RFC 9114），范围见 kdg_h3.h。
 *
 * 对端单向流（控制流）在 QUIC 层已按流的帧交付，这里只解 H3 帧本身；
 * 请求流上的响应由本层的帧解析器处理（kdg_h3_feed 单独可测）。
 */
#include "kdg_h3.h"

/* 宿主排障用的最小跟踪；内核构建下展开为空。 */
#ifdef KDG_H3_TRACE
#define H3_TRACE(...) fprintf(stderr, "[h3] " __VA_ARGS__)
#else
#define H3_TRACE(...) do { } while (0)
#endif

#ifdef __KERNEL__
#include <linux/slab.h>
#include <linux/mm.h>
#define h3_alloc(n)	kvmalloc((n), GFP_KERNEL)
#define h3_free(p)	kvfree(p)
#else
#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#define h3_alloc(n)	malloc(n)
#define h3_free(p)	free(p)
#endif

static struct kdg_h3_req *h3_slot_of(struct kdg_h3 *h, u64 sid)
{
	size_t i;

	for (i = 0; i < KDG_H3_RSTATES; i++)
		if (h->req[i].sid == sid &&
		    h->req[i].state != H3R_IDLE)
			return &h->req[i];
	return NULL;
}

static struct kdg_h3_req *h3_slot_new(struct kdg_h3 *h, u64 sid)
{
	size_t i;

	for (i = 0; i < KDG_H3_RSTATES; i++) {
		if (h->req[i].state == H3R_IDLE) {
			memset(&h->req[i], 0, sizeof(h->req[i]));
			h->req[i].sid = sid;
			h->req[i].state = H3R_OPEN;
			return &h->req[i];
		}
	}
	return NULL;
}

/* ── 帧解析：增量状态机，可跨多次 feed ───────────────────────────── */
/* 只处理请求流（响应）与控制流（SETTINGS/GOAWAY）。 */
static int h3_frame(struct kdg_h3 *h, struct kdg_h3_parser *fp,
		    struct kdg_h3_req *r, u64 type, u64 len, const u8 *p);

/* 拼一个 varint：返回 1 完成、0 还需更多字节、负值为编码错误。 */
static int h3_varint(struct kdg_h3_parser *fp, const u8 **in, size_t *left,
		     u64 *out)
{
	u8 first;

	if (!fp->vlen) {
		if (!*left)
			return 0;
		first = **in;
		fp->vneed = (u8)(1u << (first >> 6));
		if (fp->vneed > sizeof(fp->vbuf))
			return -H3E_FRAME_ERROR;
	}
	while (fp->vlen < fp->vneed && *left) {
		fp->vbuf[fp->vlen++] = **in;
		(*in)++;
		(*left)--;
	}
	if (fp->vlen < fp->vneed)
		return 0;
	{
		unsigned i;
		u64 v = fp->vbuf[0] & 0x3f;

		for (i = 1; i < fp->vneed; i++)
			v = v << 8 | fp->vbuf[i];
		*out = v;
	}
	fp->vlen = 0;
	fp->vneed = 0;
	return 1;
}

void kdg_h3_req_init(struct kdg_h3_req *r, u64 sid)
{
	memset(r, 0, sizeof(*r));
	r->sid = sid;
	r->state = H3R_OPEN;
}

void kdg_h3_req_release(struct kdg_h3_req *r)
{
	h3_free(r->body);
	memset(r, 0, sizeof(*r));
	r->state = H3R_IDLE;
}

/*
 * 增量帧解析（状态在 fp 里，载荷去向按帧类型定）。
 *   阶段 0/1：读帧类型、帧长度（可能被拆在多次 feed 里）
 *   阶段 2：载荷收进 r->hbuf（HEADERS，请求流）或 fp->pbuf（GOAWAY，控制流）
 *   阶段 3：DATA 载荷逐段追加到 body（请求流）
 *   阶段 4：其余帧类型的载荷直接丢弃（RFC 9114 §9：未知帧必须被忽略）
 */
int kdg_h3_feed(struct kdg_h3 *h, struct kdg_h3_parser *fp,
		struct kdg_h3_req *r, const u8 *data, size_t len, bool fin)
{
	const u8 *p = data;
	size_t left = len;
	int ret;

	if (!fp || (!r && !fp->is_control))
		return -EINVAL;
	for (;;) {
		if (fp->stage <= 1) {
			u64 v;
			int rc = h3_varint(fp, &p, &left, &v);

			if (rc < 0)
				return rc;
			if (!rc)
				break;
			if (fp->stage == 0) {
				fp->ftype = v;
				fp->stage = 1;
			} else {
				fp->frem = v;
				if (fp->ftype == H3F_HEADERS) {
					if (fp->is_control)	/* 控制流不得有 HEADERS */
						return -H3E_FRAME_UNEXPECTED;
					if (v > KDG_H3_HDR_MAX)
						return -H3E_EXCESSIVE_LOAD;
					fp->stage = 2;
					fp->plen = 0;
				} else if (fp->ftype == H3F_GOAWAY) {
					if (v > sizeof(fp->pbuf))
						return -H3E_FRAME_ERROR;
					fp->stage = 2;
					fp->plen = 0;
				} else if (fp->ftype == H3F_DATA) {
					if (fp->is_control)
						return -H3E_FRAME_UNEXPECTED;
					fp->stage = 3;
				} else if (fp->is_control && fp->ftype != H3F_SETTINGS &&
					   fp->ftype != H3F_MAX_PUSH_ID &&
					   fp->ftype != H3F_CANCEL_PUSH) {
					return -H3E_FRAME_UNEXPECTED;
				} else if (!fp->is_control &&
					   (fp->ftype == H3F_PUSH_PROMISE ||
					    fp->ftype == H3F_CANCEL_PUSH ||
					    fp->ftype == H3F_MAX_PUSH_ID)) {
					/* 我们从不发 MAX_PUSH_ID，所以任何推送相关帧都是
					 * ID_ERROR（§7.2.3 / §7.2.5），不能当未知帧忽略。 */
					return -H3E_ID_ERROR;
				} else {
					fp->stage = 4;
				}
			}
			continue;
		}
		if (fp->stage == 2) {
			size_t take = left < fp->frem ? left : (size_t)fp->frem;
			u8 *dst = r ? r->hbuf + r->hlen : fp->pbuf + fp->plen;

			memcpy(dst, p, take);
			if (r)
				r->hlen += take;
			else
				fp->plen += take;
			p += take;
			left -= take;
			fp->frem -= take;
			if (fp->frem) {
				if (!left)
					break;
				continue;
			}
			ret = h3_frame(h, fp, r, fp->ftype,
				       r ? r->hlen : fp->plen,
				       r ? r->hbuf : fp->pbuf);
			if (ret)
				return ret;
			fp->stage = 0;
			continue;
		}
		if (fp->stage == 3) {
			size_t take = left < fp->frem ? left : (size_t)fp->frem;

			if (!r || !r->got_headers)
				return -H3E_FRAME_UNEXPECTED;	/* DATA 在 HEADERS 前 */
			if (!r->body)
				return -H3E_INTERNAL;
			if (r->body_len + take > r->body_cap)
				return -H3E_EXCESSIVE_LOAD;
			memcpy(r->body + r->body_len, p, take);
			r->body_len += take;
			p += take;
			left -= take;
			fp->frem -= take;
			if (fp->frem) {
				if (!left)
					break;
				continue;
			}
			fp->stage = 0;
			continue;
		}
		/* 阶段 4：丢弃 */
		{
			size_t take = left < fp->frem ? left : (size_t)fp->frem;

			p += take;
			left -= take;
			fp->frem -= take;
			if (fp->frem) {
				if (!left)
					break;
				continue;
			}
			fp->stage = 0;
		}
	}
	if (fin) {
		if (fp->is_control)
			return -H3E_CLOSED_CRITICAL;	/* 控制流不得 FIN */
		if (fp->stage != 0)
			return -H3E_FRAME_ERROR;	/* 帧未收全就 FIN */
		if (!r || !r->got_headers)
			return -H3E_REQUEST_INCOMPLETE;
		if (r->body_len < 12)
			return -H3E_MESSAGE_ERROR;	/* DNS 报文至少 12 字节头 */
		r->fin = true;
		r->state = H3R_DONE;
	}
	return 0;
}

static int h3_frame(struct kdg_h3 *h, struct kdg_h3_parser *fp,
		    struct kdg_h3_req *r, u64 type, u64 len, const u8 *p)
{
	H3_TRACE("frame ctl=%d type=%llu len=%llu\n", fp->is_control,
		 (unsigned long long)type, (unsigned long long)len);
	if (fp->is_control) {
		if (type == H3F_SETTINGS)
			return 0;	/* 接受，不做协商 */
		if (type == H3F_GOAWAY) {
			u64 id = 0;
			unsigned i;

			if (len > 8)
				return -H3E_FRAME_ERROR;
			for (i = 0; i < len; i++)
				id = id << 8 | p[i];
			h->goaway_seen = true;
			h->goaway_id = id;
			return 0;
		}
		return -H3E_FRAME_UNEXPECTED;
	}
	if (!r)
		return -H3E_INTERNAL;
	switch (type) {
	case H3F_HEADERS: {
		const struct kdg_qpack_field *st;

		if (r->got_headers)
			return -H3E_FRAME_UNEXPECTED;
		kdg_qpack_dec_init(&h->dec, h->decbuf, sizeof(h->decbuf));
		if (kdg_qpack_decode(&h->dec, p, (size_t)len, h->fields,
				     KDG_QPACK_MAX_FIELDS))
			return -H3E_QPACK_DECOMPRESSION_FAILED;
		st = kdg_qpack_find(h->fields, h->dec.nfields, ":status");
		if (!st || st->val_len != 3)
			return -H3E_MESSAGE_ERROR;
		if (st->val[0] < '0' || st->val[0] > '9' || st->val[1] < '0' ||
		    st->val[1] > '9' || st->val[2] < '0' || st->val[2] > '9')
			return -H3E_MESSAGE_ERROR;
		r->status = (st->val[0] - '0') * 100 + (st->val[1] - '0') * 10 +
			    (st->val[2] - '0');
		{
			static const char want[] = "application/dns-message";
			const struct kdg_qpack_field *ct =
				kdg_qpack_find(h->fields, h->dec.nfields,
					       "content-type");

			r->ct_ok = ct && ct->val_len == sizeof(want) - 1 &&
				   !memcmp(ct->val, want, sizeof(want) - 1);
		}
		r->got_headers = true;
		return 0;
	}
	case H3F_DATA:
		/* DATA 的载荷由 feed 逐段写进 body，这里不该被调用 */
		if (!r->got_headers)
			return -H3E_FRAME_UNEXPECTED;
		return 0;
	case H3F_PUSH_PROMISE:
		return -H3E_ID_ERROR;
	default:
		return -H3E_FRAME_UNEXPECTED;
	}
}

static struct kdg_h3_uni *h3_uni_of(struct kdg_h3 *h, u64 id, bool create)
{
	size_t i;

	for (i = 0; i < KDG_H3_UNI_MAX; i++)
		if (h->uni[i].id == id)
			return &h->uni[i];
	if (!create)
		return NULL;
	for (i = 0; i < KDG_H3_UNI_MAX; i++) {
		if (!h->uni[i].id) {
			memset(&h->uni[i], 0, sizeof(h->uni[i]));
			h->uni[i].id = id;
			h->uni[i].fp.is_control = true;
			return &h->uni[i];
		}
	}
	return NULL;
}

static int h3_uni_feed(struct kdg_h3 *h, struct kdg_h3_uni *u, const u8 *data,
		       size_t len)
{
	const u8 *p = data;
	size_t left = len;

	if (!u->type_known) {
		if (!u->tlen) {
			if (!left)
				return 0;
			u->tneed = (u8)(1u << (p[0] >> 6));
			if (u->tneed > sizeof(u->tbuf))
				return -H3E_STREAM_CREATION;
		}
		while (u->tlen < u->tneed && left) {
			u->tbuf[u->tlen++] = *p++;
			left--;
		}
		if (u->tlen < u->tneed)
			return 0;
		{
			unsigned i;
			u64 v = u->tbuf[0] & 0x3f;

			for (i = 1; i < u->tneed; i++)
				v = v << 8 | u->tbuf[i];
			u->type = v;
		}
		u->type_known = true;
		/* §6.2：单向流类型必须是已知的四种之一，且控制流只能有一条 */
		if (u->type == H3S_QPACK_ENC || u->type == H3S_QPACK_DEC ||
		    u->type == H3S_PUSH)
			return 0;	/* 我们不消费，但必须读完丢弃 */
		if (u->type != H3S_CONTROL)
			return -H3E_STREAM_CREATION;
	}
	if (u->type != H3S_CONTROL)
		return 0;		/* QPACK/推送流：丢弃字节即可 */
	return kdg_h3_feed(h, &u->fp, NULL, p, left, false);
}

/* ── 连接与控制流 ─────────────────────────────────────────────────── */
static int h3_open_control(struct kdg_h3 *h)
{
	u8 buf[64];
	size_t n = 0;
	s64 sid;
	u32 w = kdg_qv_put(buf + n, sizeof(buf) - n, H3S_CONTROL);

	if (!w)
		return -ENOSPC;
	n += w;
	w = kdg_qv_put(buf + n, sizeof(buf) - n, H3F_SETTINGS);
	if (!w)
		return -ENOSPC;
	n += w;
	w = kdg_qv_put(buf + n, sizeof(buf) - n, 3 * 4);	/* 三组设置 */
	if (!w)
		return -ENOSPC;
	n += w;
	/* 容量 0：禁止对端用动态表，解码侧因此可以只认静态表 */
	w = kdg_qv_put(buf + n, sizeof(buf) - n, H3_SET_QPACK_MAX_TABLE_CAPACITY);
	if (!w)
		return -ENOSPC;
	n += w;
	w = kdg_qv_put(buf + n, sizeof(buf) - n, 0);
	if (!w)
		return -ENOSPC;
	n += w;
	w = kdg_qv_put(buf + n, sizeof(buf) - n, H3_SET_QPACK_BLOCKED_STREAMS);
	if (!w)
		return -ENOSPC;
	n += w;
	w = kdg_qv_put(buf + n, sizeof(buf) - n, 0);
	if (!w)
		return -ENOSPC;
	n += w;
	w = kdg_qv_put(buf + n, sizeof(buf) - n, H3_SET_MAX_FIELD_SECTION_SIZE);
	if (!w)
		return -ENOSPC;
	n += w;
	w = kdg_qv_put(buf + n, sizeof(buf) - n, 8192);
	if (!w)
		return -ENOSPC;
	n += w;

	sid = kdg_qc_stream_open(&h->qc, true);
	if (sid < 0)
		return (int)sid;
	if (kdg_qc_stream_write(&h->qc, (u64)sid, buf, n, false))
		return -EIO;
	h->control_open = true;
	h->settings_sent = true;
	return 0;
}

/* 返回 0 表示已开或尚不该开 */
/*
 * 控制流只能在拿到服务器传输参数之后开：QUIC 里 initial_max_streams_uni
 * 缺省为 0（RFC 9000 §18.2），握手中途开单向流会被对端判为 STREAM_LIMIT_ERROR。
 * 第一版在 init 里就开，于是初始化直接失败——这正是真机/真服务器才暴露的。
 */
static int h3_maybe_open_control(struct kdg_h3 *h)
{
	if (h->control_open || !h->qc.peer_tp_ok)
		return 0;
	if (h->qc.state < QC_ESTABLISHED)
		return 0;
	if (h3_open_control(h))
		return -EIO;
	return 0;
}

int kdg_h3_init(struct kdg_h3 *h, const char *host, const char *alpn,
		const struct kdg_qtp *tp, const mbedtls_x509_crt *ca,
		kdg_rng_fn rng, void *rng_ctx, u64 now)
{
	memset(h, 0, sizeof(*h));
	snprintf(h->authority, sizeof(h->authority), "%s", host);
	return kdg_qc_init(&h->qc, host, alpn, tp, ca, rng, rng_ctx, now);
}

void kdg_h3_fini(struct kdg_h3 *h)
{
	size_t i;

	for (i = 0; i < KDG_H3_RSTATES; i++)
		if (h->req[i].state != H3R_IDLE)
			kdg_h3_req_release(&h->req[i]);
	kdg_qc_fini(&h->qc);
}

bool kdg_h3_ready(const struct kdg_h3 *h)
{
	return h->qc.state >= QC_ESTABLISHED && !h->goaway_seen;
}

int kdg_h3_post(struct kdg_h3 *h, const char *path, const u8 *body,
		size_t body_len)
{
	u8 buf[768], hdr[128];
	struct kdg_h3_req *r;
	s64 sid;
	int n;
	size_t o = 0, w;

	if (!kdg_h3_ready(h))
		return -EAGAIN;
	if (!h->control_open) {
		int cr = h3_maybe_open_control(h);

		if (cr || !h->control_open)
			return -EAGAIN;
	}
	if (body_len > 65535)
		return -EMSGSIZE;
	n = kdg_qpack_encode_post(hdr, sizeof(hdr), h->authority, path);
	if (n <= 0)
		return -EMSGSIZE;
	sid = kdg_qc_stream_open(&h->qc, false);
	if (sid < 0)
		return (int)sid;
	r = h3_slot_new(h, (u64)sid);
	if (!r)
		return -ENOSPC;
	/* 请求体按需分配：并发只发生在真正在途的请求上，空闲槽位不占 64 KiB。
	 * 用 kvmalloc：这块 64 KiB 常在大块分配里失败。 */
	r->body = h3_alloc(KDG_H3_BODY_MAX);
	if (!r->body) {
		kdg_h3_req_release(r);
		kdg_qc_stream_free(&h->qc, (u64)sid);
		return -ENOMEM;
	}
	r->body_cap = KDG_H3_BODY_MAX;
	/* HEADERS（不以 FIN 结束，后面还有 DATA），再 DATA，最后带 FIN 收尾 */
	w = kdg_qv_put(buf + o, sizeof(buf) - o, H3F_HEADERS);
	if (!w)
		return -ENOSPC;
	o += w;
	w = kdg_qv_put(buf + o, sizeof(buf) - o, (u64)n);
	if (!w)
		return -ENOSPC;
	o += w;
	memcpy(buf + o, hdr, (size_t)n);
	o += (size_t)n;
	w = kdg_qv_put(buf + o, sizeof(buf) - o, H3F_DATA);
	if (!w)
		return -ENOSPC;
	o += w;
	w = kdg_qv_put(buf + o, sizeof(buf) - o, body_len);
	if (!w)
		return -ENOSPC;
	o += w;
	if (o + body_len > sizeof(buf))
		return -EMSGSIZE;	/* 报文过大：调用方应改用分片发送 */
	memcpy(buf + o, body, body_len);
	o += body_len;
	if (kdg_qc_stream_write(&h->qc, (u64)sid, buf, o, true))
		return -EIO;
	return (int)(r - h->req);
}

struct kdg_h3_req *kdg_h3_req_at(struct kdg_h3 *h, size_t i)
{
	return i < KDG_H3_RSTATES ? &h->req[i] : NULL;
}

/* ── 与 QUIC 层的胶水 ─────────────────────────────────────────────── */
static void h3_pump_streams(struct kdg_h3 *h)
{
	u32 it = 0;
	u64 id;

	while (kdg_qc_stream_next_readable(&h->qc, &id, &it)) {
		u8 tmp[512];	/* 内核栈软上限 2048 字节/帧：这个缓冲不能开大 */
		struct kdg_h3_req *r = h3_slot_of(h, id);
		struct kdg_h3_uni *u = NULL;
		s64 n;
		bool fin = false;

		if (!r && (id & 0x03) == 0x03) {	/* 对端单向流 */
			u = h3_uni_of(h, id, true);
			if (!u)
				continue;
		} else if (!r) {
			continue;	/* 未知的对端双向流：不接收 */
		}
		for (;;) {
			n = kdg_qc_stream_read(&h->qc, id, tmp, sizeof(tmp),
					       &fin);
			if (n <= 0)
				break;
			if (u) {
				int ret = h3_uni_feed(h, u, tmp, (size_t)n);

				if (ret) {
					/* 控制流违规：按 §6.2.1 关连接 */
					kdg_qc_close(&h->qc,
						     (u64)(-ret), true);
					break;
				}
			} else {
				int ret = kdg_h3_feed(h, &r->fp, r, tmp, (size_t)n, fin);

				if (ret) {
					r->state = H3R_FAILED;
					r->err = ret;
					kdg_qc_close(&h->qc, (u64)(-ret), true);
					break;
				}
			}
			if (fin)
				break;
		}
		if (n < 0 && r) {
			r->state = H3R_FAILED;
			r->err = (int)n;
		}
	}
}

size_t kdg_h3_send(struct kdg_h3 *h, u8 *out, size_t cap, u64 now)
{
	size_t n;

	h3_maybe_open_control(h);
	n = kdg_qc_send(&h->qc, out, cap, now);
	h3_pump_streams(h);
	return n;
}

int kdg_h3_recv(struct kdg_h3 *h, u8 *dgram, size_t len, u64 now)
{
	int ret = kdg_qc_recv(&h->qc, dgram, len, now);

	h3_maybe_open_control(h);
	h3_pump_streams(h);
	return ret;
}

void kdg_h3_timeout(struct kdg_h3 *h, u64 now)
{
	kdg_qc_timeout(&h->qc, now);
}

u64 kdg_h3_next_timer(const struct kdg_h3 *h)
{
	return kdg_qc_next_timer(&h->qc);
}
