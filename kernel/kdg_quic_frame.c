// SPDX-License-Identifier: GPL-2.0
/*
 * kdg_quic_frame.c —— QUIC varint / 帧 / 传输参数编解码，双态可编译。
 */
#include "kdg_quic_frame.h"

#ifndef __KERNEL__
#include <errno.h>
#endif

u64 kdg_qv_get(struct kdg_qrd *r)
{
	size_t len, i;
	u64 v;

	if (r->bad || !r->n) {
		r->bad = true;
		return 0;
	}
	len = (size_t)1 << (r->p[0] >> 6);
	if (r->n < len) {
		r->bad = true;
		return 0;
	}
	v = r->p[0] & 0x3f;
	for (i = 1; i < len; i++)
		v = v << 8 | r->p[i];
	r->p += len;
	r->n -= len;
	return v;
}

const u8 *kdg_qrd_take(struct kdg_qrd *r, size_t len)
{
	const u8 *p;

	if (r->bad || r->n < len) {
		r->bad = true;
		return NULL;
	}
	p = r->p;
	r->p += len;
	r->n -= len;
	return p;
}

size_t kdg_qv_len(u64 v)
{
	return v < 64 ? 1 : v < 16384 ? 2 : v < (1U << 30) ? 4 : 8;
}

size_t kdg_qv_put(u8 *p, size_t cap, u64 v)
{
	size_t len = kdg_qv_len(v), i;

	if (v > KDG_QV_MAX || cap < len)
		return 0;
	for (i = 0; i < len; i++)
		p[len - 1 - i] = (u8)(v >> (8 * i));
	p[0] |= (u8)((len == 1 ? 0 : len == 2 ? 1 : len == 4 ? 2 : 3) << 6);
	return len;
}

void kdg_qv_put2(u8 *p, u64 v)
{
	p[0] = 0x40 | (u8)((v >> 8) & 0x3f);
	p[1] = (u8)v;
}

int kdg_qframe_next(struct kdg_qrd *r, struct kdg_qframe *f)
{
	u64 len;

	/* 连续 PADDING 一次吞掉：Initial 包里常有上千字节填充 */
	while (r->n && r->p[0] == QF_PADDING) {
		r->p++;
		r->n--;
	}
	if (!r->n)
		return -EAGAIN;

	memset(f, 0, sizeof(*f));
	f->type = kdg_qv_get(r);
	switch (f->type) {
	case QF_PING:
	case QF_HANDSHAKE_DONE:
		break;
	case QF_ACK:
	case QF_ACK_ECN:
		f->u.ack.largest = kdg_qv_get(r);
		f->u.ack.delay = kdg_qv_get(r);
		f->u.ack.range_count = kdg_qv_get(r);
		f->u.ack.first_range = kdg_qv_get(r);
		if (f->u.ack.first_range > f->u.ack.largest)
			return -EBADMSG;
		f->u.ack.ranges = r->p;
		{
			u64 i;

			/* 先整体跳过以界定长度；区间语义由迭代器再读 */
			for (i = 0; i < f->u.ack.range_count && !r->bad; i++) {
				kdg_qv_get(r);
				kdg_qv_get(r);
			}
		}
		f->u.ack.ranges_len = r->p - f->u.ack.ranges;
		if (f->type == QF_ACK_ECN) {
			kdg_qv_get(r);
			kdg_qv_get(r);
			kdg_qv_get(r);
		}
		break;
	case QF_RESET_STREAM:
		f->u.reset.id = kdg_qv_get(r);
		f->u.reset.err = kdg_qv_get(r);
		f->u.reset.final_size = kdg_qv_get(r);
		break;
	case QF_STOP_SENDING:
		f->u.reset.id = kdg_qv_get(r);
		f->u.reset.err = kdg_qv_get(r);
		break;
	case QF_CRYPTO:
		f->u.crypto.off = kdg_qv_get(r);
		len = kdg_qv_get(r);
		if (len > r->n)
			return -EBADMSG;
		f->u.crypto.len = (size_t)len;
		f->u.crypto.data = kdg_qrd_take(r, f->u.crypto.len);
		if (f->u.crypto.off + len > KDG_QV_MAX)
			return -EBADMSG;
		break;
	case QF_NEW_TOKEN:
		len = kdg_qv_get(r);
		if (!len || len > r->n)
			return -EBADMSG;
		f->u.token.len = (size_t)len;
		f->u.token.tok = kdg_qrd_take(r, f->u.token.len);
		break;
	case QF_MAX_DATA:
	case QF_MAX_STREAMS_BIDI:
	case QF_MAX_STREAMS_UNI:
	case QF_DATA_BLOCKED:
	case QF_STREAMS_BLOCKED_BIDI:
	case QF_STREAMS_BLOCKED_UNI:
	case QF_RETIRE_CONNECTION_ID:
		f->u.max.max = kdg_qv_get(r);
		break;
	case QF_MAX_STREAM_DATA:
	case QF_STREAM_DATA_BLOCKED:
		f->u.max.id = kdg_qv_get(r);
		f->u.max.max = kdg_qv_get(r);
		break;
	case QF_NEW_CONNECTION_ID:
		f->u.ncid.seq = kdg_qv_get(r);
		f->u.ncid.retire_prior = kdg_qv_get(r);
		{
			const u8 *l = kdg_qrd_take(r, 1);

			if (!l || *l < 1 || *l > 20)
				return -EBADMSG;
			f->u.ncid.cid_len = *l;
		}
		f->u.ncid.cid = kdg_qrd_take(r, f->u.ncid.cid_len);
		f->u.ncid.token = kdg_qrd_take(r, 16);
		if (f->u.ncid.retire_prior > f->u.ncid.seq)
			return -EBADMSG;
		break;
	case QF_PATH_CHALLENGE:
	case QF_PATH_RESPONSE:
		f->u.path.data = kdg_qrd_take(r, 8);
		break;
	case QF_CONN_CLOSE:
	case QF_CONN_CLOSE_APP:
		f->u.close.err = kdg_qv_get(r);
		if (f->type == QF_CONN_CLOSE)
			f->u.close.frame_type = kdg_qv_get(r);
		len = kdg_qv_get(r);
		if (len > r->n)
			return -EBADMSG;
		f->u.close.rlen = (size_t)len;
		f->u.close.reason = kdg_qrd_take(r, f->u.close.rlen);
		break;
	default:
		if (f->type >= QF_STREAM && f->type <= QF_STREAM + 7) {
			bool has_off = f->type & 0x04, has_len = f->type & 0x02;

			f->u.stream.fin = f->type & 0x01;
			f->u.stream.id = kdg_qv_get(r);
			f->u.stream.off = has_off ? kdg_qv_get(r) : 0;
			len = has_len ? kdg_qv_get(r) : r->n;	/* 无 LEN 位：延伸到包尾 */
			if (r->bad || len > r->n)
				return -EBADMSG;
			f->u.stream.len = (size_t)len;
			f->u.stream.data = kdg_qrd_take(r, f->u.stream.len);
			if (f->u.stream.off + len > KDG_QV_MAX)
				return -EBADMSG;
			f->type = QF_STREAM;	/* 调用方只按 QF_STREAM 分派 */
			break;
		}
		return -EPROTO;	/* 未知帧类型：§12.4 要求 FRAME_ENCODING_ERROR */
	}
	return r->bad ? -EBADMSG : 0;
}

void kdg_qack_begin(struct kdg_qack_it *it, const struct kdg_qframe *f)
{
	it->r.p = f->u.ack.ranges;
	it->r.n = f->u.ack.ranges_len;
	it->r.bad = false;
	it->next_hi = f->u.ack.largest;
	it->left = f->u.ack.range_count;
	it->first = true;
	it->first_range = f->u.ack.first_range;
}

/* §19.3.1：首区间 [largest-first_range, largest]；之后每组 (gap, range)：
 * hi = 上个 lo - gap - 2，lo = hi - range。下溢即编码错误。 */
int kdg_qack_next(struct kdg_qack_it *it, u64 *lo, u64 *hi)
{
	u64 gap, range;

	if (it->first) {
		it->first = false;
		*hi = it->next_hi;
		*lo = *hi - it->first_range;	/* 解析时已保证不下溢 */
		it->next_hi = *lo;
		return 0;
	}
	if (!it->left)
		return -EAGAIN;
	it->left--;
	gap = kdg_qv_get(&it->r);
	range = kdg_qv_get(&it->r);
	if (it->r.bad || it->next_hi < gap + 2)
		return -EBADMSG;
	*hi = it->next_hi - gap - 2;
	if (*hi < range)
		return -EBADMSG;
	*lo = *hi - range;
	it->next_hi = *lo;
	return 0;
}

/* ── 传输参数（§18） ──────────────────────────────────────────────── */
#define TP_ORIG_DCID		0x00
#define TP_IDLE			0x01
#define TP_RESET_TOKEN		0x02
#define TP_MAX_UDP		0x03
#define TP_MAX_DATA		0x04
#define TP_SD_BIDI_LOCAL	0x05
#define TP_SD_BIDI_REMOTE	0x06
#define TP_SD_UNI		0x07
#define TP_STREAMS_BIDI		0x08
#define TP_STREAMS_UNI		0x09
#define TP_ACK_EXP		0x0a
#define TP_MAX_ACK_DELAY	0x0b
#define TP_DISABLE_MIG		0x0c
#define TP_PREF_ADDR		0x0d
#define TP_CID_LIMIT		0x0e
#define TP_INIT_SCID		0x0f
#define TP_RETRY_SCID		0x10

void kdg_qtp_defaults(struct kdg_qtp *tp)
{
	memset(tp, 0, sizeof(*tp));
	tp->max_udp_payload = 65527;
	tp->ack_delay_exponent = 3;
	tp->max_ack_delay = 25;
	tp->active_cid_limit = 2;
}

int kdg_qtp_parse(const u8 *p, size_t n, struct kdg_qtp *tp)
{
	struct kdg_qrd r = { .p = p, .n = n };
	u64 seen = 0;

	kdg_qtp_defaults(tp);
	while (r.n && !r.bad) {
		u64 id = kdg_qv_get(&r), len = kdg_qv_get(&r);
		struct kdg_qrd v;

		if (r.bad || len > r.n)
			return -EBADMSG;
		v.p = kdg_qrd_take(&r, (size_t)len);
		v.n = (size_t)len;
		v.bad = false;
		/* §7.4：同一参数出现两次是 TRANSPORT_PARAMETER_ERROR */
		if (id < 64) {
			if (seen & (1ULL << id))
				return -EBADMSG;
			seen |= 1ULL << id;
		}

#define TP_INT(field)	do { tp->field = kdg_qv_get(&v); \
			     if (v.bad || v.n) return -EBADMSG; } while (0)
		switch (id) {
		case TP_IDLE:		TP_INT(max_idle_timeout); break;
		case TP_MAX_UDP:	TP_INT(max_udp_payload);
			if (tp->max_udp_payload < 1200)
				return -EBADMSG;
			break;
		case TP_MAX_DATA:	TP_INT(initial_max_data); break;
		case TP_SD_BIDI_LOCAL:	TP_INT(initial_max_stream_data_bidi_local); break;
		case TP_SD_BIDI_REMOTE:	TP_INT(initial_max_stream_data_bidi_remote); break;
		case TP_SD_UNI:		TP_INT(initial_max_stream_data_uni); break;
		case TP_STREAMS_BIDI:	TP_INT(initial_max_streams_bidi);
			if (tp->initial_max_streams_bidi > (1ULL << 60))
				return -EBADMSG;
			break;
		case TP_STREAMS_UNI:	TP_INT(initial_max_streams_uni);
			if (tp->initial_max_streams_uni > (1ULL << 60))
				return -EBADMSG;
			break;
		case TP_ACK_EXP:	TP_INT(ack_delay_exponent);
			if (tp->ack_delay_exponent > 20)
				return -EBADMSG;
			break;
		case TP_MAX_ACK_DELAY:	TP_INT(max_ack_delay);
			if (tp->max_ack_delay >= (1 << 14))
				return -EBADMSG;
			break;
		case TP_CID_LIMIT:	TP_INT(active_cid_limit);
			if (tp->active_cid_limit < 2)
				return -EBADMSG;
			break;
		case TP_ORIG_DCID:
			if (len > 20)
				return -EBADMSG;
			memcpy(tp->orig_dcid, v.p, (size_t)len);
			tp->orig_dcid_len = (u8)len;
			tp->has_orig_dcid = true;
			break;
		case TP_INIT_SCID:
			if (len > 20)
				return -EBADMSG;
			memcpy(tp->init_scid, v.p, (size_t)len);
			tp->init_scid_len = (u8)len;
			tp->has_init_scid = true;
			break;
		case TP_RETRY_SCID:
			tp->has_retry_scid = true;
			break;
		case TP_RESET_TOKEN:
			if (len != 16)
				return -EBADMSG;
			break;
		default:	/* 含 disable_active_migration、preferred_address 与未知参数：忽略 */
			break;
		}
#undef TP_INT
	}
	if (r.bad)
		return -EBADMSG;
	/* §7.3：服务器必须给 original_destination_connection_id 与
	 * initial_source_connection_id，否则是协议错误 */
	if (!tp->has_orig_dcid || !tp->has_init_scid)
		return -EBADMSG;
	return 0;
}

static size_t tp_put_int(u8 *out, size_t cap, u64 id, u64 v)
{
	size_t n = kdg_qv_put(out, cap, id), m;

	if (!n)
		return 0;
	m = kdg_qv_put(out + n, cap - n, kdg_qv_len(v));
	if (!m)
		return 0;
	if (!kdg_qv_put(out + n + m, cap - n - m, v))
		return 0;
	return n + m + kdg_qv_len(v);
}

int kdg_qtp_encode_client(const struct kdg_qtp *tp, const u8 *scid,
			  size_t scid_len, u8 *out, size_t cap)
{
	const struct { u64 id, v; } ints[] = {
		{ TP_IDLE, tp->max_idle_timeout },
		{ TP_MAX_UDP, tp->max_udp_payload },
		{ TP_MAX_DATA, tp->initial_max_data },
		{ TP_SD_BIDI_LOCAL, tp->initial_max_stream_data_bidi_local },
		{ TP_SD_BIDI_REMOTE, tp->initial_max_stream_data_bidi_remote },
		{ TP_SD_UNI, tp->initial_max_stream_data_uni },
		{ TP_STREAMS_BIDI, tp->initial_max_streams_bidi },
		{ TP_STREAMS_UNI, tp->initial_max_streams_uni },
		{ TP_CID_LIMIT, tp->active_cid_limit },
	};
	size_t n = 0, i, w;

	for (i = 0; i < ARRAY_SIZE(ints); i++) {
		w = tp_put_int(out + n, cap - n, ints[i].id, ints[i].v);
		if (!w)
			return -ENOSPC;
		n += w;
	}
	/* 客户端只发 initial_source_connection_id（§7.3），不发 orig_dcid */
	if (cap - n < 2 + scid_len || scid_len > 20)
		return -ENOSPC;
	out[n++] = TP_INIT_SCID;
	out[n++] = (u8)scid_len;
	memcpy(out + n, scid, scid_len);
	n += scid_len;
	/* 不发 disable_active_migration：§18.2 规定它只能由服务器发送。
	 * 客户端本就不迁移 —— 换网时由连接池整体重建连接。 */
	return (int)n;
}