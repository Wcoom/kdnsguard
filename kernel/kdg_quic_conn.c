// SPDX-License-Identifier: GPL-2.0
/*
 * kdg_quic_conn.c —— QUIC v1 客户端连接状态机，双态可编译。设计见头文件。
 */
#include "kdg_quic_conn.h"

#ifdef __KERNEL__
#include <linux/slab.h>
#include <linux/mm.h>
#define qc_alloc(n)	kvzalloc((n), GFP_KERNEL)
#define qc_free(p)	kvfree(p)
#else
#include <errno.h>
#include <stdlib.h>
#define qc_alloc(n)	calloc(1, (n))
#define qc_free(p)	free(p)
#endif

#define QC_INIT_CWND	(10 * KDG_QC_MTU)	/* RFC 9002 §7.2 */
#define QC_MIN_CWND	(2 * KDG_QC_MTU)
#define QC_INIT_RTT	333			/* §6.2.2 kInitialRtt */
#define QC_GRANULARITY	1
#define QC_PKT_THRESH	3

/* 固定宽度读取（与 varint 无关），越界置 bad。 */
static u32 rd_bytes(struct kdg_qrd *r, size_t w)
{
	u32 v = 0;
	size_t i;

	if (r->bad || r->n < w) {
		r->bad = true;
		return 0;
	}
	for (i = 0; i < w; i++)
		v = v << 8 | r->p[i];
	r->p += w;
	r->n -= w;
	return v;
}

static enum kdg_tls13_level sp2lvl(enum kdg_qc_space s)
{
	return s == QS_INITIAL ? KDG_LVL_INITIAL :
	       s == QS_HANDSHAKE ? KDG_LVL_HANDSHAKE : KDG_LVL_APP;
}

static void qc_fail(struct kdg_qc *c, u64 err)
{
	if (c->state >= QC_CLOSING)
		return;
	c->err = err;
	c->err_app = false;
	c->state = QC_CLOSING;
	c->send_close = true;
	/* §10.2：关闭态维持 3·PTO 后彻底释放 */
	c->close_deadline = c->now + 3 * (c->have_rtt ? c->srtt + 4 * c->rttvar : 3 * QC_INIT_RTT);
}

/* 记录一个收到的包号到降序区间表。表满时丢掉最老（最小）的区间：
 * 这只会让对端多重传几次旧包，不影响正确性。 */
static void qc_rx_record(struct kdg_qc_pnspace *sp, u64 pn)
{
	unsigned int i, j;

	for (i = 0; i < sp->n_rx_ranges; i++) {
		if (pn >= sp->rx_ranges[i].lo && pn <= sp->rx_ranges[i].hi)
			return;
		if (pn == sp->rx_ranges[i].hi + 1) {
			sp->rx_ranges[i].hi = pn;
			/* 与前一个（更大的）区间相接则合并 */
			if (i > 0 && sp->rx_ranges[i - 1].lo == pn + 1) {
				sp->rx_ranges[i - 1].lo = sp->rx_ranges[i].lo;
				for (j = i; j + 1 < sp->n_rx_ranges; j++)
					sp->rx_ranges[j] = sp->rx_ranges[j + 1];
				sp->n_rx_ranges--;
			}
			return;
		}
		if (pn + 1 == sp->rx_ranges[i].lo) {
			sp->rx_ranges[i].lo = pn;
			if (i + 1 < sp->n_rx_ranges &&
			    sp->rx_ranges[i + 1].hi + 1 == pn) {
				sp->rx_ranges[i].lo = sp->rx_ranges[i + 1].lo;
				for (j = i + 1; j + 1 < sp->n_rx_ranges; j++)
					sp->rx_ranges[j] = sp->rx_ranges[j + 1];
				sp->n_rx_ranges--;
			}
			return;
		}
		if (pn > sp->rx_ranges[i].hi)
			break;	/* 插在 i 之前 */
	}
	if (sp->n_rx_ranges == KDG_QC_RX_RANGES) {
		if (i == KDG_QC_RX_RANGES)
			return;	/* 比所有记录都旧：不记 */
		sp->n_rx_ranges--;
	}
	for (j = sp->n_rx_ranges; j > i; j--)
		sp->rx_ranges[j] = sp->rx_ranges[j - 1];
	sp->rx_ranges[i].lo = pn;
	sp->rx_ranges[i].hi = pn;
	sp->n_rx_ranges++;
}

static bool qc_rx_seen(const struct kdg_qc_pnspace *sp, u64 pn)
{
	unsigned int i;

	for (i = 0; i < sp->n_rx_ranges; i++)
		if (pn >= sp->rx_ranges[i].lo && pn <= sp->rx_ranges[i].hi)
			return true;
	return false;
}

/* ── 流表 ───────────────────────────────────────────────────────────── */
static struct kdg_qc_stream *qc_stream_find(struct kdg_qc *c, u64 id)
{
	unsigned int i;

	for (i = 0; i < KDG_QC_MAX_STREAMS; i++)
		if (c->st[i].used && c->st[i].id == id)
			return &c->st[i];
	return NULL;
}

static struct kdg_qc_stream *qc_stream_new(struct kdg_qc *c, u64 id)
{
	unsigned int i;
	struct kdg_qc_stream *s;
	bool local = (id & 1) == 0, bidi = (id & 2) == 0;

	for (i = 0; i < KDG_QC_MAX_STREAMS; i++)
		if (!c->st[i].used)
			break;
	if (i == KDG_QC_MAX_STREAMS)
		return NULL;
	s = &c->st[i];
	memset(s, 0, sizeof(*s));
	/* 本端单向流只发、对端单向流只收、双向流两者都要 */
	if (local || bidi) {
		s->sbuf = qc_alloc(KDG_QC_STREAM_BUF);
		if (!s->sbuf)
			return NULL;
		s->s_max = !bidi ? c->peer.initial_max_stream_data_uni :
			   c->peer.initial_max_stream_data_bidi_remote;
	}
	if (!local || bidi) {
		s->rcap = KDG_QC_STREAM_BUF;
		s->rbuf = qc_alloc(s->rcap);
		s->rmap = qc_alloc(s->rcap / 8 + 1);
		if (!s->rbuf || !s->rmap) {
			qc_free(s->sbuf);
			qc_free(s->rbuf);
			qc_free(s->rmap);
			memset(s, 0, sizeof(*s));
			return NULL;
		}
		s->r_max = bidi ? c->local.initial_max_stream_data_bidi_local :
			   c->local.initial_max_stream_data_uni;
		if (s->r_max > s->rcap)
			s->r_max = s->rcap;
	}
	s->r_final = ~0ULL;
	s->id = id;
	s->used = true;
	return s;
}

void kdg_qc_stream_free(struct kdg_qc *c, u64 id)
{
	struct kdg_qc_stream *s = qc_stream_find(c, id);

	if (!s)
		return;
	qc_free(s->sbuf);
	qc_free(s->rbuf);
	qc_free(s->rmap);
	memset(s, 0, sizeof(*s));
}

static void qc_space_init(struct kdg_qc_pnspace *sp)
{
	sp->largest_rx = -1;
	sp->largest_acked = -1;
}

/* 把 TLS 引擎新产生的握手字节挪进对应空间的 CRYPTO 发送缓冲。 */
static int qc_pull_tls(struct kdg_qc *c)
{
	int s;

	for (s = 0; s < QS_COUNT; s++) {
		struct kdg_qc_pnspace *sp = &c->sp[s];
		enum kdg_tls13_level l = sp2lvl(s);
		size_t n = c->tls.tx_len[l];

		if (!n)
			continue;
		if (KDG_QC_CRYPTO_BUF - sp->c_len < n)
			return -ENOSPC;
		memcpy(sp->cbuf + sp->c_len, c->tls.tx[l], n);
		sp->c_len += n;
		c->tls.tx_len[l] = 0;
	}
	return 0;
}

int kdg_qc_init(struct kdg_qc *c, const char *host, const char *alpn,
		const struct kdg_qtp *tp, const mbedtls_x509_crt *ca,
		kdg_rng_fn rng, void *rng_ctx, u64 now)
{
	u8 tpbuf[KDG_T13_TP_MAX];
	int n, ret, s;

	memset(c, 0, sizeof(*c));
	c->now = now;
	for (s = 0; s < QS_COUNT; s++)
		qc_space_init(&c->sp[s]);
	c->local = *tp;

	/* §7.2：客户端首个 DCID 至少 8 字节、不可预测 */
	if (rng(rng_ctx, c->scid, sizeof(c->scid)) ||
	    rng(rng_ctx, c->odcid, 8))
		return -EIO;
	c->odcid_len = 8;
	memcpy(c->dcid, c->odcid, 8);
	c->dcid_len = 8;

	ret = kdg_quic_initial_keys(c->odcid, 8, &c->sp[QS_INITIAL].tx,
				    &c->sp[QS_INITIAL].rx);
	if (ret)
		return ret;

	n = kdg_qtp_encode_client(tp, c->scid, sizeof(c->scid), tpbuf,
				  sizeof(tpbuf));
	if (n < 0)
		goto fail_keys;
	ret = kdg_tls13_init(&c->tls, host, alpn, tpbuf, n, ca, rng, rng_ctx);
	if (ret)
		goto fail_keys;
	ret = kdg_tls13_start(&c->tls);
	if (!ret)
		ret = qc_pull_tls(c);
	if (ret) {
		kdg_tls13_fini(&c->tls);
		goto fail_keys;
	}

	c->max_data_rx = tp->initial_max_data;
	c->cwnd = QC_INIT_CWND;
	c->ssthresh = ~0ULL;
	c->srtt = QC_INIT_RTT;
	c->rttvar = QC_INIT_RTT / 2;
	c->min_rtt = ~0ULL;
	/* 握手期空闲超时用本端值；拿到对端参数后取两者较小（§10.1） */
	c->idle_deadline = now + (tp->max_idle_timeout ? tp->max_idle_timeout : 30000);
	c->state = QC_HANDSHAKING;
	return 0;

fail_keys:
	kdg_quic_keys_free(&c->sp[QS_INITIAL].tx);
	kdg_quic_keys_free(&c->sp[QS_INITIAL].rx);
	return ret ? ret : -EINVAL;
}

void kdg_qc_fini(struct kdg_qc *c)
{
	unsigned int i;
	int s;

	for (i = 0; i < KDG_QC_MAX_STREAMS; i++)
		if (c->st[i].used)
			kdg_qc_stream_free(c, c->st[i].id);
	for (s = 0; s < QS_COUNT; s++) {
		kdg_quic_keys_free(&c->sp[s].tx);
		kdg_quic_keys_free(&c->sp[s].rx);
	}
	kdg_tls13_fini(&c->tls);
}

void kdg_qc_close(struct kdg_qc *c, u64 err, bool app)
{
	qc_fail(c, err);
	c->err_app = app;
}

/* 丢弃一个包号空间的密钥与在途记录（§4.9：拿到 Handshake 密钥后丢 Initial，
 * 握手确认后丢 Handshake）。被丢空间的在途字节必须从 bytes_in_flight 扣除。 */
static void qc_discard_space(struct kdg_qc *c, enum kdg_qc_space s)
{
	struct kdg_qc_pnspace *sp = &c->sp[s];
	unsigned int i;

	if (sp->discarded)
		return;
	for (i = 0; i < KDG_QC_SENT_MAX; i++) {
		if (sp->sent[i].in_use && sp->sent[i].in_flight)
			c->bytes_in_flight -= sp->sent[i].bytes;
		sp->sent[i].in_use = false;
	}
	kdg_quic_keys_free(&sp->tx);
	kdg_quic_keys_free(&sp->rx);
	sp->loss_time = 0;
	sp->ack_pending = false;
	sp->discarded = true;
	c->pto_count = 0;
}

/* ── RTT 与拥塞（RFC 9002 §5 / §7） ─────────────────────────────────── */
static void qc_rtt_update(struct kdg_qc *c, u64 sample, u64 ack_delay)
{
	if (sample < c->min_rtt)
		c->min_rtt = sample;
	/* ack_delay 不可把样本压到 min_rtt 以下（§5.3） */
	if (sample >= c->min_rtt + ack_delay)
		sample -= ack_delay;
	c->latest_rtt = sample;
	if (!c->have_rtt) {
		c->srtt = sample;
		c->rttvar = sample / 2;
		c->have_rtt = true;
		return;
	}
	c->rttvar = (3 * c->rttvar + (c->srtt > sample ? c->srtt - sample :
							  sample - c->srtt)) / 4;
	c->srtt = (7 * c->srtt + sample) / 8;
}

static u64 qc_pto(const struct kdg_qc *c, enum kdg_qc_space s)
{
	u64 var = 4 * c->rttvar;
	u64 pto = c->srtt + (var > QC_GRANULARITY ? var : QC_GRANULARITY);

	if (s == QS_APP)
		pto += c->peer_tp_ok ? c->peer.max_ack_delay : 25;
	return pto << (c->pto_count > 10 ? 10 : c->pto_count);
}

/* 一个包判定为丢失：标记其内容待重发，扣在途字节，进入拥塞恢复。 */
static void qc_on_lost(struct kdg_qc *c, enum kdg_qc_space s,
		       struct kdg_qc_sent *p)
{
	struct kdg_qc_pnspace *sp = &c->sp[s];
	unsigned int i;

	if (p->has_crypto && (!sp->c_lost || p->crypto_off < sp->c_lost_off)) {
		sp->c_lost = true;
		sp->c_lost_off = p->crypto_off;
	}
	for (i = 0; i < p->nstreams; i++) {
		struct kdg_qc_stream *st = &c->st[p->st[i].slot];

		if (!st->used || p->st[i].off + p->st[i].len <= st->s_acked)
			continue;
		if (!st->s_lost || p->st[i].off < st->s_lost_off) {
			st->s_lost = true;
			st->s_lost_off = p->st[i].off;
		}
		if (p->st[i].fin)
			st->s_fin_sent = false;
	}
	if (p->has_max_data)
		c->send_max_data = true;
	if (p->in_flight) {
		c->bytes_in_flight -= p->bytes;
		/* NewReno：一个恢复期内只减一次窗口 */
		if (p->t_ms > c->recovery_start) {
			c->recovery_start = c->now;
			c->cwnd /= 2;
			if (c->cwnd < QC_MIN_CWND)
				c->cwnd = QC_MIN_CWND;
			c->ssthresh = c->cwnd;
		}
	}
	p->in_use = false;
}

static void qc_on_acked(struct kdg_qc *c, struct kdg_qc_sent *p)
{
	unsigned int i;

	for (i = 0; i < p->nstreams; i++) {
		struct kdg_qc_stream *st = &c->st[p->st[i].slot];
		u64 end = p->st[i].off + p->st[i].len;

		if (!st->used)
			continue;
		if (p->st[i].off <= st->s_acked && end > st->s_acked)
			st->s_acked = end;
		if (p->st[i].fin && st->s_acked >= st->slen)
			st->s_fin_acked = true;
	}
	if (p->in_flight) {
		c->bytes_in_flight -= p->bytes;
		if (p->t_ms > c->recovery_start) {
			if (c->cwnd < c->ssthresh)
				c->cwnd += p->bytes;		/* 慢启动 */
			else
				c->cwnd += (u64)KDG_QC_MTU * p->bytes / c->cwnd;
		}
	}
	p->in_use = false;
}

/* §6.1：包号阈值 3 或时间阈值 9/8·max(srtt, latest_rtt)。 */
static void qc_detect_loss(struct kdg_qc *c, enum kdg_qc_space s)
{
	struct kdg_qc_pnspace *sp = &c->sp[s];
	u64 rtt = c->srtt > c->latest_rtt ? c->srtt : c->latest_rtt;
	u64 delay = rtt * 9 / 8, lost_before;
	unsigned int i;

	if (delay < QC_GRANULARITY)
		delay = QC_GRANULARITY;
	lost_before = c->now > delay ? c->now - delay : 0;
	sp->loss_time = 0;
	if (sp->largest_acked < 0)
		return;
	for (i = 0; i < KDG_QC_SENT_MAX; i++) {
		struct kdg_qc_sent *p = &sp->sent[i];

		if (!p->in_use || (s64)p->pn > sp->largest_acked)
			continue;
		if (p->t_ms <= lost_before ||
		    sp->largest_acked >= (s64)(p->pn + QC_PKT_THRESH)) {
			qc_on_lost(c, s, p);
		} else {
			u64 t = p->t_ms + delay;

			if (!sp->loss_time || t < sp->loss_time)
				sp->loss_time = t;
		}
	}
}

static int qc_on_ack_frame(struct kdg_qc *c, enum kdg_qc_space s,
			   const struct kdg_qframe *f)
{
	struct kdg_qc_pnspace *sp = &c->sp[s];
	struct kdg_qack_it it;
	struct kdg_qc_sent *newest = NULL;
	u64 lo, hi;
	unsigned int i;
	int ret;

	/* §13.1：确认一个从未发过的包号是 PROTOCOL_VIOLATION */
	if (f->u.ack.largest >= sp->next_pn)
		return -EPROTO;
	kdg_qack_begin(&it, f);
	while ((ret = kdg_qack_next(&it, &lo, &hi)) == 0) {
		for (i = 0; i < KDG_QC_SENT_MAX; i++) {
			struct kdg_qc_sent *p = &sp->sent[i];

			if (!p->in_use || p->pn < lo || p->pn > hi)
				continue;
			if (p->pn == f->u.ack.largest && p->ack_eliciting)
				newest = p;
			else
				qc_on_acked(c, p);
		}
	}
	if (ret != -EAGAIN)
		return ret;

	if ((s64)f->u.ack.largest > sp->largest_acked)
		sp->largest_acked = (s64)f->u.ack.largest;
	/* §5.1：只有「新确认了最大包号且它是 ack-eliciting」才产生 RTT 样本 */
	if (newest) {
		u64 delay = 0;

		if (s == QS_APP) {
			u64 exp = c->peer_tp_ok ? c->peer.ack_delay_exponent : 3;
			u64 cap = c->peer_tp_ok ? c->peer.max_ack_delay : 25;

			/* ack_delay 单位是 2^exp 微秒；本模块计时用毫秒 */
			delay = exp < 40 ? (f->u.ack.delay << exp) / 1000 : 0;
			if (c->hs_confirmed && delay > cap)
				delay = cap;
		}
		if (c->now >= newest->t_ms)
			qc_rtt_update(c, c->now - newest->t_ms, delay);
		qc_on_acked(c, newest);
	}
	qc_detect_loss(c, s);
	c->pto_count = 0;
	return 0;
}

static int qc_on_crypto(struct kdg_qc *c, enum kdg_qc_space s,
			const struct kdg_qframe *f)
{
	struct kdg_qc_pnspace *sp = &c->sp[s];
	u64 off = f->u.crypto.off, end, n;
	size_t rel, i, contig;
	int ret;

	if (off + f->u.crypto.len <= sp->c_rx)
		return 0;			/* 已交过的前缀：忽略 */
	if (off >= sp->c_rx + KDG_T13_RXBUF)
		return 0;			/* 超出窗口：丢，对端会重传 */
	{
		/* 与已交付部分重叠时裁掉前缀；超出窗口的尾巴截断 */
		size_t skip = off < sp->c_rx ? (size_t)(sp->c_rx - off) : 0;

		off += skip;
		rel = (size_t)(off - sp->c_rx);
		n = f->u.crypto.len - skip;
		if (rel + n > KDG_T13_RXBUF)
			n = KDG_T13_RXBUF - rel;
		memcpy(sp->crx + rel, f->u.crypto.data + skip, (size_t)n);
		memset(sp->crx_map + rel, 1, (size_t)n);
	}
	end = sp->c_rx;
	for (i = 0; i < KDG_T13_RXBUF && sp->crx_map[i]; i++)
		end++;
	contig = (size_t)(end - sp->c_rx);
	if (!contig)
		return 0;
	ret = kdg_tls13_recv(&c->tls, sp2lvl(s), sp->crx, contig);
	if (ret)
		return ret;
	memmove(sp->crx, sp->crx + contig, KDG_T13_RXBUF - contig);
	memmove(sp->crx_map, sp->crx_map + contig, KDG_T13_RXBUF - contig);
	memset(sp->crx + KDG_T13_RXBUF - contig, 0, contig);
	memset(sp->crx_map + KDG_T13_RXBUF - contig, 0, contig);
	sp->c_rx += contig;
	return qc_pull_tls(c);
}

/* 收到对端流帧时取得流对象。本端发起的流必须已存在；对端只允许开单向流
 * （HTTP/3 的控制/QPACK 流），且不超过本端给的 initial_max_streams_uni。 */
static struct kdg_qc_stream *qc_stream_for_rx(struct kdg_qc *c, u64 id, u64 *err)
{
	struct kdg_qc_stream *s = qc_stream_find(c, id);

	if (s)
		return s;
	if ((id & 1) == 0) {
		/* 本端发起：要么已关闭（迟到的帧，忽略），要么从未开过（违规） */
		u64 next = (id & 2) ? c->next_uni : c->next_bidi;

		*err = (id >> 2) >= next ? QE_STREAM_STATE : 0;
		return NULL;
	}
	if ((id & 2) == 0) {		/* 对端双向流：DoH 客户端不接受 */
		*err = QE_STREAM_LIMIT;
		return NULL;
	}
	if ((id >> 2) >= c->local.initial_max_streams_uni) {
		*err = QE_STREAM_LIMIT;
		return NULL;
	}
	if ((id >> 2) < c->peer_uni_seen) {
		*err = 0;		/* 已关闭的旧流 */
		return NULL;
	}
	c->peer_uni_seen = (id >> 2) + 1;
	s = qc_stream_new(c, id);
	if (!s)
		*err = QE_INTERNAL;
	return s;
}

static int qc_on_stream(struct kdg_qc *c, const struct kdg_qframe *f)
{
	u64 id = f->u.stream.id, off = f->u.stream.off, end, err = 0,
	    i, newly = 0;
	struct kdg_qc_stream *s;

	if ((id & 3) == 2)		/* 本端单向流：对端不得在上面发数据 */
		return -(int)QE_STREAM_STATE;
	s = qc_stream_for_rx(c, id, &err);
	if (!s)
		return err ? -(int)err : 0;
	if (s->r_reset)
		return 0;
	end = off + f->u.stream.len;
	/* §4.5：最终长度一经确定不可改变，数据不得越过它 */
	if (s->r_final != ~0ULL && end > s->r_final)
		return -(int)QE_FINAL_SIZE;
	if (f->u.stream.fin) {
		if (s->r_final != ~0ULL && s->r_final != end)
			return -(int)QE_FINAL_SIZE;
		if (end < s->r_contig)
			return -(int)QE_FINAL_SIZE;
		s->r_final = end;
	}
	if (end > s->r_max)
		return -(int)QE_FLOW_CONTROL;
	/* 连接级流控按「新出现的最高偏移」计 */
	for (i = off; i < end; i++)
		if (!(s->rmap[i / 8] & (1u << (i % 8))))
			newly++;
	if (c->data_rx + newly > c->max_data_rx)
		return -(int)QE_FLOW_CONTROL;
	c->data_rx += newly;
	for (i = off; i < end; i++) {
		s->rbuf[i] = f->u.stream.data[i - off];
		s->rmap[i / 8] |= 1u << (i % 8);
	}
	while (s->r_contig < s->rcap &&
	       (s->rmap[s->r_contig / 8] & (1u << (s->r_contig % 8))))
		s->r_contig++;
	return 0;
}

/* ── 帧分派 ─────────────────────────────────────────────────────────── */
/* 返回 0 或负的传输错误码；*ack_eliciting 由调用方据此决定是否回 ACK */
static int qc_on_frame(struct kdg_qc *c, enum kdg_qc_space s,
		       const struct kdg_qframe *f, bool *ack_eliciting)
{
	struct kdg_qc_stream *st;

	if (f->type != QF_ACK && f->type != QF_ACK_ECN &&
	    f->type != QF_CONN_CLOSE && f->type != QF_CONN_CLOSE_APP)
		*ack_eliciting = true;

	/* §12.4 表 3：Initial/Handshake 只许 PADDING/PING/ACK/CRYPTO/CLOSE */
	if (s != QS_APP && f->type != QF_PING && f->type != QF_ACK &&
	    f->type != QF_ACK_ECN && f->type != QF_CRYPTO &&
	    f->type != QF_CONN_CLOSE)
		return -(int)QE_PROTOCOL_VIOLATION;

	switch (f->type) {
	case QF_PING:
		return 0;
	case QF_ACK:
	case QF_ACK_ECN:
		return qc_on_ack_frame(c, s, f) ? -(int)QE_PROTOCOL_VIOLATION : 0;
	case QF_CRYPTO: {
		int ret = qc_on_crypto(c, s, f);

		if (ret == -ENOSPC)
			return -(int)QE_INTERNAL;
		if (ret)
			return -(int)(QE_CRYPTO_BASE + (c->tls.alert ? c->tls.alert : 80));
		return 0;
	}
	case QF_NEW_TOKEN:	/* 客户端可忽略（不做恢复） */
		return 0;
	case QF_STREAM:
		return qc_on_stream(c, f);
	case QF_RESET_STREAM:
		st = qc_stream_find(c, f->u.reset.id);
		if (st && st->rbuf) {
			st->r_reset = true;
			st->r_err = f->u.reset.err;
		}
		return 0;
	case QF_STOP_SENDING:
		/* 对端不要了：本端结束该流发送（DoH 请求本身很小，直接视为已确认） */
		st = qc_stream_find(c, f->u.reset.id);
		if (st && st->sbuf) {
			st->s_fin_acked = true;
			st->s_acked = st->slen;
		}
		return 0;
	case QF_MAX_DATA:
		if (f->u.max.max > c->max_data_tx)
			c->max_data_tx = f->u.max.max;
		return 0;
	case QF_MAX_STREAM_DATA:
		st = qc_stream_find(c, f->u.max.id);
		if (st && st->sbuf && f->u.max.max > st->s_max)
			st->s_max = f->u.max.max;
		return 0;
	case QF_MAX_STREAMS_BIDI:
		if (f->u.max.max > c->max_bidi_tx)
			c->max_bidi_tx = f->u.max.max;
		return 0;
	case QF_MAX_STREAMS_UNI:
	case QF_DATA_BLOCKED:
	case QF_STREAM_DATA_BLOCKED:
	case QF_STREAMS_BLOCKED_BIDI:
	case QF_STREAMS_BLOCKED_UNI:
	case QF_RETIRE_CONNECTION_ID:
		return 0;
	case QF_NEW_CONNECTION_ID:
		/* 不迁移、不轮换 CID：只按 retire_prior_to 要求退役旧 CID（§19.15）。
		 * 当前使用的 CID 序号是 0；若被要求退役它，切换到新 CID。 */
		if (f->u.ncid.retire_prior > 0 && c->retire_cid_seq == 0) {
			memcpy(c->dcid, f->u.ncid.cid, f->u.ncid.cid_len);
			c->dcid_len = f->u.ncid.cid_len;
			c->send_retire = true;
		}
		return 0;
	case QF_PATH_CHALLENGE:
		memcpy(c->path_resp, f->u.path.data, 8);
		c->send_path_resp = true;
		return 0;
	case QF_PATH_RESPONSE:
		return 0;
	case QF_CONN_CLOSE:
	case QF_CONN_CLOSE_APP:
		c->err = f->u.close.err;
		c->err_app = f->type == QF_CONN_CLOSE_APP;
		c->peer_closed = true;
		c->state = QC_DRAINING;
		c->close_deadline = c->now + 3 * qc_pto(c, QS_APP);
		return 0;
	case QF_HANDSHAKE_DONE:
		c->hs_confirmed = true;
		qc_discard_space(c, QS_HANDSHAKE);
		return 0;
	default:
		return -(int)QE_FRAME_ENCODING;
	}
}

/* PART_PKT_RX */

/* ── 握手密钥安装与对端参数采纳 ─────────────────────────────────────── */
static int qc_adopt_tp(struct kdg_qc *c)
{
	int ret = kdg_qtp_parse(c->tls.peer_tp, c->tls.peer_tp_len, &c->peer);

	if (ret)
		return -(int)QE_TRANSPORT_PARAM;
	/* §7.3：服务器回的 original_destination_connection_id 必须等于我们首发的 DCID */
	if (!(c->retried && c->peer.has_retry_scid) &&
	    (c->peer.orig_dcid_len != c->odcid_len ||
	     memcmp(c->peer.orig_dcid, c->odcid, c->odcid_len)))
		return -(int)QE_TRANSPORT_PARAM;
	c->peer_tp_ok = true;
	c->max_data_tx = c->peer.initial_max_data;
	c->max_bidi_tx = c->peer.initial_max_streams_bidi;
	/* §10.1：空闲超时取本端与对端参数的较小值 */
	if (c->peer.max_idle_timeout) {
		u64 idle = c->peer.max_idle_timeout < c->local.max_idle_timeout ?
			   c->peer.max_idle_timeout : c->local.max_idle_timeout;

		if (idle)
			c->idle_deadline = c->now + idle;
	}
	return 0;
}

/* TLS 有进展后：装密钥、采纳对端参数、把新产生的握手字节搬到发送缓冲。 */
static int qc_after_tls(struct kdg_qc *c)
{
	int ret = qc_pull_tls(c);

	if (ret)
		return ret;
	if (c->tls.keys_hs && !c->sp[QS_HANDSHAKE].tx.ready) {
		ret = kdg_tls13_quic_keys(&c->tls, KDG_LVL_HANDSHAKE, true,
					  &c->sp[QS_HANDSHAKE].tx);
		if (!ret)
			ret = kdg_tls13_quic_keys(&c->tls, KDG_LVL_HANDSHAKE,
						  false, &c->sp[QS_HANDSHAKE].rx);
		if (ret)
			return ret;
		ret = qc_pull_tls(c);
		if (ret)
			return ret;
	}
	if (c->tls.peer_tp_seen && !c->peer_tp_ok) {
		ret = qc_adopt_tp(c);
		if (ret)
			return ret;
	}
	if (c->tls.keys_ap && !c->sp[QS_APP].tx.ready) {
		ret = kdg_tls13_quic_keys(&c->tls, KDG_LVL_APP, true,
					  &c->sp[QS_APP].tx);
		if (!ret)
			ret = kdg_tls13_quic_keys(&c->tls, KDG_LVL_APP, false,
						  &c->sp[QS_APP].rx);
		if (ret)
			return ret;
		ret = qc_pull_tls(c);
		if (ret)
			return ret;
		c->state = QC_ESTABLISHED;
	}
	return 0;
}

/* Retry（RFC 9000 §17.2.5）：校验完整性标签，换 DCID 与 token，重置 Initial 空间，
 * 重发 ClientHello。密钥种子仍是原 DCID（§5.2）。 */
static int qc_on_retry(struct kdg_qc *c, const u8 *pkt, size_t len,
		       const u8 *scid, size_t scid_len)
{
	u8 tag[KDG_QUIC_TAG_LEN];
	size_t tlen;
	unsigned int i;

	if (c->retried)
		return -(int)QE_PROTOCOL_VIOLATION;	/* 只接受一次 Retry */
	if (len < 16 + 1)
		return -(int)QE_PROTOCOL_VIOLATION;
	tlen = len - 16;
	if (tlen - 1 > sizeof(c->token))
		return -(int)QE_INTERNAL;
	if (kdg_quic_retry_tag(c->odcid, c->odcid_len, pkt, len - 16, tag))
		return -(int)QE_INTERNAL;
	if (memcmp(tag, pkt + len - 16, 16))
		return -(int)QE_PROTOCOL_VIOLATION;
	if (scid_len == 0 || scid_len > KDG_QUIC_MAX_CID)
		return -(int)QE_PROTOCOL_VIOLATION;

	/* token = 长度前缀之后到标签之前的全部字节 */
	{
		struct kdg_qrd r = { .p = pkt + 1 + 4 + 1 + c->dcid_len + 1,
				     .n = 0 };
		const u8 *tok = NULL;
		u64 n;

		/* 手工跳过 DCID/SCID 后读 token 长度 */
		r.n = len - (size_t)(r.p - pkt) - 16;
		n = kdg_qv_get(&r);
		if (r.bad || n != r.n)
			return -(int)QE_PROTOCOL_VIOLATION;
		tok = r.p;
		memcpy(c->token, tok, (size_t)n);
		c->token_len = (u16)n;
	}

	memcpy(c->dcid, scid, scid_len);
	c->dcid_len = (u8)scid_len;
	c->dcid_from_server = true;
	c->retried = true;

	/* 丢弃 Initial 空间在途记录与接收状态，但保留 CRYPTO 待发字节 */
	for (i = 0; i < KDG_QC_SENT_MAX; i++) {
		if (c->sp[QS_INITIAL].sent[i].in_use &&
		    c->sp[QS_INITIAL].sent[i].in_flight)
			c->bytes_in_flight -= c->sp[QS_INITIAL].sent[i].bytes;
		c->sp[QS_INITIAL].sent[i].in_use = false;
	}
	c->sp[QS_INITIAL].c_sent = 0;
	c->sp[QS_INITIAL].c_lost = false;
	c->sp[QS_INITIAL].n_rx_ranges = 0;
	c->sp[QS_INITIAL].ack_pending = false;
	c->pto_count = 0;
	c->pto_deadline = 0;
	return 0;
}

/* PART_PKT_RX */

/* ── 收包 ───────────────────────────────────────────────────────────── */
struct qc_hdr {
	enum kdg_qc_space space;
	bool long_form;
	size_t hdr_len, pn_off, pkt_len;	/* pkt_len 为本包在数据报中的长度 */
	size_t dcid_off, dcid_len, scid_off, scid_len;
	size_t token_off, token_len;
	bool is_retry;
};

/* 解析长/短头，界定本包长度。不涉及解密。 */
static int qc_parse_hdr(struct kdg_qc *c, u8 *buf, size_t len, struct qc_hdr *h)
{
	struct kdg_qrd r = { .p = buf + 1, .n = len - 1 };
	u8 b0 = buf[0];
	u64 l;

	memset(h, 0, sizeof(*h));
	if (len < 1)
		return -EBADMSG;
	if (!(b0 & 0x80)) {
		/* 短头：DCID 长度 = 本端 SCID 长度，包尾即包末 */
		h->space = QS_APP;
		h->long_form = false;
		h->dcid_len = sizeof(c->scid);
		h->dcid_off = 1;
		h->pn_off = 1 + h->dcid_len;
		h->pkt_len = len;
		h->hdr_len = h->pn_off + (b0 & 0x03) + 1;
		return h->hdr_len <= len ? 0 : -EBADMSG;
	}
	h->long_form = true;
	/* 长头类型在未解保护前不可信 —— 保留位 0x0c 也被保护，故只按版本与
	 * 长度字段定位；类型在解保护后重新判定。 */
	l = (u64)rd_bytes(&r, 4);
	if (l != KDG_QUIC_V1)
		return -EPROTONOSUPPORT;
	h->dcid_len = rd_bytes(&r, 1);
	if (r.bad || h->dcid_len > KDG_QUIC_MAX_CID || r.n < h->dcid_len + 1)
		return -EBADMSG;
	h->dcid_off = (size_t)(r.p - buf);
	r.p += h->dcid_len;
	r.n -= h->dcid_len;
	h->scid_len = rd_bytes(&r, 1);
	if (r.bad || h->scid_len > KDG_QUIC_MAX_CID || r.n < h->scid_len)
		return -EBADMSG;
	h->scid_off = (size_t)(r.p - buf);
	r.p += h->scid_len;
	r.n -= h->scid_len;
	if ((b0 & 0x30) == 0x30) {		/* Retry：无长度字段 */
		h->is_retry = true;
		h->pkt_len = len;
		h->token_off = (size_t)(r.p - buf);
		h->token_len = len - h->token_off;
		return 0;
	}
	if ((b0 & 0x30) == 0x00) {		/* Initial：token 长度可变 */
		u64 tl = kdg_qv_get(&r);

		if (r.bad || tl > r.n)
			return -EBADMSG;
		h->token_off = (size_t)(r.p - buf);
		h->token_len = (size_t)tl;
		r.p += tl;
		r.n -= tl;
	}
	l = kdg_qv_get(&r);
	if (r.bad || l > r.n || l < 20)		/* 至少 pn(1) + tag(16) */
		return -EBADMSG;
	h->pn_off = (size_t)(r.p - buf);
	h->pkt_len = h->pn_off + (size_t)l;
	if (h->pkt_len > len)
		return -EBADMSG;
	h->hdr_len = h->pn_off + (buf[0] & 0x03) + 1;	/* 解保护后修正 */
	return 0;
}

/* 按长头类型选空间。类型位在解保护后才可靠，此处先按未保护位粗判，
 * 解保护后由 qc_on_packet 复核。 */
static enum kdg_qc_space qc_space_of(u8 b0, bool long_form)
{
	if (!long_form)
		return QS_APP;
	switch (b0 & 0x30) {
	case 0x00:	return QS_INITIAL;
	case 0x20:	return QS_HANDSHAKE;
	default:	return QS_APP;	/* 0-RTT 不支持 */
	}
}

/* 解保护 + 解密 + 逐帧分派。pn 已在包内原地解出。 */
static int qc_on_packet(struct kdg_qc *c, u8 *buf, size_t len, u64 now)
{
	struct kdg_qc_pnspace *sp;
	struct qc_hdr h;
	enum kdg_qc_space space;
	u64 pn = 0;
	size_t pt_len;
	struct kdg_qrd r;
	bool ack_eliciting = false;
	struct kdg_qframe f;
	int ret;

	c->now = now;
	ret = qc_parse_hdr(c, buf, len, &h);
	if (ret)
		return ret;
	if (h.is_retry)
		return qc_on_retry(c, buf, len, buf + h.scid_off, h.scid_len);

	space = qc_space_of(buf[0], h.long_form);
	sp = &c->sp[space];
	/* 服务器首个 Initial 的 SCID 成为我们后续发包的 DCID（§7.2） */
	if (h.long_form && space == QS_INITIAL && !c->dcid_from_server &&
	    h.scid_len) {
		memcpy(c->dcid, buf + h.scid_off, h.scid_len);
		c->dcid_len = (u8)h.scid_len;
		c->dcid_from_server = true;
	}
	/* 收到的包其 DCID 必须等于本端 SCID，否则不是给我们的（§5.2 多路径） */
	if (h.dcid_len != sizeof(c->scid) ||
	    memcmp(buf + h.dcid_off, c->scid, h.dcid_len)) {
		c->rx_ignored++;
		return 0;
	}
	if (!sp->rx.ready) {
		c->rx_ignored++;	/* 该级密钥还没有（乱序的 Handshake） */
		return 0;
	}

	pt_len = (size_t)kdg_quic_unprotect(&sp->rx, buf, h.pn_off, h.pkt_len,
					    sp->largest_rx, &pn, &h.hdr_len);
	if ((s64)pt_len < 0) {
		c->rx_undecryptable++;	/* 含「数据报被接收缓冲截断」这一类 */
		return 0;
	}
	/* 保留位必须为 0（§17.2/§17.3.1） */
	if (h.long_form && (buf[0] & 0x0c))
		return -(int)QE_PROTOCOL_VIOLATION;
	if (!h.long_form && (buf[0] & 0x18))
		return -(int)QE_PROTOCOL_VIOLATION;
	if (qc_rx_seen(sp, pn))
		return 0;		/* 重复包：只再 ACK 一次 */
	/* 类型复核：Initial/Handshake 的密钥不同，解开了自证类型正确 */
	if (space == QS_INITIAL && (buf[0] & 0x30) == 0x20)
		return 0;

	qc_rx_record(sp, pn);
	if (sp->largest_rx < (s64)pn) {
		sp->largest_rx = (s64)pn;
		sp->largest_rx_t = now;
	}

	r.p = buf + h.hdr_len;
	r.n = pt_len;
	r.bad = false;
	while (r.n) {
		ret = kdg_qframe_next(&r, &f);
		if (ret == -EAGAIN)
			break;
		if (ret)
			return -(int)QE_FRAME_ENCODING;
		ret = qc_on_frame(c, space, &f, &ack_eliciting);
		if (ret)
			return ret;
		if (c->state == QC_DRAINING)
			return 0;
	}
	if (ack_eliciting) {
		sp->ack_pending = true;
		sp->last_ack_eliciting_t = now;
	}
	return qc_after_tls(c);
}

int kdg_qc_recv(struct kdg_qc *c, u8 *dgram, size_t len, u64 now)
{
	size_t off = 0;
	int ret = 0;

	if (c->state == QC_DRAINING) {
		c->close_deadline = now + 3 * qc_pto(c, QS_APP);
		return 0;
	}
	while (off < len) {
		size_t consumed, before;

		before = off;
		/* 每个包独立界定长度：先解析头部拿到 pkt_len */
		{
			struct qc_hdr h;

			if (qc_parse_hdr(c, dgram + off, len - off, &h))
				break;		/* 尾部残包：丢弃 */
			consumed = h.pkt_len;
		}
		ret = qc_on_packet(c, dgram + off, consumed, now);
		if (ret < 0)
			qc_fail(c, (u64)-ret);
		off += consumed;
		if (off <= before)
			break;
		if (c->state >= QC_CLOSING)
			break;
	}
	return ret < 0 ? ret : 0;
}

/* PART_PKT_TX */

/* ── 发包 ───────────────────────────────────────────────────────────── */
static struct kdg_qc_sent *qc_sent_alloc(struct kdg_qc_pnspace *sp, u64 pn,
					 u64 now)
{
	unsigned int i;

	for (i = 0; i < KDG_QC_SENT_MAX; i++) {
		if (!sp->sent[i].in_use) {
			struct kdg_qc_sent *p = &sp->sent[i];

			memset(p, 0, sizeof(*p));
			p->pn = pn;
			p->t_ms = now;
			p->in_use = true;
			return p;
		}
	}
	return NULL;	/* 在途包太多：调用方等确认后再发 */
}

/* ACK 帧：largest / delay / 区间数 / 首区间 / 其余 gap+range */
static u32 qc_build_ack(struct kdg_qc *c, enum kdg_qc_space s, u8 *out,
			u32 cap)
{
	struct kdg_qc_pnspace *sp = &c->sp[s];
	u32 n = 0, i;
	u64 delay_units = 0;
	size_t w;

	if (!sp->n_rx_ranges)
		return 0;
	if (c->now > sp->largest_rx_t)
		delay_units = ((c->now - sp->largest_rx_t) * 1000) >>
			      c->local.ack_delay_exponent;
	if (cap < 64)
		return 0;
	out[n++] = 0x02;
	w = kdg_qv_put(out + n, cap - n, (u64)sp->largest_rx);
	if (!w)
		return 0;
	n += w;
	w = kdg_qv_put(out + n, cap - n, delay_units);
	if (!w)
		return 0;
	n += w;
	w = kdg_qv_put(out + n, cap - n, sp->n_rx_ranges - 1);
	if (!w)
		return 0;
	n += w;
	w = kdg_qv_put(out + n, cap - n,
		       sp->rx_ranges[0].hi - sp->rx_ranges[0].lo);
	if (!w)
		return 0;
	n += w;
	for (i = 1; i < sp->n_rx_ranges; i++) {
		u64 gap = sp->rx_ranges[i - 1].lo - sp->rx_ranges[i].hi - 2;

		w = kdg_qv_put(out + n, cap - n, gap);
		if (!w)
			return 0;
		n += w;
		w = kdg_qv_put(out + n, cap - n,
			       sp->rx_ranges[i].hi - sp->rx_ranges[i].lo);
		if (!w)
			return 0;
		n += w;
	}
	return n;
}

static u32 qc_build_crypto(struct kdg_qc_pnspace *sp, u8 *out, u32 cap,
			   u32 *sent_off, u32 *sent_len)
{
	u32 off = sp->c_lost ? sp->c_lost_off : sp->c_sent;
	u32 len, n = 0, w;

	if (off >= sp->c_len || cap < 16)
		return 0;
	len = sp->c_len - off;
	if (len > cap - 16)
		len = cap - 16;
	out[n++] = 0x06;
	w = kdg_qv_put(out + n, cap - n, off);
	if (!w)
		return 0;
	n += w;
	w = kdg_qv_put(out + n, cap - n, len);
	if (!w)
		return 0;
	n += w;
	memcpy(out + n, sp->cbuf + off, len);
	n += len;
	*sent_off = off;
	*sent_len = len;
	return n;
}

/* 本端单向流上必须发的 HTTP/3 控制流数据也在 sbuf 里，走同一条路径。 */
static u32 qc_build_streams(struct kdg_qc *c, u8 *out, u32 cap,
			    struct kdg_qc_sent *rec)
{
	u32 n = 0;
	unsigned int i;

	for (i = 0; i < KDG_QC_MAX_STREAMS && n + 32 < cap; i++) {
		struct kdg_qc_stream *st = &c->st[i];
		u64 off;
		u32 len, w;
		bool fin;

		if (!st->used || !st->sbuf)
			continue;
		if (rec->nstreams >= ARRAY_SIZE(rec->st))
			break;
		off = st->s_lost ? st->s_lost_off : st->s_sent;
		if (off > st->slen)
			off = st->slen;
		if (off >= st->slen && (!st->s_fin || st->s_fin_sent))
			continue;
		if (off > st->s_max || c->data_sent >= c->max_data_tx)
			continue;
		len = (u32)(st->slen - off);
		if (len > cap - n - 32)
			len = cap - n - 32;
		if (len > st->s_max - off)
			len = (u32)(st->s_max - off);
		if (len > c->max_data_tx - c->data_sent)
			len = (u32)(c->max_data_tx - c->data_sent);
		fin = st->s_fin && off + len == st->slen;
		if (!len && !fin)
			continue;	/* 没有数据也没有 FIN：本轮不发 */
		if (st->s_fin_sent && !len)
			continue;
		/* 帧类型位：0x0e = OFF|LEN，0x0f 再加 FIN，0x0b = LEN|FIN */
		out[n++] = fin ? (len ? 0x0f : 0x0b) : 0x0e;
		w = kdg_qv_put(out + n, cap - n, st->id);
		if (!w)
			return n;
		n += w;
		w = kdg_qv_put(out + n, cap - n, off);
		if (!w)
			return n;
		n += w;
		w = kdg_qv_put(out + n, cap - n, len);
		if (!w)
			return n;
		n += w;
		memcpy(out + n, st->sbuf + off, len);
		n += len;
		rec->st[rec->nstreams].slot = i;
		rec->st[rec->nstreams].off = (u32)off;
		rec->st[rec->nstreams].len = len;
		rec->st[rec->nstreams].fin = fin;
		rec->nstreams++;
		c->data_sent += len;
		if (off + len > st->s_sent)
			st->s_sent = off + len;
		if (fin)
			st->s_fin_sent = true;
		st->s_lost = false;
	}
	return n;
}

/* PART_PKT_TX2 */

/* 组装一个包（含头部保护）。返回包总长，0 表示本空间暂无可发内容。 */
static int qc_build_packet(struct kdg_qc *c, enum kdg_qc_space s, u8 *out,
			   size_t cap, u64 now)
{
	struct kdg_qc_pnspace *sp = &c->sp[s];
	struct kdg_qc_sent *rec;
	size_t len_off, pn_off, hdr_len, room;
	u32 pl = 0, w, coff = 0, clen = 0;
	bool ack_eliciting = false;
	u64 pn = sp->next_pn;
	int total;

	if (!sp->tx.ready || cap < 400)
		return 0;
	/* 一个包的总长不得超过 1200（§14.1：不知道路径 MTU 时就按最小 1200 发）。
	 * 调用方给的缓冲可能更大（接收缓冲就是 1600），这里必须自己收口，
	 * 否则会发出比自己申报的 max_udp_payload 还大的数据报。 */
	if (cap > KDG_QC_MTU)
		cap = KDG_QC_MTU;
	if (s != QS_APP)
		hdr_len = 1 + 4 + 1 + c->dcid_len + 1 + sizeof(c->scid) + 2 +
			  (s == QS_INITIAL ? (size_t)(c->token_len ? c->token_len + 2 : 1) : 0) + 4;
	else
		hdr_len = 1 + c->dcid_len + 4;
	if (hdr_len + 24 > cap)
		return 0;

	/* 头部 */
	if (s == QS_APP) {
		out[0] = 0x40 | 0x03;			/* 短头，pn_len=4，保留位 0 */
		memcpy(out + 1, c->dcid, c->dcid_len);
		len_off = 0;				/* 短头无 Length 字段 */
		pn_off = 1 + c->dcid_len;
	} else {
		u8 *p = out;

		*p++ = (u8)(0xC0 | (s == QS_INITIAL ? 0x00 : 0x20) | 0x03);
		*p++ = 0; *p++ = 0; *p++ = 0; *p++ = 0x01;	/* version = 1 */
		*p++ = c->dcid_len;
		memcpy(p, c->dcid, c->dcid_len);
		p += c->dcid_len;
		*p++ = (u8)sizeof(c->scid);
		memcpy(p, c->scid, sizeof(c->scid));
		p += sizeof(c->scid);
		if (s == QS_INITIAL) {
			if (c->token_len) {
				size_t n = kdg_qv_put(p, 4, c->token_len);

				p += n;
				memcpy(p, c->token, c->token_len);
				p += c->token_len;
			} else {
				*p++ = 0;
			}
		}
		len_off = (size_t)(p - out);
		p += 2;					/* Length 占位（2 字节 varint） */
		pn_off = (size_t)(p - out);
	}
	hdr_len = pn_off + 4;
	out[pn_off + 0] = (u8)(pn >> 24);
	out[pn_off + 1] = (u8)(pn >> 16);
	out[pn_off + 2] = (u8)(pn >> 8);
	out[pn_off + 3] = (u8)pn;
	room = cap - hdr_len - KDG_QUIC_TAG_LEN;
	if (room > KDG_QC_MTU)
		room = KDG_QC_MTU;

	/* 帧：ACK → CLOSE → CRYPTO → STREAM → 其它 */
	if (sp->ack_pending) {
		w = qc_build_ack(c, s, out + hdr_len + pl, (u32)room - pl);
		if (w) {
			pl += w;
			sp->ack_pending = false;
		}
	}
	if (c->send_close && (s == QS_APP || s == QS_INITIAL)) {
		u8 *f = out + hdr_len + pl;
		u32 n = 0;

		f[n++] = c->err_app ? 0x1d : 0x1c;
		w = kdg_qv_put(f + n, room - pl - n, c->err);
		if (w) {
			n += w;
			if (!c->err_app) {
				w = kdg_qv_put(f + n, room - pl - n, 0);
				n += w;
			}
			f[n++] = 0;
			pl += n;
			ack_eliciting = true;
		}
	}
	if (s != QS_APP || sp->c_len > sp->c_sent || sp->c_lost) {
		w = qc_build_crypto(sp, out + hdr_len + pl, (u32)room - pl,
				    &coff, &clen);
		if (w) {
			pl += w;
			ack_eliciting = true;
			if (!sp->c_lost && coff + clen > sp->c_sent)
				sp->c_sent = coff + clen;
		}
	}
	rec = qc_sent_alloc(sp, pn, now);
	if (!rec)
		return 0;
	if (pl)
		rec->ack_eliciting = true;
	if (s == QS_APP) {
		w = qc_build_streams(c, out + hdr_len + pl, (u32)room - pl, rec);
		if (w) {
			pl += w;
			ack_eliciting = true;
		}
	}
	if (c->send_path_resp && s == QS_APP && room - pl > 12) {
		u8 *f = out + hdr_len + pl;

		f[0] = 0x1b;
		memcpy(f + 1, c->path_resp, 8);
		pl += 9;
		c->send_path_resp = false;
		ack_eliciting = true;
	}
	if (!pl) {
		rec->in_use = false;
		return 0;
	}
	if (s != QS_APP && (sp->c_len > sp->c_sent || sp->c_lost) && clen) {
		rec->has_crypto = true;
		rec->crypto_off = coff;
		rec->crypto_len = clen;
	}
	rec->ack_eliciting = ack_eliciting;

	/* Initial 所在数据报必须凑满 1200（§14.1） */
	if (s == QS_INITIAL) {
		while (hdr_len + pl + KDG_QUIC_TAG_LEN < KDG_QC_MTU && pl < room)
			out[hdr_len + pl++] = 0x00;
	}
	if (len_off)
		kdg_qv_put2(out + len_off, (u64)(4 + pl + KDG_QUIC_TAG_LEN));

	total = kdg_quic_protect(&sp->tx, pn, out, pn_off, 4, hdr_len, pl, cap);
	if (total < 0) {
		rec->in_use = false;
		return 0;
	}
	rec->bytes = (u16)total;
	rec->in_flight = ack_eliciting;
	if (ack_eliciting) {
		c->bytes_in_flight += total;
		sp->last_ack_eliciting_t = now;
	}
	sp->next_pn++;
	return total;
}

size_t kdg_qc_send(struct kdg_qc *c, u8 *out, size_t cap, u64 now)
{
	int n, i;
	bool sent_any = false;

	c->now = now;
	if (c->state == QC_DRAINING)
		return 0;
	if (c->state == QC_CLOSED)
		return 0;
	/* 关闭中：只在 1-RTT 发一次 CONNECTION_CLOSE */
	if (c->state == QC_CLOSING)
		return c->send_close ? (size_t)qc_build_packet(c, QS_APP, out, cap, now) : 0;

	for (i = 0; i < QS_COUNT; i++) {
		/* 先发最"紧急"的空间：APP 优先（数据），其次 Handshake，最后 Initial */
		enum kdg_qc_space s2 = i == 0 ? QS_APP : i == 1 ? QS_HANDSHAKE : QS_INITIAL;
		struct kdg_qc_pnspace *sp = &c->sp[s2];

		if (sp->discarded || !sp->tx.ready)
			continue;
		if (c->bytes_in_flight >= c->cwnd && s2 != QS_APP)
			continue;	/* 拥塞窗口满：只有 1-RTT 的 ACK 仍可发 */
		n = qc_build_packet(c, s2, out, cap, now);
		if (n > 0) {
			sent_any = true;
			/* 发出首个 Handshake 包后即可丢弃 Initial 密钥（RFC 9001 §4.9.1） */
			if (s2 == QS_HANDSHAKE)
				qc_discard_space(c, QS_INITIAL);
			/* §6.2.1：有 ack-eliciting 在途包就安排 PTO */
			if (c->bytes_in_flight && !c->pto_deadline)
				c->pto_deadline = now + qc_pto(c, s2);
			break;
		}
	}
	if (c->state == QC_CLOSING && sent_any)
		c->send_close = false;
	return sent_any ? (size_t)n : 0;
}

/* ── 计时器 ─────────────────────────────────────────────────────────── */
void kdg_qc_timeout(struct kdg_qc *c, u64 now)
{
	unsigned int i;
	int s;

	c->now = now;
	if (c->state == QC_DRAINING) {
		if (now >= c->close_deadline)
			c->state = QC_CLOSED;
		return;
	}
	if (c->state == QC_CLOSED)
		return;
	if (now >= c->idle_deadline && c->state != QC_CLOSING) {
		qc_fail(c, QE_NO_ERROR);
		return;
	}
	if (c->state == QC_CLOSING) {
		if (now >= c->close_deadline)
			c->state = QC_CLOSED;
		return;
	}
	/* 时间阈值丢包 */
	qc_detect_loss(c, QS_APP);
	qc_detect_loss(c, QS_HANDSHAKE);
	qc_detect_loss(c, QS_INITIAL);
	if (c->pto_deadline && now >= c->pto_deadline) {
		c->pto_count++;
		c->pto_deadline = 0;
		/* PTO：把最早的在途包标记为待重传（§6.2.4） */
		for (s = 0; s < QS_COUNT; s++) {
			struct kdg_qc_pnspace *sp = &c->sp[s];

			if (sp->discarded)
				continue;
			for (i = 0; i < KDG_QC_SENT_MAX; i++) {
				struct kdg_qc_sent *p = &sp->sent[i];

				if (!p->in_use || !p->ack_eliciting)
					continue;
				qc_on_lost(c, (enum kdg_qc_space)s, p);
			}
		}
		/* 触发一次探测：发 PING 以便拿到 RTT 样本 */
		c->send_ping = true;
	}
}

u64 kdg_qc_next_timer(const struct kdg_qc *c)
{
	u64 t = c->idle_deadline;
	unsigned int i;
	int s;

	if (c->state == QC_CLOSED)
		return 0;
	if (c->close_deadline && c->close_deadline < t)
		t = c->close_deadline;
	if (c->pto_deadline && c->pto_deadline < t)
		t = c->pto_deadline;
	for (s = 0; s < QS_COUNT; s++) {
		if (c->sp[s].loss_time && c->sp[s].loss_time < t)
			t = c->sp[s].loss_time;
		for (i = 0; i < KDG_QC_SENT_MAX; i++) {
			if (!c->sp[s].sent[i].in_use)
				continue;
			/* 有在途 ack-eliciting 包时，PTO 至少要到最近一次发送 + PTO */
			break;
		}
	}
	return t;
}

/* ── 流接口 ─────────────────────────────────────────────────────────── */
s64 kdg_qc_stream_open(struct kdg_qc *c, bool uni)
{
	u64 seq, id;

	if (c->state < QC_HANDSHAKING)
		return -EINVAL;
	if (uni) {
		/* 对端还没给 initial_max_streams_uni 前一律不许开（保守取值 0） */
		if (c->next_uni >= c->peer.initial_max_streams_uni)
			return -EMFILE;
		seq = c->next_uni++;
		id = (seq << 2) | 0x02;			/* 本端发起、单向 */
	} else {
		if (c->next_bidi >= c->max_bidi_tx)
			return -EMFILE;			/* 对端还不允许更多双向流 */
		seq = c->next_bidi++;
		id = seq << 2;				/* 本端发起、双向 */
	}
	if (!qc_stream_new(c, id))
		return -ENOMEM;
	return (s64)id;
}

int kdg_qc_stream_write(struct kdg_qc *c, u64 id, const u8 *data, size_t len,
			bool fin)
{
	struct kdg_qc_stream *s = qc_stream_find(c, id);

	if (!s || !s->sbuf)
		return -EINVAL;
	if (s->s_fin)
		return -EPIPE;
	if (len > KDG_QC_STREAM_BUF - s->slen)
		return -EMSGSIZE;
	if (len)
		memcpy(s->sbuf + s->slen, data, len);
	s->slen += len;
	s->s_fin = fin;
	return 0;
}

s64 kdg_qc_stream_read(struct kdg_qc *c, u64 id, u8 *out, size_t cap,
		       bool *fin)
{
	struct kdg_qc_stream *s = qc_stream_find(c, id);
	size_t n;

	*fin = false;
	if (!s || !s->rbuf)
		return -EINVAL;
	if (s->r_reset)
		return -(s64)s->r_err;
	if (s->r_read >= s->r_contig) {
		if (s->r_final != ~0ULL && s->r_read >= s->r_final)
			*fin = true;
		return 0;
	}
	n = (size_t)(s->r_contig - s->r_read);
	if (n > cap)
		n = cap;
	memcpy(out, s->rbuf + s->r_read, n);
	s->r_read += n;
	if (s->r_final != ~0ULL && s->r_read >= s->r_final)
		*fin = true;
	return (s64)n;
}

/* 线性扫描：DoH 的并发流很少，且有界（≤ 72）。 */
int kdg_qc_stream_next_readable(struct kdg_qc *c, u64 *id, u32 *iter)
{
	for (; *iter < KDG_QC_MAX_STREAMS; (*iter)++) {
		struct kdg_qc_stream *s = &c->st[*iter];

		if (!s->used)
			continue;
		if (s->r_reset) {
			*id = s->id;
			(*iter)++;
			return 1;
		}
		if (s->r_read < s->r_contig ||
		    (s->r_final != ~0ULL && s->r_read >= s->r_final)) {
			*id = s->id;
			(*iter)++;
			return 1;
		}
	}
	return 0;
}

