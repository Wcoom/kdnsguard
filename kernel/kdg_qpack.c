// SPDX-License-Identifier: GPL-2.0
/*
 * kdg_qpack.c —— QPACK 静态表、整数/字符串编解码、字段段解码。
 * 范围与验证说明见 kdg_qpack.h。
 */
#include "kdg_qpack.h"
#include "kdg_qpack_huff_table.h"

#ifndef __KERNEL__
#include <errno.h>
#endif

/* RFC 9204 附录 A。name 为 NULL 表示该行只有名（值恒为空串）。 */
static const struct { const char *name, *value; } qpack_static[KDG_QPACK_STATIC_N] = {
	{ ":authority", "" },
	{ ":path", "/" },
	{ "age", "0" },
	{ "content-disposition", "" },
	{ "content-length", "0" },
	{ "cookie", "" },
	{ "date", "" },
	{ "etag", "" },
	{ "if-modified-since", "" },
	{ "if-none-match", "" },
	{ "last-modified", "" },
	{ "link", "" },
	{ "location", "" },
	{ "referer", "" },
	{ "set-cookie", "" },
	{ ":method", "CONNECT" },
	{ ":method", "DELETE" },
	{ ":method", "GET" },
	{ ":method", "HEAD" },
	{ ":method", "OPTIONS" },
	{ ":method", "POST" },
	{ ":method", "PUT" },
	{ ":scheme", "http" },
	{ ":scheme", "https" },
	{ ":status", "103" },
	{ ":status", "200" },
	{ ":status", "304" },
	{ ":status", "404" },
	{ ":status", "503" },
	{ "accept", "*/*" },
	{ "accept", "application/dns-message" },
	{ "accept-encoding", "gzip, deflate, br" },
	{ "accept-ranges", "bytes" },
	{ "access-control-allow-headers", "cache-control" },
	{ "access-control-allow-headers", "content-type" },
	{ "access-control-allow-origin", "*" },
	{ "cache-control", "max-age=0" },
	{ "cache-control", "max-age=2592000" },
	{ "cache-control", "max-age=604800" },
	{ "cache-control", "no-cache" },
	{ "cache-control", "no-store" },
	{ "cache-control", "public, max-age=31536000" },
	{ "content-encoding", "br" },
	{ "content-encoding", "gzip" },
	{ "content-type", "application/dns-message" },
	{ "content-type", "application/javascript" },
	{ "content-type", "application/json" },
	{ "content-type", "application/x-www-form-urlencoded" },
	{ "content-type", "image/gif" },
	{ "content-type", "image/jpeg" },
	{ "content-type", "image/png" },
	{ "content-type", "text/css" },
	{ "content-type", "text/html; charset=utf-8" },
	{ "content-type", "text/plain" },
	{ "content-type", "text/plain;charset=utf-8" },
	{ "range", "bytes=0-" },
	{ "strict-transport-security", "max-age=31536000" },
	{ "strict-transport-security", "max-age=31536000; includesubdomains" },
	{ "strict-transport-security", "max-age=31536000; includesubdomains; preload" },
	{ "vary", "accept-encoding" },
	{ "vary", "origin" },
	{ "x-content-type-options", "nosniff" },
	{ "x-xss-protection", "1; mode=block" },
	{ ":status", "100" },
	{ ":status", "204" },
	{ ":status", "206" },
	{ ":status", "302" },
	{ ":status", "400" },
	{ ":status", "403" },
	{ ":status", "421" },
	{ ":status", "425" },
	{ ":status", "500" },
	{ "accept-language", "" },
	{ "access-control-allow-credentials", "FALSE" },
	{ "access-control-allow-credentials", "TRUE" },
	{ "access-control-allow-headers", "*" },
	{ "access-control-allow-methods", "get" },
	{ "access-control-allow-methods", "get, post, options" },
	{ "access-control-allow-methods", "options" },
	{ "access-control-expose-headers", "content-length" },
	{ "access-control-request-headers", "content-type" },
	{ "access-control-request-method", "get" },
	{ "access-control-request-method", "post" },
	{ "alt-svc", "clear" },
	{ "authorization", "" },
	{ "content-security-policy", "script-src 'none'; object-src 'none'; base-uri 'none'" },
	{ "early-data", "1" },
	{ "expect-ct", "" },
	{ "forwarded", "" },
	{ "if-range", "" },
	{ "origin", "" },
	{ "purpose", "prefetch" },
	{ "server", "" },
	{ "timing-allow-origin", "*" },
	{ "upgrade-insecure-requests", "1" },
	{ "user-agent", "" },
	{ "x-forwarded-for", "" },
	{ "x-frame-options", "deny" },
	{ "x-frame-options", "sameorigin" },
};

/* 编译期守住表长：少一行会让索引整体错位，而错位不会崩、只会解出错值。 */
typedef char qpack_static_size_check[(ARRAY_SIZE(qpack_static) == KDG_QPACK_STATIC_N) ? 1 : -1];

const char *kdg_qpack_static_name(size_t idx)
{
	return idx < KDG_QPACK_STATIC_N ? qpack_static[idx].name : NULL;
}

const char *kdg_qpack_static_value(size_t idx)
{
	return idx < KDG_QPACK_STATIC_N ? qpack_static[idx].value : NULL;
}

/* ── 有界读取 ──────────────────────────────────────────────────────── */
struct qrd {
	const u8 *p;
	size_t n;
	bool bad;
};

static u8 qrd_u8(struct qrd *r)
{
	if (r->bad || !r->n) {
		r->bad = true;
		return 0;
	}
	r->n--;
	return *r->p++;
}

/* 取一个 n 位前缀的整数（RFC 9204 §4.1.1） */
static u64 qrd_int(struct qrd *r, unsigned prefix)
{
	u64 v = qrd_u8(r) & ((1u << prefix) - 1);
	unsigned shift = 0;

	if (v < (u64)((1u << prefix) - 1))
		return v;
	for (;;) {
		u8 b = qrd_u8(r);

		if (r->bad || shift > 62)
			break;
		v += (u64)(b & 0x7f) << shift;
		shift += 7;
		if (!(b & 0x80))
			break;
	}
	return v;
}

/* 字符串字面量：长度用 prefix 位前缀，H 位在 hbit 位置（§4.1.2）。 */
static const u8 *qrd_str(struct qrd *r, unsigned prefix, u8 hbit, u64 *len,
			 bool *huff)
{
	u64 n;
	const u8 *p;

	if (r->bad || !r->n) {
		r->bad = true;
		*len = 0;
		return NULL;
	}
	*huff = r->p[0] & hbit;
	n = qrd_int(r, prefix);
	if (r->bad || n > r->n) {
		r->bad = true;
		*len = 0;
		return NULL;
	}
	p = r->p;
	r->p += n;
	r->n -= n;
	*len = n;
	return p;
}

/* ── Huffman 解码（RFC 7541 §5.2 的表，逐位走生成树） ──────────────── */
int kdg_qpack_huff_decode(const u8 *in, size_t inlen, u8 *out, size_t outcap,
			  size_t *outlen)
{
	s32 node = 0;
	u32 acc = 0, pend = 0;
	unsigned nbits = 0, pendbits = 0;
	size_t o = 0, i;

	for (i = 0; i < inlen; i++) {
		acc = (acc << 8) | in[i];
		nbits += 8;
		while (nbits) {
			unsigned bit = (acc >> (nbits - 1)) & 1;

			nbits--;
			acc &= (1u << nbits) - 1;
			pend = (pend << 1) | bit;
			pendbits++;
			node = kdg_huff_tree[node].child[bit];
			if (node < 0)
				return -EBADMSG;
			if (kdg_huff_tree[node].sym >= 0) {
				if (kdg_huff_tree[node].sym == KDG_HUFF_EOS_SYM)
					return -EBADMSG;
				if (o >= outcap)
					return -ENOSPC;
				out[o++] = (u8)kdg_huff_tree[node].sym;
				node = 0;
				pend = 0;
				pendbits = 0;
			}
		}
	}
	/* 收尾：停在非叶节点说明有填充，必须 ≤7 位且全为 1（EOS 高位） */
	if (node != 0) {
		if (pendbits > 7)
			return -EBADMSG;
		if ((pend & ((1u << pendbits) - 1)) != ((1u << pendbits) - 1))
			return -EBADMSG;
	}
	*outlen = o;
	return 0;
}

/* 解码器缓冲里的字符串：Huffman 或原样引用 */
static int qpack_put_str(struct kdg_qpack_dec *d, struct qrd *r,
			 unsigned prefix, u8 hbit, const u8 **p, size_t *len)
{
	bool huff;
	u64 n;
	const u8 *src = qrd_str(r, prefix, hbit, &n, &huff);

	if (r->bad)
		return -EBADMSG;
	if (!huff) {
		*p = src;
		*len = (size_t)n;
		return 0;
	}
	if (d->used >= d->cap)
		return -ENOSPC;
	if (kdg_qpack_huff_decode(src, (size_t)n, d->buf + d->used,
				  d->cap - d->used, len))
		return -EBADMSG;
	*p = d->buf + d->used;
	d->used += *len;
	return 0;
}

void kdg_qpack_dec_init(struct kdg_qpack_dec *d, u8 *buf, size_t cap)
{
	d->buf = buf;
	d->cap = cap;
	d->used = 0;
	d->nfields = 0;
}

int kdg_qpack_decode(struct kdg_qpack_dec *d, const u8 *in, size_t inlen,
		     struct kdg_qpack_field *out, size_t max_fields)
{
	struct qrd r = { .p = in, .n = inlen };
	u64 ric, base;

	d->used = 0;
	d->nfields = 0;
	/* 字段段前缀：Required Insert Count(8) + Delta Base(7+符号位) */
	ric = qrd_int(&r, 8);
	if (r.bad)
		return -EBADMSG;
	base = qrd_int(&r, 7);
	if (r.bad)
		return -EBADMSG;
	/* 申报容量 0 ⇒ 对端不得引用动态表（§4.5.1.1） */
	if (ric || base)
		return -EOPNOTSUPP;

	while (r.n && !r.bad) {
		u8 b;
		const u8 *name = NULL, *val = NULL;
		size_t nlen = 0, vlen = 0;

		if (d->nfields >= max_fields)
			return -ENOSPC;
		/* ⚠️ 只窥视首字节：前缀位就在这个字节里，必须由下面的整数读取器
		 * 消费它。第一版先 qrd_u8 再按前缀重读，等于整体错位一字节。 */
		b = r.p[0];
		if (b & 0x80) {				/* 索引字段行 */
			u64 idx;

			idx = qrd_int(&r, 6);
			if (!(b & 0x40))
				return -EOPNOTSUPP;	/* T=0：动态表 */
			if (idx >= KDG_QPACK_STATIC_N)
				return -EBADMSG;
			name = (const u8 *)kdg_qpack_static_name(idx);
			nlen = strlen((const char *)name);
			val = (const u8 *)kdg_qpack_static_value(idx);
			vlen = strlen((const char *)val);
		} else if ((b & 0xc0) == 0x40) {	/* 名引用字面量 */
			u64 idx;

			idx = qrd_int(&r, 4);
			if (!(b & 0x10))
				return -EOPNOTSUPP;
			if (idx >= KDG_QPACK_STATIC_N)
				return -EBADMSG;
			name = (const u8 *)kdg_qpack_static_name(idx);
			nlen = strlen((const char *)name);
			if (qpack_put_str(d, &r, 7, 0x80, &val, &vlen))
				return -EBADMSG;
		} else if ((b & 0xe0) == 0x20) {	/* 字面量名 */
			if (qpack_put_str(d, &r, 3, 0x08, &name, &nlen))
				return -EBADMSG;
			if (qpack_put_str(d, &r, 7, 0x80, &val, &vlen))
				return -EBADMSG;
		} else {
			return -EOPNOTSUPP;		/* Post-Base：动态表 */
		}
		if (r.bad || !name)
			return -EBADMSG;
		out[d->nfields].name = name;
		out[d->nfields].name_len = nlen;
		out[d->nfields].val = val;
		out[d->nfields].val_len = vlen;
		d->nfields++;
	}
	if (r.bad)
		return -EBADMSG;
	return 0;
}

const struct kdg_qpack_field *kdg_qpack_dec_at(const struct kdg_qpack_dec *d,
					       const struct kdg_qpack_field *f,
					       size_t i)
{
	return i < d->nfields ? &f[i] : NULL;
}

const struct kdg_qpack_field *kdg_qpack_find(const struct kdg_qpack_field *f,
					     size_t n, const char *name)
{
	size_t i, l = strlen(name);

	for (i = 0; i < n; i++)
		if (f[i].name_len == l && !memcmp(f[i].name, name, l))
			return &f[i];
	return NULL;
}

/* ── 请求编码：只用静态索引与名引用，不发 Huffman（最小可审） ─────── */
static int qp_put(u8 *out, size_t cap, size_t *n, const void *p, size_t l)
{
	if (cap - *n < l)
		return -ENOSPC;
	memcpy(out + *n, p, l);
	*n += l;
	return 0;
}

static int qp_put_str(u8 *out, size_t cap, size_t *n, const char *s)
{
	size_t l = strlen(s);
	u8 hdr = (u8)l;				/* H=0，长度 ≤127 */

	if (l > 127)
		return -EMSGSIZE;
	if (qp_put(out, cap, n, &hdr, 1))
		return -ENOSPC;
	return qp_put(out, cap, n, s, l);
}

int kdg_qpack_encode_post(u8 *out, size_t cap, const char *authority,
			  const char *path)
{
	size_t n = 0;
	u8 b;

	b = 0x00;				/* RIC = 0 */
	if (qp_put(out, cap, &n, &b, 1))
		return -ENOSPC;
	b = 0x00;				/* Delta Base = 0 */
	if (qp_put(out, cap, &n, &b, 1))
		return -ENOSPC;
	b = 0xc0 | 20;				/* 索引 :method POST（静态 20） */
	if (qp_put(out, cap, &n, &b, 1))
		return -ENOSPC;
	b = 0xc0 | 23;				/* 索引 :scheme https */
	if (qp_put(out, cap, &n, &b, 1))
		return -ENOSPC;
	b = 0x50;				/* 名引用 :authority（静态 0） */
	if (qp_put(out, cap, &n, &b, 1) || qp_put_str(out, cap, &n, authority))
		return -ENOSPC;
	b = 0x51;				/* 名引用 :path（静态 1） */
	if (qp_put(out, cap, &n, &b, 1) || qp_put_str(out, cap, &n, path))
		return -ENOSPC;
	b = 0xc0 | 30;				/* accept: application/dns-message */
	if (qp_put(out, cap, &n, &b, 1))
		return -ENOSPC;
	b = 0xc0 | 44;				/* content-type: application/dns-message */
	if (qp_put(out, cap, &n, &b, 1))
		return -ENOSPC;
	return (int)n;
}

