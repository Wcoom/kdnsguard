/* SPDX-License-Identifier: GPL-2.0 */
/*
 * test_cache.c —— kdg_cache 的宿主侧语料测试。
 *
 * 重点在三块最容易错的地方：
 *   1. 回包重封装：ID 恢复、问题区**原样**替换（含大小写）、TTL 逐条递减
 *   2. 拒绝路径：过期、问题区压缩、长度不符、缓冲区不足
 *   3. TTL 偏移收集必须**跳过 OPT**（OPT 的 TTL 字段不是生存时间）
 */
#include <stdio.h>
#include <string.h>

#include "kdg_cache.h"

static int g_pass, g_fail;

#define T(cond, name) do {						\
	if (cond) {							\
		g_pass++;						\
	} else {							\
		g_fail++;						\
		printf("  FAIL %-52s (line %d)\n", name, __LINE__);	\
	}								\
} while (0)

#define TEQ(expr, want, name) do {					\
	long _g = (long)(expr), _w = (long)(want);			\
	if (_g == _w) {							\
		g_pass++;						\
	} else {							\
		g_fail++;						\
		printf("  FAIL %-52s got=%ld want=%ld (line %d)\n",	\
		       name, _g, _w, __LINE__);				\
	}								\
} while (0)

/* ── 报文构造 ────────────────────────────────────────────────────────── */

static size_t raw_name(u8 *p, const char *text)
{
	const char *s = text;
	size_t o = 0;

	while (*s) {
		const char *dot = strchr(s, '.');
		size_t l = dot ? (size_t)(dot - s) : strlen(s);

		p[o++] = (u8)l;
		memcpy(p + o, s, l);
		o += l;
		if (!dot)
			break;
		s = dot + 1;
	}
	p[o++] = 0;
	return o;
}

static void put16(u8 *p, u16 v)
{
	p[0] = (u8)(v >> 8);
	p[1] = (u8)v;
}

static void put32(u8 *p, u32 v)
{
	p[0] = (u8)(v >> 24);
	p[1] = (u8)(v >> 16);
	p[2] = (u8)(v >> 8);
	p[3] = (u8)v;
}

static u32 get32(const u8 *p)
{
	return ((u32)p[0] << 24) | ((u32)p[1] << 16) |
	       ((u32)p[2] << 8) | p[3];
}

/* 构造查询：qname/qtype，可选大小写。 */
static size_t build_query(u8 *b, u16 id, const char *name, u16 qtype,
			  u16 flags)
{
	size_t n = 12;

	put16(b, id);
	put16(b + 2, flags);
	put16(b + 4, 1);
	put16(b + 6, 0);
	put16(b + 8, 0);
	put16(b + 10, 0);
	n += raw_name(b + n, name);
	put16(b + n, qtype);
	n += 2;
	put16(b + n, 1 /* IN */);
	n += 2;
	return n;
}

/* 构造响应：问题区为 name，一条 A 记录 ttl。返回 ttl 字段的偏移。 */
static size_t build_resp(u8 *b, u16 id, const char *name, u32 ttl,
			 const u8 ip[4], size_t *ttl_off)
{
	size_t n = 12;

	put16(b, id);
	put16(b + 2, 0x8180);	/* QR|RD|RA, NOERROR */
	put16(b + 4, 1);
	put16(b + 6, 1);
	put16(b + 8, 0);
	put16(b + 10, 0);
	n += raw_name(b + n, name);
	put16(b + n, 1);
	n += 2;
	put16(b + n, 1);
	n += 2;

	/* answer：owner 用压缩指针指向问题区 */
	b[n++] = 0xC0;
	b[n++] = 0x0C;
	put16(b + n, 1);
	n += 2;
	put16(b + n, 1);
	n += 2;
	*ttl_off = n;
	put32(b + n, ttl);
	n += 4;
	put16(b + n, 4);
	n += 2;
	memcpy(b + n, ip, 4);
	n += 4;
	return n;
}

/* 追加一个 OPT（其 TTL 字段不是 TTL，必须被收集器跳过）。 */
static size_t append_opt(u8 *b, size_t n)
{
	b[n++] = 0;		/* root */
	put16(b + n, 41);	/* OPT */
	n += 2;
	put16(b + n, 1232);	/* UDP size */
	n += 2;
	put32(b + n, 0x00000000);	/* ext-rcode|ver|flags */
	n += 4;
	put16(b + n, 0);	/* rdlen */
	n += 2;
	return n;
}

/* ── 键 ──────────────────────────────────────────────────────────────── */

static void test_key(void)
{
	struct kdg_query q;
	struct kdg_cache_key k1, k2;
	u8 b[512];
	size_t n;

	puts("[缓存键]");

	n = build_query(b, 0x1234, "Example.COM", 1, KDG_DNS_F_RD);
	TEQ(kdg_wire_parse_query(b, n, &q), KDG_W_OK, "查询解析");
	TEQ(kdg_cache_key_from_query(&q, 0, 5, &k1), KDG_CKE_OK, "构造键");
	TEQ(k1.qname_len, 13, "qname 长度（含 root）");
	T(k1.flags & KDG_CKF_RD, "RD 位进键");
	T(!(k1.flags & KDG_CKF_EDNS), "无 EDNS");
	TEQ(k1.profile_gen, 5, "profile 代际进键");
	TEQ(k1.qtype, 1, "qtype");

	/* 大小写不同的同一名字必须产生**相同**的键（规范小写） */
	n = build_query(b, 0x1234, "eXaMpLe.cOm", 1, KDG_DNS_F_RD);
	kdg_wire_parse_query(b, n, &q);
	TEQ(kdg_cache_key_from_query(&q, 0, 5, &k2), KDG_CKE_OK, "大写查询构键");
	T(kdg_cache_key_eq(&k1, &k2), "大小写不同 → 键相等");
	TEQ(kdg_cache_key_hash(&k1), kdg_cache_key_hash(&k2), "哈希也相等");

	/* reserved_ 不应影响哈希（否则填充字节会让同键散到不同桶） */
	k2.reserved_ = 0xAB;
	TEQ(kdg_cache_key_hash(&k1), kdg_cache_key_hash(&k2),
	    "reserved_ 不影响哈希");

	/* 不同 profile 代际必须不同键 */
	n = build_query(b, 1, "example.com", 1, KDG_DNS_F_RD);
	kdg_wire_parse_query(b, n, &q);
	kdg_cache_key_from_query(&q, 0, 6, &k2);
	T(!kdg_cache_key_eq(&k1, &k2), "不同 profile 代际 → 键不等");

	/* 不同 qtype 必须不同键 */
	n = build_query(b, 1, "example.com", 28, KDG_DNS_F_RD);
	kdg_wire_parse_query(b, n, &q);
	kdg_cache_key_from_query(&q, 0, 5, &k2);
	T(!kdg_cache_key_eq(&k1, &k2), "A 与 AAAA → 键不等");

	/* 不同 netId 必须不同键 */
	n = build_query(b, 1, "example.com", 1, KDG_DNS_F_RD);
	kdg_wire_parse_query(b, n, &q);
	kdg_cache_key_from_query(&q, 7, 5, &k2);
	T(!kdg_cache_key_eq(&k1, &k2), "不同 netId → 键不等");
}

static void test_key_reject(void)
{
	struct kdg_query q;
	struct kdg_cache_key k;
	u8 b[512];
	u8 opts[16];
	size_t n, olen;

	puts("[缓存键 · 拒绝路径]");

	/* 带 ECS 的请求：不缓存、不合并（方案 §7.2） */
	put16(opts, KDG_EDNS_OPT_ECS);
	put16(opts + 2, 7);
	memset(opts + 4, 0xAB, 7);
	olen = 11;

	n = build_query(b, 1, "example.com", 1, KDG_DNS_F_RD);
	/* 手工追加 OPT */
	b[n++] = 0;
	put16(b + n, 41);
	n += 2;
	put16(b + n, 1232);
	n += 2;
	put32(b + n, 0);
	n += 4;
	put16(b + n, (u16)olen);
	n += 2;
	memcpy(b + n, opts, olen);
	n += olen;
	put16(b + 10, 1);

	TEQ(kdg_wire_parse_query(b, n, &q), KDG_W_OK, "带 ECS 查询解析");
	T(q.edns_has_ecs, "ECS 被识别");
	TEQ(kdg_cache_key_from_query(&q, 0, 1, &k), -KDG_CKE_NOTCACHEABLE,
	    "ECS 请求被拒绝缓存");

	/* 无 EDNS 的正常请求应当接受 */
	n = build_query(b, 1, "example.com", 1, KDG_DNS_F_RD);
	kdg_wire_parse_query(b, n, &q);
	TEQ(kdg_cache_key_from_query(&q, 0, 1, &k), KDG_CKE_OK, "普通请求接受");
}

/* ── 新鲜度 ──────────────────────────────────────────────────────────── */

static void test_fresh(void)
{
	struct kdg_cache_tmpl t;

	puts("[新鲜度]");

	memset(&t, 0, sizeof(t));
	t.stored_ms = 1000;
	t.ttl_ms = 5000;

	T(kdg_cache_fresh(&t, 1000), "刚写入 → 新鲜");
	T(kdg_cache_fresh(&t, 5999), "差 1ms 到期 → 仍新鲜");
	T(!kdg_cache_fresh(&t, 6000), "正好到期 → 不新鲜");
	T(!kdg_cache_fresh(&t, 6001), "过期 → 不新鲜");

	/* 时钟源回退（测试构造或切换时钟）不得被当成「已过去很久」 */
	T(!kdg_cache_fresh(&t, 999), "now < stored → 不新鲜（而非误判新鲜）");

	t.ttl_ms = 0;
	T(!kdg_cache_fresh(&t, 1000), "TTL=0 → 永不新鲜");
}

/* ── TTL 偏移收集 ────────────────────────────────────────────────────── */

static void test_ttl_offs(void)
{
	u8 b[512];
	const u8 ip[4] = { 1, 2, 3, 4 };
	size_t n, ttl_off;
	u16 offs[16];
	int r;

	puts("[TTL 偏移收集]");

	/* 只有一条 A：应收集到 1 个偏移，且等于我们记录的位置 */
	n = build_resp(b, 1, "example.com", 300, ip, &ttl_off);
	r = kdg_wire_collect_ttl_offs(b, n, offs, 16);
	TEQ(r, 1, "收集到 1 个偏移");
	TEQ(offs[0], ttl_off, "偏移位置正确");
	TEQ(get32(b + offs[0]), 300, "该位置确实是 TTL");

	/* 加上 OPT：OPT 的 TTL 字段**不得**被收集 */
	n = 12;
	put16(b, 1);
	put16(b + 2, 0x8180);
	put16(b + 4, 1);
	put16(b + 6, 1);
	put16(b + 8, 0);
	put16(b + 10, 1);	/* arcount = 1 */
	n += raw_name(b + n, "example.com");
	put16(b + n, 1);
	n += 2;
	put16(b + n, 1);
	n += 2;
	b[n++] = 0xC0;
	b[n++] = 0x0C;
	put16(b + n, 1);
	n += 2;
	put16(b + n, 1);
	n += 2;
	put32(b + n, 300);
	n += 4;
	put16(b + n, 4);
	n += 2;
	memcpy(b + n, ip, 4);
	n += 4;
	n = append_opt(b, n);

	r = kdg_wire_collect_ttl_offs(b, n, offs, 16);
	TEQ(r, 1, "带 OPT 时仍只收集 1 个（OPT 被跳过）");

	/* 容量不足必须报错而不是少收几个 */
	r = kdg_wire_collect_ttl_offs(b, n, offs, 0);
	TEQ(r, KDG_W_ECOUNT, "容量为 0 时报错");
}

/* ── 回包重封装 ──────────────────────────────────────────────────────── */

static void test_repack(void)
{
	u8 q[512], r[512], out[512];
	const u8 ip[4] = { 1, 2, 3, 4 };
	struct kdg_cache_tmpl t;
	size_t qn, rn, ttl_off, outlen;
	u16 offs[16];
	int cnt;

	puts("[回包重封装]");

	/* 调用方查询用**混合大小写**，模板用全小写 —— 回包必须还原调用方的大小写 */
	qn = build_query(q, 0xBEEF, "ExAmPlE.cOm", 1, KDG_DNS_F_RD);
	rn = build_resp(r, 0x0000, "example.com", 300, ip, &ttl_off);

	cnt = kdg_wire_collect_ttl_offs(r, rn, offs, 16);
	TEQ(cnt, 1, "模板 TTL 偏移收集");

	memset(&t, 0, sizeof(t));
	t.msg = r;
	t.msg_len = (u16)rn;
	t.qname_off = 12;
	t.qname_len = 13;	/* "example.com" 的 wire 长度 */
	t.ttl_offs = offs;
	t.n_ttl = 1;
	t.stored_ms = 10000;
	t.ttl_ms = 600000;

	/* 1) 刚写入：TTL 原值 */
	TEQ(kdg_cache_repack(&t, 10000, q, qn, out, sizeof(out), &outlen),
	    KDG_CRE_OK, "重封装成功");
	TEQ(outlen, rn, "长度与模板一致");
	TEQ((out[0] << 8) | out[1], 0xBEEF, "调用方 ID 已恢复");
	TEQ(get32(out + offs[0]), 300, "刚写入时 TTL 不变");
	T(memcmp(out + 12, q + 12, 13) == 0, "问题区逐字节等于调用方的（含大小写）");
	/* 首标签是 "ExAmPlE"（7 字节），其长度字节与首字符必须原样保留 */
	T(out[12] == 7 && out[13] == 'E', "首标签长度与大小写被原样保留");

	/* 2) 过了 30 秒：TTL 应减到 270 */
	TEQ(kdg_cache_repack(&t, 40000, q, qn, out, sizeof(out), &outlen),
	    KDG_CRE_OK, "30 秒后重封装成功");
	TEQ(get32(out + offs[0]), 270, "TTL 递减到 270");

	/* 3) 过了 299.9 秒（向下取整到 299）：TTL 应为 1 而非 0 */
	TEQ(kdg_cache_repack(&t, 10000 + 299999, q, qn, out, sizeof(out),
			     &outlen),
	    KDG_CRE_OK, "299.999 秒后重封装成功");
	TEQ(get32(out + offs[0]), 1, "向下取整不提前削掉一秒");

	/* 4) 过期：必须拒绝，而不是给出 TTL=0 的响应 */
	TEQ(kdg_cache_repack(&t, 10000 + 600001, q, qn, out, sizeof(out),
			     &outlen),
	    -KDG_CRE_STALE, "过期 → STALE");

	/* 5) 输出缓冲区不足 */
	TEQ(kdg_cache_repack(&t, 10000, q, qn, out, 8, &outlen),
	    -KDG_CRE_SMALL, "缓冲区不足 → SMALL");
}

static void test_repack_reject(void)
{
	u8 q[512], r[512], out[512];
	const u8 ip[4] = { 1, 2, 3, 4 };
	struct kdg_cache_tmpl t;
	size_t qn, rn, ttl_off;
	u16 offs[16];

	puts("[回包重封装 · 拒绝路径]");

	qn = build_query(q, 0x1234, "example.com", 1, KDG_DNS_F_RD);
	rn = build_resp(r, 0, "example.com", 300, ip, &ttl_off);
	kdg_wire_collect_ttl_offs(r, rn, offs, 16);

	memset(&t, 0, sizeof(t));
	t.msg = r;
	t.msg_len = (u16)rn;
	t.qname_off = 12;
	t.qname_len = 13;
	t.ttl_offs = offs;
	t.n_ttl = 1;
	t.stored_ms = 1000;
	t.ttl_ms = 60000;

	/* 调用方问题区长度不符（用另一个域名） */
	{
		u8 q2[512];
		size_t q2n = build_query(q2, 1, "other.org", 1, KDG_DNS_F_RD);

		TEQ(kdg_cache_repack(&t, 1000, q2, q2n, out, sizeof(out),
				     (size_t[]){ 0 }),
		    -KDG_CRE_PACK, "问题区长度不符 → PACK");
	}

	/* 调用方问题区被压缩（放一个压缩指针）——必须拒绝，不能把指针当名字写 */
	{
		u8 q3[64];

		memcpy(q3, q, 12);
		q3[12] = 0xC0;
		q3[13] = 0x0C;
		q3[14] = 0;
		q3[15] = 1;
		q3[16] = 0;
		q3[17] = 1;
		TEQ(kdg_cache_repack(&t, 1000, q3, 18, out, sizeof(out),
				     (size_t[]){ 0 }),
		    -KDG_CRE_PACK, "调用方问题区压缩 → PACK");
	}

	/* 模板自称问题区被压缩 —— 缓存项被破坏时也要拦住 */
	{
		u8 bad[512];

		memcpy(bad, r, rn);
		bad[12] = 0xC0;
		t.msg = bad;
		TEQ(kdg_cache_repack(&t, 1000, q, qn, out, sizeof(out),
				     (size_t[]){ 0 }),
		    -KDG_CRE_PACK, "模板问题区压缩 → PACK");
		t.msg = r;
	}

	/* NULL 参数 */
	TEQ(kdg_cache_repack(NULL, 0, q, qn, out, sizeof(out), (size_t[]){ 0 }),
	    -KDG_CRE_BADARG, "NULL 模板 → BADARG");
}

static void test_invariants(void)
{
	struct kdg_cache_key a, b;
	u8 q[512];
	size_t n;
	struct kdg_query pq;
	unsigned int seed = 424242u;
	int i;

	puts("[结构性不变量]");

	/* 键比较必须自反且对哈希一致 */
	n = build_query(q, 1, "example.com", 1, KDG_DNS_F_RD);
	kdg_wire_parse_query(q, n, &pq);
	kdg_cache_key_from_query(&pq, 0, 1, &a);

	T(kdg_cache_key_eq(&a, &a), "自反");
	b = a;
	T(kdg_cache_key_eq(&a, &b), "副本相等");
	TEQ(kdg_cache_key_hash(&a), kdg_cache_key_hash(&b), "副本哈希相等");

	/* 随机键：相等蕴含哈希相等（哈希表正确性的必要条件） */
	for (i = 0; i < 20000; i++) {
		unsigned int j;

		seed = seed * 1103515245u + 12345u;
		b = a;
		for (j = 0; j < sizeof(b.qname) && j < 8; j++) {
			seed = seed * 1103515245u + 12345u;
			b.qname[j] = (u8)(seed >> 16);
		}
		seed = seed * 1103515245u + 12345u;
		b.qname_len = (u16)(seed % 32);
		seed = seed * 1103515245u + 12345u;
		b.qtype = (u16)seed;
		seed = seed * 1103515245u + 12345u;
		b.flags = (u8)seed;

		if (kdg_cache_key_eq(&a, &b)) {
			if (kdg_cache_key_hash(&a) != kdg_cache_key_hash(&b)) {
				g_fail++;
				printf("  FAIL 相等的键哈希不等 (i=%d)\n", i);
				goto done;
			}
		}
	}
	g_pass++;
done:
	;

	/* 重封装：任意输出容量都不得越界（ASan 会抓） */
	{
		u8 r2[512], out[512];
		size_t rn2, ttl_off;
		const u8 ip[4] = { 8, 8, 8, 8 };
		struct kdg_cache_tmpl t;
		u16 offs[16];
		size_t cap;

		n = build_query(q, 1, "example.com", 1, KDG_DNS_F_RD);
		rn2 = build_resp(r2, 0, "example.com", 300, ip, &ttl_off);
		kdg_wire_collect_ttl_offs(r2, rn2, offs, 16);
		memset(&t, 0, sizeof(t));
		t.msg = r2;
		t.msg_len = (u16)rn2;
		t.qname_off = 12;
		t.qname_len = 13;
		t.ttl_offs = offs;
		t.n_ttl = 1;
		t.stored_ms = 0;
		t.ttl_ms = 100000;

		for (cap = 0; cap <= rn2 + 8; cap++) {
			size_t ol;

			(void)kdg_cache_repack(&t, 0, q, n, out, cap, &ol);
		}
		g_pass++;
	}
}

int main(void)
{
	puts("=== kdg_cache 语料测试 ===");

	test_key();
	test_key_reject();
	test_fresh();
	test_ttl_offs();
	test_repack();
	test_repack_reject();
	test_invariants();

	printf("\n=== 通过 %d / 失败 %d ===\n", g_pass, g_fail);
	return g_fail ? 1 : 0;
}
