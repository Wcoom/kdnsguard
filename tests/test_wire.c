/* SPDX-License-Identifier: GPL-2.0 */
/*
 * test_wire.c —— kdg_wire 的宿主侧语料测试。
 *
 * 为什么不在内核里跑 KUnit：本树 CONFIG_KUNIT=m，而 lib/kunit/Kconfig 要求
 * KUNIT=y 才会编入用例，设备构建里这些用例根本不会被编译。DNS 边界代码
 * 的价值完全取决于畸形输入的覆盖度，所以主战场必须放在宿主。
 *
 * 构建（见 Makefile）默认带 -fsanitize=address,undefined：越界读、整数溢出、
 * 未对齐访问都会当场炸出来，而不是等到真机上一个罕见的 DNS 报文触发。
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "kdg_wire.h"

static int g_pass, g_fail;

#define T(cond, name) do {						\
	if (cond) {							\
		g_pass++;						\
	} else {							\
		g_fail++;						\
		printf("  FAIL %-46s (line %d)\n", name, __LINE__);	\
	}								\
} while (0)

#define TEQ(expr, want, name) do {					\
	long _g = (long)(expr), _w = (long)(want);			\
	if (_g == _w) {							\
		g_pass++;						\
	} else {							\
		g_fail++;						\
		printf("  FAIL %-46s got=%ld want=%ld (line %d)\n",	\
		       name, _g, _w, __LINE__);				\
	}								\
} while (0)

/* ── 独立的报文构造器 ─────────────────────────────────────────────────
 * 刻意**不调用** kdg_wire_dname_from_text，避免用被测代码构造测试数据
 * 造成循环验证。 */
static size_t raw_name(u8 *p, const char *text)
{
	const char *s = text;
	size_t o = 0;

	if (strcmp(text, ".") == 0) {
		p[0] = 0;
		return 1;
	}
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

static void put_hdr(u8 *b, u16 id, u16 flags, u16 qd, u16 an, u16 ns, u16 ar)
{
	put16(b, id);
	put16(b + 2, flags);
	put16(b + 4, qd);
	put16(b + 6, an);
	put16(b + 8, ns);
	put16(b + 10, ar);
}

/* 构造一个标准查询：example.com A IN，可选附加 RR 段。 */
static size_t build_query(u8 *b, u16 id, u16 flags, const char *name,
			  u16 qtype)
{
	size_t n = KDG_DNS_HDR_LEN;

	put_hdr(b, id, flags, 1, 0, 0, 0);
	n += raw_name(b + n, name);
	put16(b + n, qtype);
	n += 2;
	put16(b + n, KDG_RRCLASS_IN);
	n += 2;
	return n;
}

/* 追加一个 OPT 伪记录（EDNS0）。opts 为已编码的选项区，optslen 为其字节数。
 * ext_rcode 占 TTL 字段的 bit31-24，DO 位在 bit15 —— OPT 的 TTL 字段不是
 * 生存时间，这一点必须由构造器如实反映，否则测的就不是真实编码。 */
static size_t append_opt(u8 *b, size_t n, u16 udp_size, u8 ext_rcode,
			 bool do_bit, const u8 *opts, size_t optslen)
{
	u32 ttl = ((u32)ext_rcode << 24) | (do_bit ? 0x8000u : 0u);

	b[n++] = 0;			/* owner = root */
	put16(b + n, KDG_RRTYPE_OPT);
	n += 2;
	put16(b + n, udp_size);		/* class 字段承载 UDP 载荷大小 */
	n += 2;
	put32(b + n, ttl);
	n += 4;
	put16(b + n, (u16)optslen);
	n += 2;
	if (optslen) {
		memcpy(b + n, opts, optslen);
		n += optslen;
	}
	return n;
}

/* 追加一条 answer，owner 用指向报文开头域名的压缩指针。 */
static size_t append_a_answer(u8 *b, size_t n, u16 ttl, const u8 ip[4])
{
	b[n++] = 0xC0;
	b[n++] = 0x0C;			/* -> offset 12，即问题区的名字 */
	put16(b + n, KDG_RRTYPE_A);
	n += 2;
	put16(b + n, KDG_RRCLASS_IN);
	n += 2;
	put32(b + n, ttl);
	n += 4;
	put16(b + n, 4);
	n += 2;
	memcpy(b + n, ip, 4);
	return n + 4;
}

/* 追加一条 SOA（authority），rdata 内的两个名字按未压缩形式写出。 */
static size_t append_soa(u8 *b, size_t n, u32 ttl, u32 minimum)
{
	size_t rdlen_at;
	size_t rd_start;

	b[n++] = 0xC0;
	b[n++] = 0x0C;
	put16(b + n, KDG_RRTYPE_SOA);
	n += 2;
	put16(b + n, KDG_RRCLASS_IN);
	n += 2;
	put32(b + n, ttl);
	n += 4;
	rdlen_at = n;
	n += 2;				/* rdlen 占位，稍后回填 */
	rd_start = n;

	n += raw_name(b + n, "ns1.example.com");
	n += raw_name(b + n, "hostmaster.example.com");
	put32(b + n, 2026100301u);	/* SERIAL */
	n += 4;
	put32(b + n, 7200);		/* REFRESH */
	n += 4;
	put32(b + n, 3600);		/* RETRY */
	n += 4;
	put32(b + n, 1209600);		/* EXPIRE */
	n += 4;
	put32(b + n, minimum);		/* MINIMUM */
	n += 4;

	put16(b + rdlen_at, (u16)(n - rd_start));
	return n;
}

/* ── 查询解析 ─────────────────────────────────────────────────────────── */

static void test_query_ok(void)
{
	u8 b[512];
	size_t n;
	struct kdg_query q;
	char text[256];

	puts("[查询解析 · 正常路径]");

	n = build_query(b, 0x1234, KDG_DNS_F_RD, "example.com", KDG_RRTYPE_A);
	TEQ(kdg_wire_parse_query(b, n, &q), KDG_W_OK, "example.com A 解析成功");
	TEQ(q.id, 0x1234, "DNS ID 保真");
	TEQ(q.qtype, KDG_RRTYPE_A, "qtype");
	TEQ(q.qclass, KDG_RRCLASS_IN, "qclass");
	TEQ(q.opcode, KDG_DNS_OPCODE_QUERY, "opcode");
	TEQ(q.qname.nlabels, 2, "标签数");
	TEQ(kdg_wire_dname_to_text(&q.qname, text, sizeof(text)), 11, "文本长度");
	T(strcmp(text, "example.com") == 0, "文本形式一致");
	T(!q.has_edns, "无 EDNS");

	/* 大写必须被规范化为小写，否则缓存键会分裂成两份 */
	n = build_query(b, 1, KDG_DNS_F_RD, "ExAmPlE.CoM", KDG_RRTYPE_A);
	TEQ(kdg_wire_parse_query(b, n, &q), KDG_W_OK, "大写查询解析成功");
	TEQ(kdg_wire_dname_to_text(&q.qname, text, sizeof(text)), 11, "大写→小写");
	T(strcmp(text, "example.com") == 0, "大小写折叠为同一键");

	/* 根查询 */
	n = build_query(b, 2, KDG_DNS_F_RD, ".", KDG_RRTYPE_NS);
	TEQ(kdg_wire_parse_query(b, n, &q), KDG_W_OK, "根查询解析成功");
	TEQ(q.qname.len, 1, "根名字 wire 长度 1");
	TEQ(q.qname.nlabels, 0, "根无标签");
}

static void test_query_edns(void)
{
	u8 b[512];
	u8 opts[16];
	size_t n, olen = 0;
	struct kdg_query q;

	puts("[查询解析 · EDNS0]");

	n = build_query(b, 3, KDG_DNS_F_RD, "example.com", KDG_RRTYPE_A);
	/* OPT：udp_size=1232，版本 0，DO 位置 1 */
	n = append_opt(b, n, 1232, 0, true, NULL, 0);
	put16(b + 10, 1);		/* arcount = 1 */
	TEQ(kdg_wire_parse_query(b, n, &q), KDG_W_OK, "带 OPT 的查询解析成功");
	T(q.has_edns, "has_edns");
	TEQ(q.edns_udp_size, 1232, "UDP 载荷大小取自 class 字段");
	T(q.edns_do, "DO 位被识别");
	T(!q.edns_badvers, "版本 0 不是 BADVERS");
	T(!q.edns_has_ecs, "无 ECS");

	/* 加一个 ECS 选项（code=8），它会让该请求不可跨调用方合并 */
	put16(opts + olen, KDG_EDNS_OPT_ECS);
	olen += 2;
	put16(opts + olen, 7);		/* optlen */
	olen += 2;
	memset(opts + olen, 0xAB, 7);
	olen += 7;

	n = build_query(b, 4, KDG_DNS_F_RD, "example.com", KDG_RRTYPE_A);
	n = append_opt(b, n, 1232, 0, false, opts, olen);
	put16(b + 10, 1);
	TEQ(kdg_wire_parse_query(b, n, &q), KDG_W_OK, "带 ECS 的查询解析成功");
	T(q.edns_has_ecs, "ECS 被识别（决定不参与合并）");
}

static void test_query_reject(void)
{
	u8 b[512] = { 0 };
	size_t n;
	struct kdg_query q;

	puts("[查询解析 · 畸形与恶意输入]");

	TEQ(kdg_wire_parse_query(b, 0, &q), KDG_W_ETRUNC, "空报文");
	TEQ(kdg_wire_parse_query(b, 11, &q), KDG_W_ETRUNC, "不足 12 字节 header");

	n = build_query(b, 1, KDG_DNS_F_RD, "example.com", KDG_RRTYPE_A);
	TEQ(kdg_wire_parse_query(b, n - 6, &q), KDG_W_ETRUNC, "名字被截断");

	/* 多问题域：RFC 9619 已废弃，本模块不做多问题解析 */
	n = build_query(b, 1, KDG_DNS_F_RD, "example.com", KDG_RRTYPE_A);
	put16(b + 4, 2);
	TEQ(kdg_wire_parse_query(b, n, &q), KDG_W_ECOUNT, "qdcount=2 被拒绝");
	put16(b + 4, 0);
	TEQ(kdg_wire_parse_query(b, n, &q), KDG_W_ECOUNT, "qdcount=0 被拒绝");

	/* QR=1：这是响应，不是查询 */
	n = build_query(b, 1, KDG_DNS_F_QR | KDG_DNS_F_RD, "example.com",
			KDG_RRTYPE_A);
	TEQ(kdg_wire_parse_query(b, n, &q), KDG_W_EFORMAT, "QR=1 被拒绝");

	/* opcode != QUERY */
	n = build_query(b, 1, (u16)(KDG_DNS_OPCODE_UPDATE << 11),
			"example.com", KDG_RRTYPE_A);
	TEQ(kdg_wire_parse_query(b, n, &q), KDG_W_ENOTSUP, "UPDATE opcode 拒绝");

	/* 查询携带 answer 段 */
	n = build_query(b, 1, KDG_DNS_F_RD, "example.com", KDG_RRTYPE_A);
	put16(b + 6, 1);
	TEQ(kdg_wire_parse_query(b, n, &q), KDG_W_ECOUNT, "查询带 ancount 被拒绝");
}

static void test_compression_pointers(void)
{
	u8 b[512];
	size_t n;
	struct kdg_query q;

	puts("[查询解析 · 压缩指针（安全核心）]");

	/* 自环：偏移 12 处的指针指向 12 自己 */
	n = KDG_DNS_HDR_LEN;
	put_hdr(b, 1, KDG_DNS_F_RD, 1, 0, 0, 0);
	b[n++] = 0xC0;
	b[n++] = 0x0C;
	put16(b + n, 1);
	n += 2;
	put16(b + n, 1);
	n += 2;
	TEQ(kdg_wire_parse_query(b, n, &q), KDG_W_ELOOP, "自环指针被拒绝");

	/* 前向指针：偏移 12 指向偏移 16。报文总长 18，故目标**在报文内**，
	 * 这样才测得到「非合规前向指针」而不是「越界」——两者错误码不同。 */
	n = KDG_DNS_HDR_LEN;
	put_hdr(b, 1, KDG_DNS_F_RD, 1, 0, 0, 0);
	b[n++] = 0xC0;
	b[n++] = 0x10;			/* 12 -> 16，位于报文内但方向向前 */
	put16(b + n, 1);
	n += 2;
	put16(b + n, 1);
	n += 2;
	TEQ(kdg_wire_parse_query(b, n, &q), KDG_W_ELOOP, "前向指针被拒绝");

	/* 互环：12 -> 14，14 -> 12。因为强制严格回指，第一跳就被判死 */
	n = KDG_DNS_HDR_LEN;
	put_hdr(b, 1, KDG_DNS_F_RD, 1, 0, 0, 0);
	b[n++] = 0xC0;
	b[n++] = 0x0E;			/* 12 -> 14 */
	b[n++] = 0xC0;
	b[n++] = 0x0C;			/* 14 -> 12 */
	put16(b + n, 1);
	n += 2;
	put16(b + n, 1);
	n += 2;
	TEQ(kdg_wire_parse_query(b, n, &q), KDG_W_ELOOP, "互环指针被拒绝");

	/* 指针指向报文之外 */
	n = KDG_DNS_HDR_LEN;
	put_hdr(b, 1, KDG_DNS_F_RD, 1, 0, 0, 0);
	b[n++] = 0xC0;
	b[n++] = 0xFF;			/* 指向 255，超出实际报文 */
	put16(b + n, 1);
	n += 2;
	put16(b + n, 1);
	n += 2;
	TEQ(kdg_wire_parse_query(b, n, &q), KDG_W_ETRUNC, "越界指针被拒绝");

	/* 0x40 / 0x80 前缀未定义，必须拒绝而不是当作标签长度 */
	n = KDG_DNS_HDR_LEN;
	put_hdr(b, 1, KDG_DNS_F_RD, 1, 0, 0, 0);
	b[n++] = 0x40;
	b[n++] = 'a';
	put16(b + n, 1);
	n += 2;
	put16(b + n, 1);
	n += 2;
	TEQ(kdg_wire_parse_query(b, n, &q), KDG_W_EFORMAT, "保留前缀 0x40 被拒绝");
}

static void test_name_too_long(void)
{
	u8 b[1024];
	size_t n;
	struct kdg_query q;
	int i;

	puts("[查询解析 · 长度上限]");

	/* 4 个 63 字节标签 = 4*(1+63) = 256 > 255，必须拒绝 */
	n = KDG_DNS_HDR_LEN;
	put_hdr(b, 1, KDG_DNS_F_RD, 1, 0, 0, 0);
	for (i = 0; i < 4; i++) {
		int j;

		b[n++] = 63;
		for (j = 0; j < 63; j++)
			b[n++] = 'a';
	}
	b[n++] = 0;
	put16(b + n, 1);
	n += 2;
	put16(b + n, 1);
	n += 2;
	TEQ(kdg_wire_parse_query(b, n, &q), KDG_W_ELEN, "名字超 255 字节被拒绝");

	/* 3 个 63 字节标签 = 192+1 = 193，合法 */
	n = KDG_DNS_HDR_LEN;
	put_hdr(b, 1, KDG_DNS_F_RD, 1, 0, 0, 0);
	for (i = 0; i < 3; i++) {
		int j;

		b[n++] = 63;
		for (j = 0; j < 63; j++)
			b[n++] = 'a';
	}
	b[n++] = 0;
	put16(b + n, 1);
	n += 2;
	put16(b + n, 1);
	n += 2;
	TEQ(kdg_wire_parse_query(b, n, &q), KDG_W_OK, "193 字节名字合法");
	TEQ(q.qname.nlabels, 3, "3 个标签");
}

/* ── 响应解析 ─────────────────────────────────────────────────────────── */

static size_t build_resp_a(u8 *b, u16 id, u16 ttl, const u8 ip[4])
{
	size_t n;

	put_hdr(b, id, KDG_DNS_F_QR | KDG_DNS_F_RD | KDG_DNS_F_RA, 1, 1, 0, 0);
	n = KDG_DNS_HDR_LEN;
	n += raw_name(b + n, "example.com");
	put16(b + n, KDG_RRTYPE_A);
	n += 2;
	put16(b + n, KDG_RRCLASS_IN);
	n += 2;
	return append_a_answer(b, n, ttl, ip);
}

static void test_response_ok(void)
{
	u8 b[512];
	const u8 ip[4] = { 1, 2, 3, 4 };
	size_t n;
	struct kdg_summary s;

	puts("[响应解析 · 正常应答]");

	n = build_resp_a(b, 0x1234, 300, ip);
	TEQ(kdg_wire_parse_response(b, n, &s), KDG_W_OK, "A 响应解析成功");
	T(s.qr, "QR=1");
	T(s.ra, "RA=1");
	TEQ(s.rcode, KDG_RCODE_NOERROR, "NOERROR");
	TEQ(s.ancount, 1, "ancount");
	TEQ(s.counted_an, 1, "实际走到 1 条 answer");
	TEQ(s.min_ttl, 300, "min_ttl");
	T(!s.tc, "未截断");
	T(!s.is_nxdomain, "非 NXDOMAIN");
	T(!s.is_nodata, "非 NODATA");
	TEQ(kdg_wire_cacheable_ttl(&s, true), 300, "可缓存 300 秒");
}

static void test_response_negative(void)
{
	u8 b[1024];
	size_t n;
	struct kdg_summary s;

	puts("[响应解析 · 否定应答（区分 NXDOMAIN / NODATA）]");

	/* NXDOMAIN：rcode=3，authority 带 SOA，SOA MINIMUM=60 */
	put_hdr(b, 0x1234, KDG_DNS_F_QR | KDG_DNS_F_RD | KDG_DNS_F_RA | 3, 1, 0, 1, 0);
	n = KDG_DNS_HDR_LEN;
	n += raw_name(b + n, "nope.example.com");
	put16(b + n, KDG_RRTYPE_A);
	n += 2;
	put16(b + n, KDG_RRCLASS_IN);
	n += 2;
	n = append_soa(b, n, 3600, 60);
	TEQ(kdg_wire_parse_response(b, n, &s), KDG_W_OK, "NXDOMAIN 解析成功");
	T(s.is_nxdomain, "被识别为 NXDOMAIN");
	T(s.has_soa, "SOA 被提取");
	TEQ(s.soa_ttl, 3600, "SOA 自身 TTL");
	TEQ(s.soa_minimum, 60, "SOA MINIMUM 字段");
	/* RFC 2308：负缓存 TTL = min(SOA TTL, MINIMUM) */
	TEQ(kdg_wire_cacheable_ttl(&s, true), 60, "负缓存 TTL = min(TTL,MINIMUM)");
	TEQ(kdg_wire_cacheable_ttl(&s, false), 0, "不允许负缓存时为 0");

	/* NODATA：NOERROR + 答案区空 + authority 带 SOA */
	put_hdr(b, 0x1234, KDG_DNS_F_QR | KDG_DNS_F_RD | KDG_DNS_F_RA, 1, 0, 1, 0);
	n = KDG_DNS_HDR_LEN;
	n += raw_name(b + n, "empty.example.com");
	put16(b + n, KDG_RRTYPE_AAAA);
	n += 2;
	put16(b + n, KDG_RRCLASS_IN);
	n += 2;
	n = append_soa(b, n, 1800, 30);
	TEQ(kdg_wire_parse_response(b, n, &s), KDG_W_OK, "NODATA 解析成功");
	T(!s.is_nxdomain, "NODATA 不是 NXDOMAIN");
	T(s.is_nodata, "被识别为 NODATA");
	TEQ(kdg_wire_cacheable_ttl(&s, true), 30, "NODATA 负缓存 TTL");
}

static void test_response_opt_ttl(void)
{
	u8 b[512];
	const u8 ip[4] = { 8, 8, 4, 4 };
	size_t n;
	struct kdg_summary s;

	puts("[响应解析 · OPT 的 TTL 字段不是 TTL]");

	/* answer TTL=900，但 OPT 的 TTL 字段写成一个很大的值。
	 * 若把 OPT 当普通 RR，min_ttl 会被污染——这正是 §8 点名的陷阱。 */
	n = KDG_DNS_HDR_LEN;
	put_hdr(b, 0x1234, KDG_DNS_F_QR | KDG_DNS_F_RD | KDG_DNS_F_RA, 1, 1, 0, 1);
	n += raw_name(b + n, "example.com");
	put16(b + n, KDG_RRTYPE_A);
	n += 2;
	put16(b + n, KDG_RRCLASS_IN);
	n += 2;
	n = append_a_answer(b, n, 900, ip);
	n = append_opt(b, n, 4096, 0, false, NULL, 0);
	TEQ(kdg_wire_parse_response(b, n, &s), KDG_W_OK, "带 OPT 的响应解析成功");
	T(s.has_edns, "has_edns");
	TEQ(s.edns_udp_size, 4096, "对端 UDP 载荷上限");
	TEQ(s.min_ttl, 900, "min_ttl 只取非 OPT 记录");
	TEQ(kdg_wire_cacheable_ttl(&s, true), 900, "缓存 TTL 不被 OPT 污染");
}

static void test_response_reject(void)
{
	u8 b[512];
	const u8 ip[4] = { 1, 2, 3, 4 };
	size_t n;
	struct kdg_summary s;

	puts("[响应解析 · 拒绝路径]");

	/* 声明 ancount=2 但只给 1 条 */
	n = build_resp_a(b, 1, 300, ip);
	put16(b + 6, 2);
	TEQ(kdg_wire_parse_response(b, n, &s), KDG_W_ETRUNC,
	    "计数多于实际内容被拒绝");

	/* 声明 ancount=0 但实际有内容：walker 只走声明条数，多余字节被容忍，
	 * 但 min_ttl 不会看到那条记录——这里验证解析仍成功且 min_ttl=0 */
	n = build_resp_a(b, 1, 300, ip);
	put16(b + 6, 0);
	TEQ(kdg_wire_parse_response(b, n, &s), KDG_W_OK, "少报计数可解析");
	TEQ(s.min_ttl, 0, "未走到的记录不贡献 TTL");

	/* 非响应（QR=0）喂给响应解析器 */
	n = build_query(b, 1, KDG_DNS_F_RD, "example.com", KDG_RRTYPE_A);
	TEQ(kdg_wire_parse_response(b, n, &s), KDG_W_EFORMAT, "QR=0 被拒绝");
}

static void test_cache_policy(void)
{
	u8 b[512];
	const u8 ip[4] = { 1, 2, 3, 4 };
	size_t n;
	struct kdg_summary s;

	puts("[缓存策略]");

	/* TTL=0：语义是「仅本次使用」，不得进缓存 */
	n = build_resp_a(b, 1, 0, ip);
	kdg_wire_parse_response(b, n, &s);
	TEQ(kdg_wire_cacheable_ttl(&s, true), 0, "TTL=0 不缓存");

	/* SERVFAIL：绝不当作 NXDOMAIN 缓存 */
	n = build_resp_a(b, 1, 300, ip);
	put16(b + 2, KDG_DNS_F_QR | KDG_DNS_F_RD | KDG_DNS_F_RA |
	      KDG_RCODE_SERVFAIL);
	kdg_wire_parse_response(b, n, &s);
	TEQ(kdg_wire_cacheable_ttl(&s, true), 0, "SERVFAIL 不缓存");

	/* 截断响应：语义不完整 */
	n = build_resp_a(b, 1, 300, ip);
	put16(b + 2, KDG_DNS_F_QR | KDG_DNS_F_RD | KDG_DNS_F_RA | KDG_DNS_F_TC);
	kdg_wire_parse_response(b, n, &s);
	T(s.tc, "TC 位被识别");
	TEQ(kdg_wire_cacheable_ttl(&s, true), 0, "截断响应不缓存");

	/* NXDOMAIN 但没有 SOA：无法确定负缓存时长 */
	put_hdr(b, 1, KDG_DNS_F_QR | KDG_DNS_F_RD | KDG_DNS_F_RA | 3, 1, 0, 0, 0);
	n = KDG_DNS_HDR_LEN;
	n += raw_name(b + n, "nope.example.com");
	put16(b + n, KDG_RRTYPE_A);
	n += 2;
	put16(b + n, KDG_RRCLASS_IN);
	n += 2;
	kdg_wire_parse_response(b, n, &s);
	T(s.is_nxdomain, "NXDOMAIN");
	T(!s.has_soa, "无 SOA");
	TEQ(kdg_wire_cacheable_ttl(&s, true), 0, "无 SOA 的 NXDOMAIN 不缓存");
}

/* ── 响应与请求匹配 ───────────────────────────────────────────────────── */

static void test_match(void)
{
	u8 q[512], r[512];
	const u8 ip[4] = { 1, 2, 3, 4 };
	size_t qn, rn;
	struct kdg_summary s;

	puts("[响应匹配]");

	qn = build_query(q, 0x1234, KDG_DNS_F_RD, "example.com", KDG_RRTYPE_A);
	rn = build_resp_a(r, 0x1234, 300, ip);
	TEQ(kdg_wire_match_response(q, qn, r, rn, &s), KDG_W_OK, "正常匹配");

	/* ID 不符 —— 这是「拒绝跨上游身份跳转」的关键判据 */
	rn = build_resp_a(r, 0x9999, 300, ip);
	TEQ(kdg_wire_match_response(q, qn, r, rn, &s), KDG_W_EMISMATCH, "ID 不符");

	/* qname 不符 */
	rn = KDG_DNS_HDR_LEN;
	put_hdr(r, 0x1234, KDG_DNS_F_QR | KDG_DNS_F_RD | KDG_DNS_F_RA, 1, 1, 0, 0);
	rn += raw_name(r + rn, "attacker.example.net");
	put16(r + rn, KDG_RRTYPE_A);
	rn += 2;
	put16(r + rn, KDG_RRCLASS_IN);
	rn += 2;
	rn = append_a_answer(r, rn, 300, ip);
	TEQ(kdg_wire_match_response(q, qn, r, rn, &s), KDG_W_EMISMATCH,
	    "qname 不符");

	/* qtype 不符 */
	rn = build_resp_a(r, 0x1234, 300, ip);
	put16(r + KDG_DNS_HDR_LEN + 13, KDG_RRTYPE_AAAA);
	TEQ(kdg_wire_match_response(q, qn, r, rn, &s), KDG_W_EMISMATCH,
	    "qtype 不符");
}

/* ── 域名文本互转 ─────────────────────────────────────────────────────── */

static void test_dname_text(void)
{
	struct kdg_dname n;
	char text[300];
	char longlabel[300];

	puts("[域名文本互转]");

	TEQ(kdg_wire_dname_from_text("example.com", 11, &n), KDG_W_OK, "普通域名");
	TEQ(n.nlabels, 2, "标签数");
	TEQ(kdg_wire_dname_to_text(&n, text, sizeof(text)), 11, "往返长度");
	T(strcmp(text, "example.com") == 0, "往返一致");

	TEQ(kdg_wire_dname_from_text(".", 1, &n), KDG_W_OK, "根");
	TEQ(kdg_wire_dname_to_text(&n, text, sizeof(text)), 1, "根往返长度");
	T(strcmp(text, ".") == 0, "根往返一致");

	/* 尾部单点等价于不带点 */
	TEQ(kdg_wire_dname_from_text("example.com.", 12, &n), KDG_W_OK,
	    "尾部单点被接受");
	T(strcmp(text, "example.com") == 0 ||
	  kdg_wire_dname_to_text(&n, text, sizeof(text)) == 11,
	  "尾部单点规范化");

	TEQ(kdg_wire_dname_from_text("", 0, &n), KDG_W_ELEN, "空串被拒绝");
	TEQ(kdg_wire_dname_from_text("a..b", 4, &n), KDG_W_ELEN, "空标签被拒绝");

	/* 标签正好 63 合法，64 非法 */
	memset(longlabel, 'a', 63);
	longlabel[63] = '\0';
	TEQ(kdg_wire_dname_from_text(longlabel, 63, &n), KDG_W_OK, "63 字节标签合法");
	longlabel[63] = 'a';
	longlabel[64] = '\0';
	TEQ(kdg_wire_dname_from_text(longlabel, 64, &n), KDG_W_ELEN,
	    "64 字节标签被拒绝");

	/* 缓冲区太小时必须报错而不是截断 */
	TEQ(kdg_wire_dname_from_text("example.com", 11, &n), KDG_W_OK, "重建");
	TEQ(kdg_wire_dname_to_text(&n, text, 5), KDG_W_EBOUNDS, "小缓冲区报错");
}

/* ── 结构性不变量 ─────────────────────────────────────────────────────── */

static void test_invariants(void)
{
	u8 b[512];
	size_t n;
	struct kdg_query q;
	struct kdg_summary s;
	unsigned int seed = 12345;
	int i;

	puts("[结构性不变量 · 截断前缀不越界]");

	/* 对同一份合法报文，逐个长度前缀全部喂进解析器。任何长度都不允许
	 * 崩、不允许 ASan 报越界；结果只允许是 OK 或某个 KDG_W_E*。 */
	n = build_query(b, 1, KDG_DNS_F_RD, "example.com", KDG_RRTYPE_A);
	for (i = 0; i <= (int)n + 8; i++) {
		int r = kdg_wire_parse_query(b, (size_t)i, &q);

		if (r != KDG_W_OK && r > 0) {
			g_fail++;
			printf("  FAIL 前缀 %d 返回了非错误码 %d\n", i, r);
		}
	}
	g_pass++;

	/* 随机字节流：只要不越界、不挂死、不返回正整数即可 */
	for (i = 0; i < 20000; i++) {
		u8 rnd[64];
		size_t len;
		unsigned int j;

		seed = seed * 1103515245u + 12345u;
		len = seed % sizeof(rnd);
		for (j = 0; j < len; j++) {
			seed = seed * 1103515245u + 12345u;
			rnd[j] = (u8)(seed >> 16);
		}
		(void)kdg_wire_parse_query(rnd, len, &q);
		(void)kdg_wire_parse_response(rnd, len, &s);
	}
	g_pass++;
}

/* ── 失败应答构造（方案 §18：严格模式必须明确失败，不能静默丢包）────── */
static void test_error_response(void)
{
	u8 q[512], r[512];
	size_t qn, rn;
	struct kdg_summary s;

	puts("[失败应答]");

	qn = build_query(q, 0x1234, KDG_DNS_F_RD, "example.com", KDG_RRTYPE_A);

	/* 基本形态：ID / question 原样，QR=1，rcode=SERVFAIL，其余计数为 0 */
	rn = sizeof(r);
	TEQ(kdg_wire_make_error_response(q, qn, KDG_RCODE_SERVFAIL, r, rn, &rn),
	    KDG_W_OK, "构造成功");
	TEQ(r[0], 0x12, "ID 高字节逐字节保留");
	TEQ(r[1], 0x34, "ID 低字节逐字节保留");
	T((r[2] & 0x80) != 0, "QR=1");
	TEQ(r[3] & 0x0f, KDG_RCODE_SERVFAIL, "rcode=SERVFAIL");
	TEQ(r[4], 0, "ANCOUNT 高字节=0");
	TEQ(r[5], 1, "QDCOUNT=1");
	TEQ(r[6], 0, "ANCOUNT=0");
	TEQ(r[8], 0, "NSCOUNT=0");
	TEQ(r[10], 0, "ARCOUNT=0");
	/* flags 的两个字节各自承载哪些位要写清楚，否则很容易把 RD 写成 r[3]：
	 *   高字节 r[2]：QR(0x80) opcode(0x78) AA(0x04) TC(0x02) RD(0x01)
	 *   低字节 r[3]：RA(0x80) Z(0x40) AD(0x20) CD(0x10) RCODE(0x0f) */
	T(r[2] & 0x01, "RD 位保留");
	T(!(r[2] & 0x02), "TC 清零");
	T(!(r[2] & 0x04), "AA 清零");
	T(!(r[3] & 0x80), "RA 清零");
	T(!(r[3] & 0x20), "AD 清零（绝不伪造安全状态）");
	TEQ(rn, KDG_DNS_HDR_LEN + qn - KDG_DNS_HDR_LEN, "长度=header+question");
	TEQ(memcmp(r + KDG_DNS_HDR_LEN, q + KDG_DNS_HDR_LEN,
		   qn - KDG_DNS_HDR_LEN), 0, "问题区逐字节一致");

	/* 产物必须是可被自家解析器接受的合法响应 */
	TEQ(kdg_wire_parse_response(r, rn, &s), KDG_W_OK, "产物可解析");
	TEQ(s.rcode, KDG_RCODE_SERVFAIL, "解析出的 rcode 正确");
	TEQ(s.id, 0x1234, "解析出的 ID 正确");
	T(s.qr, "解析出的 QR=1");
	T(s.question_ok, "question 段完整");
	TEQ(s.ancount, 0, "无答案");

	/* 请求带 AD 时也必须清掉：AD 是「已验证」的声明，不是可继承的位 */
	qn = build_query(q, 0xbeef, KDG_DNS_F_RD | KDG_DNS_F_AD, "a.example",
			 KDG_RRTYPE_AAAA);
	rn = sizeof(r);
	TEQ(kdg_wire_make_error_response(q, qn, KDG_RCODE_SERVFAIL, r, rn, &rn),
	    KDG_W_OK, "带 AD 的请求也能构造");
	T(!(r[3] & 0x20), "请求带 AD 也要清掉");

	/* CD 是调用方语义，要保留 */
	qn = build_query(q, 0x0001, KDG_DNS_F_CD, "b.example", KDG_RRTYPE_A);
	rn = sizeof(r);
	TEQ(kdg_wire_make_error_response(q, qn, KDG_RCODE_FORMERR, r, rn, &rn),
	    KDG_W_OK, "FORMERR 构造");
	T(r[3] & 0x10, "CD 位保留");
	TEQ(r[3] & 0x0f, KDG_RCODE_FORMERR, "rcode=FORMERR");

	/* 畸形请求：header 合法但问题区坏掉 → 仍然回一个应答（QDCOUNT=0），
	 * 而不是无声丢弃。 */
	memset(q, 0, sizeof(q));
	put_hdr(q, 0x2222, KDG_DNS_F_RD, 1, 0, 0, 0);
	q[12] = 0xc0;	/* 指向自己的压缩指针：非法 */
	q[13] = 0x0c;
	q[14] = 0; q[15] = 1; q[16] = 0; q[17] = 1;
	rn = sizeof(r);
	TEQ(kdg_wire_make_error_response(q, 18, KDG_RCODE_FORMERR, r, rn, &rn),
	    KDG_W_OK, "畸形问题区仍回应答");
	TEQ(r[5], 0, "畸形时 QDCOUNT=0");
	TEQ(rn, KDG_DNS_HDR_LEN, "畸形时长度=12");
	TEQ(r[1], 0x22, "畸形时 ID 仍原样");

	/* 边界 */
	TEQ(kdg_wire_make_error_response(q, 11, KDG_RCODE_SERVFAIL, r, sizeof(r),
					 &rn), KDG_W_ETRUNC, "报文短于 header");
	{
		size_t small = 8;

		qn = build_query(q, 0x1234, KDG_DNS_F_RD, "example.com",
				 KDG_RRTYPE_A);
		TEQ(kdg_wire_make_error_response(q, qn, KDG_RCODE_SERVFAIL, r,
						 small, &small),
		    KDG_W_EBOUNDS, "输出缓冲不足");
	}
	TEQ(kdg_wire_make_error_response((const u8 *)0, 12, 0, r, sizeof(r), &rn),
	    KDG_W_EARG, "空请求指针");
	TEQ(kdg_wire_make_error_response(q, 12, 0, (u8 *)0, sizeof(r), &rn),
	    KDG_W_EARG, "空输出指针");
}

int main(void)
{
	puts("=== kdg_wire 语料测试 ===");

	test_query_ok();
	test_query_edns();
	test_query_reject();
	test_compression_pointers();
	test_name_too_long();
	test_response_ok();
	test_response_negative();
	test_response_opt_ttl();
	test_response_reject();
	test_cache_policy();
	test_match();
	test_dname_text();
	test_error_response();
	test_invariants();

	printf("\n=== 通过 %d / 失败 %d ===\n", g_pass, g_fail);
	return g_fail ? 1 : 0;
}
