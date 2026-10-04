/* SPDX-License-Identifier: GPL-2.0 */
/*
 * test_map.c —— kdg_map 与 kdg_wire_collect_addrs 的宿主侧测试。
 *
 * 直接编译内核侧的 kdg_map.c（双态），用**可控时钟**把过期、淘汰、歧义集合
 * 宽度这些在真机上要靠运气才碰得到的分支逐个走一遍。与 test_cache_tab.c
 * 同一套路，理由也相同：真机上没法把时间拨快一小时，也没法优雅地制造
 * 「512 个槽位全满」。
 *
 * 报文用独立的手写构造器，**不调用**被测代码 —— 否则就是拿被测代码构造
 * 测试数据，循环验证。
 */
#include <stdio.h>
#include <string.h>

#include "host_kernel.h"
#include "../kernel/kdg_map.c"

static int g_pass, g_fail;

#define CHECK(cond, name) do {						\
	if (cond) {							\
		g_pass++;						\
	} else {							\
		g_fail++;						\
		printf("  FAIL %s (line %d)\n", (name), __LINE__);	\
	}								\
} while (0)

#define EQ(a, b, name)	CHECK((long)(a) == (long)(b), name)

/* ── 报文构造器（独立于被测代码） ────────────────────────────────────── */

static size_t put16(u8 *p, unsigned v)
{
	p[0] = (u8)(v >> 8);
	p[1] = (u8)v;
	return 2;
}

static size_t put32(u8 *p, unsigned long v)
{
	p[0] = (u8)(v >> 24);
	p[1] = (u8)(v >> 16);
	p[2] = (u8)(v >> 8);
	p[3] = (u8)v;
	return 4;
}

static size_t put_name(u8 *p, const char *text)
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

struct rrmaker {
	u16 type;
	u16 rdlen;
	u16 class_;
	u32 ttl;
	u8  rdata[16];
};

/* 构造一条应答：question 为 qname/A，答案区按 rrs 逐条写（owner 名用压缩
 * 指针指向 question，与真实递归解析器的形态一致）。 */
static size_t build_resp(u8 *buf, const char *qname,
			 const struct rrmaker *rrs, int nrr)
{
	size_t o = 0;
	int i;

	put16(buf + o, 0); o += 2;		/* id */
	put16(buf + o, 0x8180); o += 2;		/* QR|RD|RA|NOERROR */
	put16(buf + o, 1); o += 2;		/* qdcount */
	put16(buf + o, (unsigned)nrr); o += 2;	/* ancount */
	put16(buf + o, 0); o += 2;
	put16(buf + o, 0); o += 2;

	o += put_name(buf + o, qname);
	put16(buf + o, 1); o += 2;		/* qtype A */
	put16(buf + o, 1); o += 2;		/* qclass IN */

	for (i = 0; i < nrr; i++) {
		buf[o++] = 0xc0;		/* 压缩指针 → 12 */
		buf[o++] = 0x0c;
		put16(buf + o, rrs[i].type); o += 2;
		put16(buf + o, rrs[i].class_); o += 2;
		put32(buf + o, rrs[i].ttl); o += 4;
		put16(buf + o, rrs[i].rdlen); o += 2;
		memcpy(buf + o, rrs[i].rdata, rrs[i].rdlen);
		o += rrs[i].rdlen;
	}
	return o;
}

static struct rrmaker rr_a(u32 ttl, u8 a, u8 b, u8 c, u8 d)
{
	struct rrmaker r;

	memset(&r, 0, sizeof(r));
	r.type = 1;
	r.class_ = 1;
	r.ttl = ttl;
	r.rdlen = 4;
	r.rdata[0] = a; r.rdata[1] = b; r.rdata[2] = c; r.rdata[3] = d;
	return r;
}

static const u8 Q_A_EXAMPLE[] = { 1, 'a', 7, 'e', 'x', 'a', 'm', 'p', 'l',
				  'e', 0 };
static const u8 Q_B_EXAMPLE[] = { 1, 'b', 7, 'e', 'x', 'a', 'm', 'p', 'l',
				  'e', 0 };
static const u8 IP_1_2_3_4[4] = { 1, 2, 3, 4 };

/* ── 1. wire 层：收集地址 ─────────────────────────────────────────────── */
static void test_collect(void)
{
	u8 msg[512];
	struct kdg_addr_ref refs[KDG_WIRE_MAX_ADDRS];
	struct rrmaker rr[3];
	size_t len;
	int n;

	/* 两条 A + 一条 CNAME，CNAME 不该被当成地址 */
	rr[0] = rr_a(60, 1, 2, 3, 4);
	rr[1] = rr_a(120, 5, 6, 7, 8);
	memset(&rr[2], 0, sizeof(rr[2]));
	rr[2].type = 5;			/* CNAME */
	rr[2].class_ = 1;
	rr[2].ttl = 60;
	rr[2].rdlen = 5;
	/* 逐字节写：`"\x03c"` 会被当成**一个**十六进制转义（c 是十六进制位），
	 * 结果是 0x3c 截断值而不是 0x03 后跟 'c' —— 这类坑在测试数据里同样致命。 */
	rr[2].rdata[0] = 3; rr[2].rdata[1] = 'c'; rr[2].rdata[2] = 'd';
	rr[2].rdata[3] = 'n'; rr[2].rdata[4] = 0;
	len = build_resp(msg, "a.example", rr, 3);

	n = kdg_wire_collect_addrs(msg, len, refs, KDG_WIRE_MAX_ADDRS);
	EQ(n, 2, "只收集 A/AAAA，跳过 CNAME");
	EQ(refs[0].ttl, 60, "第一条 TTL");
	EQ(refs[1].ttl, 120, "第二条 TTL");
	CHECK(refs[0].rdlen == 4 && refs[1].rdlen == 4, "rdlen 都是 4");
	EQ(memcmp(msg + refs[0].rdata_off, IP_1_2_3_4, 4), 0, "第一条地址值正确");

	/* 容量不足：整体拒绝而不是截断 */
	n = kdg_wire_collect_addrs(msg, len, refs, 1);
	EQ(n, KDG_W_ECOUNT, "超过 cap 时整体拒绝");

	/* rdata 长度与类型不符 ⇒ 跳过该条（不能按短的读，那会把后续字节
	 * 当成地址的一部分） */
	rr[0].rdlen = 16;
	len = build_resp(msg, "a.example", rr, 1);
	n = kdg_wire_collect_addrs(msg, len, refs, KDG_WIRE_MAX_ADDRS);
	EQ(n, 0, "A 的 rdlen 不是 4 时跳过");

	/* 非 IN 类跳过 */
	rr[0] = rr_a(60, 1, 2, 3, 4);
	rr[0].class_ = 3;		/* CHAOS */
	len = build_resp(msg, "a.example", rr, 1);
	n = kdg_wire_collect_addrs(msg, len, refs, KDG_WIRE_MAX_ADDRS);
	EQ(n, 0, "非 IN 类不收集");

	/* 坏 wire 整体拒绝 */
	EQ(kdg_wire_collect_addrs(msg, 5, refs, KDG_WIRE_MAX_ADDRS),
	   KDG_W_ETRUNC, "报文截断时拒绝");
	EQ(kdg_wire_collect_addrs((const u8 *)0, 12, refs, 4), KDG_W_EARG,
	   "空指针");
}

/* ── 2. 基本记录与反查 ───────────────────────────────────────────────── */
static void test_basic(void)
{
	u8 msg[512];
	struct kdg_addr_ref refs[4];
	struct kdg_map_result out;
	struct rrmaker rr[2];
	size_t len;
	int n;

	rr[0] = rr_a(300, 1, 2, 3, 4);
	rr[1] = rr_a(300, 5, 6, 7, 8);
	len = build_resp(msg, "a.example", rr, 2);
	n = kdg_wire_collect_addrs(msg, len, refs, 4);
	EQ(n, 2, "收集到两条");

	kdg_map_host_now_ms = 1000;
	kdg_map_record(0, 7, Q_A_EXAMPLE, sizeof(Q_A_EXAMPLE), msg, len, refs, 2);

	EQ(kdg_map_lookup(0, 7, 4, IP_1_2_3_4, KDG_MAP_MAX_NAMES, &out), 0,
	   "反查命中第一个地址");
	EQ(out.count, 1, "一个域名");
	EQ(out.profile_gen, 7, "provenance 是记录时的代际");
	EQ(memcmp(out.names[0], Q_A_EXAMPLE, sizeof(Q_A_EXAMPLE)), 0,
	   "域名逐字节一致");
	EQ(out.lens[0], sizeof(Q_A_EXAMPLE), "域名长度");
	EQ(out.ttl_ms[0], 300000, "剩余 TTL");
	CHECK(!out.truncated, "未被截断");

	{
		const u8 other[4] = { 5, 6, 7, 8 };

		EQ(kdg_map_lookup(0, 7, 4, other, KDG_MAP_MAX_NAMES, &out), 0,
		   "反查命中第二个地址");
		EQ(memcmp(out.names[0], Q_A_EXAMPLE, sizeof(Q_A_EXAMPLE)), 0,
		   "第二个地址同样挂到同一个域名");
	}

	/* 代际不符 → 不命中（换上游后旧关联不可信） */
	EQ(kdg_map_lookup(0, 8, 4, IP_1_2_3_4, KDG_MAP_MAX_NAMES, &out), -ENOENT,
	   "profile 代际不符视为不命中");
	/* net_id 不符 */
	EQ(kdg_map_lookup(9, 7, 4, IP_1_2_3_4, KDG_MAP_MAX_NAMES, &out), -ENOENT,
	   "net_id 不符不命中");
	/* 没记录过的地址 */
	{
		const u8 miss[4] = { 9, 9, 9, 9 };

		EQ(kdg_map_lookup(0, 7, 4, miss, KDG_MAP_MAX_NAMES, &out), -ENOENT,
		   "未记录地址不命中");
	}
	/* 地址长度不符。注意必须给够 addr_len 字节的缓冲：kdg_map_lookup 按
	 * 调用方声明的长度读地址，这是它的接口契约（内核侧由 chardev 拷进
	 * 16 字节栈缓冲保证）。第一次写这个测试时传了 4 字节指针配 addr_len=16，
	 * 被 ASan 当场抓出来 —— 这正是宿主侧带 ASan 的价值。 */
	{
		u8 wide[16] = { 1, 2, 3, 4 };

		EQ(kdg_map_lookup(0, 7, 16, wide, KDG_MAP_MAX_NAMES, &out), -ENOENT,
		   "族不符不命中");
	}
	/* cap 非法 */
	EQ(kdg_map_lookup(0, 7, 4, IP_1_2_3_4, 0, &out), -EINVAL, "cap=0 拒绝");
	EQ(kdg_map_lookup(0, 7, 4, IP_1_2_3_4, 200, &out), -EINVAL, "cap 越界拒绝");
}

/* ── 3. 歧义集合：同 IP 多域名必须全保留 ─────────────────────────────── */
static void test_ambiguity(void)
{
	u8 msg[512];
	struct kdg_addr_ref refs[2];
	struct kdg_map_result out;
	struct rrmaker rr[1];
	size_t len;
	int n, i, seen = 0;

	rr[0] = rr_a(600, 1, 2, 3, 4);
	len = build_resp(msg, "a.example", rr, 1);
	n = kdg_wire_collect_addrs(msg, len, refs, 2);
	EQ(n, 1, "一条地址");

	kdg_map_host_now_ms = 5000;
	kdg_map_record(0, 1, Q_A_EXAMPLE, sizeof(Q_A_EXAMPLE), msg, len, refs, 1);
	kdg_map_record(0, 1, Q_B_EXAMPLE, sizeof(Q_B_EXAMPLE), msg, len, refs, 1);

	EQ(kdg_map_lookup(0, 1, 4, IP_1_2_3_4, KDG_MAP_MAX_NAMES, &out), 0,
	   "命中");
	EQ(out.count, 2, "一个 IP 关联两个域名（歧义保留）");
	for (i = 0; i < out.count; i++) {
		if (out.lens[i] == sizeof(Q_A_EXAMPLE) &&
		    !memcmp(out.names[i], Q_A_EXAMPLE, out.lens[i]))
			seen |= 1;
		if (out.lens[i] == sizeof(Q_B_EXAMPLE) &&
		    !memcmp(out.names[i], Q_B_EXAMPLE, out.lens[i]))
			seen |= 2;
	}
	EQ(seen, 3, "两个域名都在结果里，没有被「最后一个覆盖」");

	/* cap 小于持有数 ⇒ 截断标志必须为真（有信息量的截断） */
	EQ(kdg_map_lookup(0, 1, 4, IP_1_2_3_4, 1, &out), 0, "cap=1 命中");
	EQ(out.count, 1, "只回一个");
	CHECK(out.truncated, "cap 不足时要标 truncated");

	/* 同一条目里重复记录同一个域名：刷新 TTL，不产生第二条 */
	kdg_map_host_now_ms = 10000;
	kdg_map_record(0, 1, Q_A_EXAMPLE, sizeof(Q_A_EXAMPLE), msg, len, refs, 1);
	EQ(kdg_map_lookup(0, 1, 4, IP_1_2_3_4, KDG_MAP_MAX_NAMES, &out), 0, "命中");
	EQ(out.count, 2, "重复记录不增加条数");
	{
		int a_seen = 0;

		for (i = 0; i < out.count; i++)
			if (out.lens[i] == sizeof(Q_A_EXAMPLE) &&
			    !memcmp(out.names[i], Q_A_EXAMPLE, out.lens[i])) {
				a_seen = 1;
				EQ(out.ttl_ms[i], 600000, "重复记录刷新 TTL");
			}
		EQ(a_seen, 1, "域名 A 仍在");
	}
}

/* ── 4. 过期 ─────────────────────────────────────────────────────────── */
static void test_expiry(void)
{
	u8 msg[512];
	struct kdg_addr_ref refs[1];
	struct kdg_map_result out;
	struct kdg_map_stats st;
	struct rrmaker rr[1];
	size_t len;

	rr[0] = rr_a(60, 10, 0, 0, 1);
	len = build_resp(msg, "a.example", rr, 1);
	kdg_wire_collect_addrs(msg, len, refs, 1);

	kdg_map_host_now_ms = 100000;
	kdg_map_record(0, 2, Q_A_EXAMPLE, sizeof(Q_A_EXAMPLE), msg, len, refs, 1);
	{
		const u8 ip[4] = { 10, 0, 0, 1 };

		EQ(kdg_map_lookup(0, 2, 4, ip, 4, &out), 0, "刚记录时命中");
		/* 剩余 TTL 随时钟推进而减少 */
		kdg_map_host_now_ms += 20000;
		EQ(kdg_map_lookup(0, 2, 4, ip, 4, &out), 0, "20 秒后仍命中");
		EQ(out.ttl_ms[0], 40000, "剩余 TTL 正确递减");
		/* 越过到期点 */
		kdg_map_host_now_ms += 40000;
		EQ(kdg_map_lookup(0, 2, 4, ip, 4, &out), -ENOENT, "过期后不命中");
	}

	/* TTL=0 不记录 */
	rr[0] = rr_a(0, 10, 0, 0, 2);
	len = build_resp(msg, "a.example", rr, 1);
	kdg_wire_collect_addrs(msg, len, refs, 1);
	kdg_map_record(0, 2, Q_A_EXAMPLE, sizeof(Q_A_EXAMPLE), msg, len, refs, 1);
	{
		const u8 ip[4] = { 10, 0, 0, 2 };

		EQ(kdg_map_lookup(0, 2, 4, ip, 4, &out), -ENOENT, "TTL=0 不记录");
	}

	/* TTL 夹取：极大值被压到 KDG_MAP_MAX_TTL_MS */
	rr[0] = rr_a(0xffffffffu, 10, 0, 0, 3);
	len = build_resp(msg, "a.example", rr, 1);
	kdg_wire_collect_addrs(msg, len, refs, 1);
	kdg_map_record(0, 2, Q_A_EXAMPLE, sizeof(Q_A_EXAMPLE), msg, len, refs, 1);
	{
		const u8 ip[4] = { 10, 0, 0, 3 };

		EQ(kdg_map_lookup(0, 2, 4, ip, 4, &out), 0, "大 TTL 命中");
		EQ(out.ttl_ms[0], KDG_MAP_MAX_TTL_MS, "TTL 被夹到上界");
	}

	kdg_map_get_stats(&st);
	CHECK(st.entries > 0, "统计里有条目");
	CHECK(st.lookup_hits > 0, "统计里有命中");
	CHECK(st.lookup_misses > 0, "统计里有未命中");
}

/* ── 5. 边界：超长名、越界偏移、IPv6 ─────────────────────────────────── */
static void test_bounds(void)
{
	u8 msg[512];
	u8 longname[KDG_MAP_NAME_MAX + 8];
	struct kdg_addr_ref refs[2];
	struct kdg_map_result out;
	struct kdg_map_stats st0, st1;
	struct rrmaker rr[1];
	size_t len;

	memset(longname, 0xaa, sizeof(longname));
	longname[0] = 63;		/* 只是内容，不需要是合法域名：record 只看长度 */

	rr[0] = rr_a(300, 1, 2, 3, 4);
	len = build_resp(msg, "a.example", rr, 1);
	kdg_wire_collect_addrs(msg, len, refs, 2);

	kdg_map_host_now_ms = 1;
	kdg_map_get_stats(&st0);
	kdg_map_record(0, 3, longname, sizeof(longname), msg, len, refs, 1);
	kdg_map_get_stats(&st1);
	EQ(st1.record_rejected, st0.record_rejected + 1, "超长名被拒并计数");
	EQ(kdg_map_lookup(0, 3, 4, IP_1_2_3_4, 4, &out), -ENOENT,
	   "超长名没有被记进去");

	/* rdata_off 超出报文长度 ⇒ 跳过，不做越界读（ASan 会当场炸） */
	refs[0].rdata_off = (u16)(len + 4);
	kdg_map_record(0, 3, Q_A_EXAMPLE, sizeof(Q_A_EXAMPLE), msg, len, refs, 1);
	EQ(kdg_map_lookup(0, 3, 4, IP_1_2_3_4, 4, &out), -ENOENT,
	   "越界偏移的记录被丢弃");

	/* rdlen 既不是 4 也不是 16 ⇒ 跳过 */
	refs[0].rdata_off = 12;
	refs[0].rdlen = 8;
	kdg_map_record(0, 3, Q_A_EXAMPLE, sizeof(Q_A_EXAMPLE), msg, len, refs, 1);
	EQ(kdg_map_lookup(0, 3, 4, IP_1_2_3_4, 4, &out), -ENOENT,
	   "rdlen 异常时跳过");

	/* IPv6（16 字节） */
	{
		u8 v6[16] = { 0x20, 0x01, 0x48, 0x60, 0, 0, 0, 0,
			      0, 0, 0, 0, 0, 0, 0, 0x88 };
		struct rrmaker r6;

		memset(&r6, 0, sizeof(r6));
		r6.type = 28;		/* AAAA */
		r6.class_ = 1;
		r6.ttl = 300;
		r6.rdlen = 16;
		memcpy(r6.rdata, v6, 16);
		len = build_resp(msg, "a.example", &r6, 1);
		EQ(kdg_wire_collect_addrs(msg, len, refs, 2), 1, "收集到一条 AAAA");
		kdg_map_record(0, 3, Q_A_EXAMPLE, sizeof(Q_A_EXAMPLE), msg, len,
			       refs, 1);
		EQ(kdg_map_lookup(0, 3, 16, v6, 4, &out), 0, "IPv6 反查命中");
		EQ(out.count, 1, "IPv6 一个域名");
		/* 长度不符（拿 v6 当地址、按 4 字节查）不能命中 */
		EQ(kdg_map_lookup(0, 3, 4, v6, 4, &out), -ENOENT,
		   "地址长度不符不命中");
	}
}

/* ── 6. 容量：填满不崩、有界、flush ──────────────────────────────────── */
static void test_capacity(void)
{
	u8 msg[512];
	struct kdg_addr_ref refs[1];
	struct kdg_map_result out;
	struct kdg_map_stats st;
	struct rrmaker rr[1];
	size_t len;
	u32 i;

	kdg_map_flush(0);
	kdg_map_flush(0xffffffffu);
	kdg_map_host_now_ms = 1000;

	/* 造出远超槽位数的不同 IP（用 10.a.b.c 铺满） */
	for (i = 0; i < (u32)KDG_MAP_DEF_SLOTS * 3; i++) {
		u8 ip[4] = { 10, (u8)(i >> 16), (u8)(i >> 8), (u8)i };

		rr[0] = rr_a(300, ip[0], ip[1], ip[2], ip[3]);
		len = build_resp(msg, "a.example", rr, 1);
		kdg_wire_collect_addrs(msg, len, refs, 2);
		kdg_map_record(0, 4, Q_A_EXAMPLE, sizeof(Q_A_EXAMPLE), msg, len,
			       refs, 1);
		/* 每条都立刻反查一次，把 CLOCK 的二次机会位搅动起来 */
		(void)kdg_map_lookup(0, 4, 4, ip, 4, &out);
	}
	kdg_map_get_stats(&st);
	CHECK(st.entries <= KDG_MAP_DEF_SLOTS, "条目数不超槽位上限");
	CHECK(st.evictions > 0, "发生了淘汰");
	CHECK(st.mem_bytes == st.mem_max_bytes, "内存核算与上限一致");

	/* 最近记录的那个必须还在（淘汰不许把刚写进去的吃掉） */
	{
		u32 last = (u32)KDG_MAP_DEF_SLOTS * 3 - 1;
		u8 ip[4] = { 10, (u8)(last >> 16), (u8)(last >> 8), (u8)last };

		EQ(kdg_map_lookup(0, 4, 4, ip, 4, &out), 0, "最近写入的仍在");
	}

	/* flush 按 net_id */
	kdg_map_flush(0);
	kdg_map_get_stats(&st);
	EQ(st.entries, 0, "flush 清空");
	{
		u8 ip[4] = { 10, 0, 0, 1 };

		EQ(kdg_map_lookup(0, 4, 4, ip, 4, &out), -ENOENT, "清空后不命中");
	}
}

/* ── 4. 歧义集合写满：truncated 必须能反映存储侧丢过域名 ─────────────── */
static void test_set_full(void)
{
	u8 msg[512];
	struct kdg_addr_ref refs[1];
	u8 names[KDG_MAP_MAX_NAMES + 3][8];
	struct kdg_map_result out;
	struct kdg_map_stats st;
	struct rrmaker rr[1];
	size_t len;
	int i;
	const u8 ip[4] = { 1, 2, 3, 9 };

	rr[0] = rr_a(300, 1, 2, 3, 9);
	len = build_resp(msg, "a.example", rr, 1);
	kdg_wire_collect_addrs(msg, len, refs, 1);

	kdg_map_host_now_ms = 1000;
	/* 造 KDG_MAP_MAX_NAMES + 3 个不同的名字，逼集合溢出 */
	for (i = 0; i < KDG_MAP_MAX_NAMES + 3; i++) {
		names[i][0] = 1;
		names[i][1] = (u8)('a' + i);
		names[i][2] = 0;
		kdg_map_host_now_ms += 1000;
		kdg_map_record(0, 11, names[i], 3, msg, len, refs, 1);
	}

	EQ(kdg_map_lookup(0, 11, 4, ip, KDG_MAP_MAX_NAMES, &out), 0, "命中");
	EQ(out.count, KDG_MAP_MAX_NAMES, "条数被集合宽度限死");
	CHECK(out.truncated, "存储侧丢过域名 ⇒ truncated 必须为真");
	kdg_map_get_stats(&st);
	CHECK(st.record_rejected > 0, "溢出被计数");
}

int main(void)
{
	puts("=== kdg_map 语料测试 ===");

	CHECK(kdg_map_init() == 0, "初始化");

	test_collect();
	test_basic();
	test_ambiguity();
	test_expiry();
	test_bounds();
	test_set_full();
	test_capacity();

	kdg_map_exit();

	printf("\n=== 通过 %d / 失败 %d ===\n", g_pass, g_fail);
	return g_fail ? 1 : 0;
}
