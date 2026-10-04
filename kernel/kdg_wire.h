/* SPDX-License-Identifier: GPL-2.0 */
/*
 * kdg_wire.h —— 有界 DNS wire 校验器（方案 §8）。
 *
 * 定位：这是整个项目**唯一由本项目新增的报文解析边界**。方案 §8 明确要求
 * 「不能称为零开发」，且「首期只实现最小有界 walker、TTL 元信息和响应重封装」。
 * 完整递归解析器与 DNSSEC 验证器交给远端 DoH 服务，此处不重复实现。
 *
 * 三条不可让步的性质：
 *  1. **有界**：任何输入长度下，读取都不越过 msg[0..len)，且不存在无界循环
 *     或无界递归。压缩指针只允许严格向低地址回指，从构造上排除自环/互环，
 *     而不是靠「跳转次数上限」兜底（上限只是第二道闸）。
 *  2. **不分配**：全部状态在调用者的栈/结构体里，解析路径不调用 kmalloc。
 *     这样它在 Netfilter hook 或任何内存紧张路径上都能安全调用。
 *  3. **不信任计数**：header 里的 qdcount/ancount/nscount/arcount 只当作
 *     「声明值」，实际 walker 以报文长度为准逐条推进；两者不一致即拒绝，
 *     绝不按声明值预分配或预先信任。
 *
 * 注意：本文件与 kdg_wire.c 必须保持双态可编译（见 kdg_base.h），
 * 不得包含 kdg_base.h 之外的其它内核头。
 */
#ifndef _KDG_WIRE_H
#define _KDG_WIRE_H

#include "kdg_base.h"

/* ── 协议常量 ─────────────────────────────────────────────────────────── */
#define KDG_DNS_HDR_LEN		12
#define KDG_DNS_MAX_LABEL	63	/* RFC 1035 §2.3.4 */
#define KDG_DNS_MAX_NAME	255	/* RFC 1035 §3.1：名字 wire 形式上限（含 root） */
/* 压缩指针跳数上限。由于我们强制严格回指，跳数天然 <= 报文长度；这个上限
 * 只是防止在超长报文上做 O(n) 次跳转放大 CPU 消耗（DoS 面）。 */
#define KDG_DNS_MAX_PTR_JUMPS	64

/* UDP 载荷上限（方案 §8）：无 EDNS 时 512，有 EDNS 时按客户端能力与本地上限
 * 取小，本地安全上限建议 1232（IPv6 最小 MTU 1280 减去头部的保守值）。 */
#define KDG_DNS_UDP_CLASSIC	512
#define KDG_DNS_UDP_SAFE	1232

/* header 标志位 */
#define KDG_DNS_F_QR		0x8000
#define KDG_DNS_F_OPCODE_MASK	0x7800
#define KDG_DNS_F_AA		0x0400
#define KDG_DNS_F_TC		0x0200
#define KDG_DNS_F_RD		0x0100
#define KDG_DNS_F_RA		0x0080
#define KDG_DNS_F_Z		0x0040
#define KDG_DNS_F_AD		0x0020
#define KDG_DNS_F_CD		0x0010
#define KDG_DNS_F_RCODE_MASK	0x000f

#define KDG_DNS_OPCODE_QUERY	0
#define KDG_DNS_OPCODE_NOTIFY	4
#define KDG_DNS_OPCODE_UPDATE	5

/* 记录类型（只列出本模块有专门语义的；其余一律「安全透明传递」） */
#define KDG_RRTYPE_A		1
#define KDG_RRTYPE_NS		2
#define KDG_RRTYPE_CNAME	5
#define KDG_RRTYPE_SOA		6
#define KDG_RRTYPE_PTR		12
#define KDG_RRTYPE_MX		15
#define KDG_RRTYPE_TXT		16
#define KDG_RRTYPE_AAAA		28
#define KDG_RRTYPE_SRV		33
#define KDG_RRTYPE_OPT		41	/* EDNS0 伪记录，**不是**普通 RR */
#define KDG_RRTYPE_SVCB		64
#define KDG_RRTYPE_HTTPS	65	/* SVCB 的 HTTPS 特化，ECH 参数在这里 */
#define KDG_RRTYPE_ANY		255

#define KDG_RRCLASS_IN		1
#define KDG_RRCLASS_ANY		255

/* 响应码 */
#define KDG_RCODE_NOERROR	0
#define KDG_RCODE_FORMERR	1
#define KDG_RCODE_SERVFAIL	2
#define KDG_RCODE_NXDOMAIN	3
#define KDG_RCODE_NOTIMP	4
#define KDG_RCODE_REFUSED	5
/* 9..15 为 6/7/8 扩展（RFC 6895）；EDNS 的 ext-rcode 另占高 8 位 */

/* EDNS0 option codes（我们只识别，不改写） */
#define KDG_EDNS_OPT_NSID	3
#define KDG_EDNS_OPT_COOKIE	10
#define KDG_EDNS_OPT_ECS		8	/* EDNS Client Subnet —— 不可合并 */
#define KDG_EDNS_OPT_ECH	18	/* Encrypted Client Hello 参数 */
#define KDG_EDNS_OPT_PADDING	12

/* ── 错误码 ───────────────────────────────────────────────────────────── */
#define KDG_W_OK		0
#define KDG_W_EFORMAT		(-1)	/* 结构上不合法（保留位、地址族等） */
#define KDG_W_EBOUNDS		(-2)	/* 读取越过报文尾部 */
#define KDG_W_ELOOP		(-3)	/* 压缩指针非法：自环/互环/前向 */
#define KDG_W_ELEN		(-4)	/* 标签或名字超长 */
#define KDG_W_ECOUNT		(-5)	/* 声明计数与实际不符 */
#define KDG_W_ETRUNC		(-6)	/* 报文不完整（含 header 都不够） */
#define KDG_W_EARG		(-7)	/* 调用方参数错误 */
#define KDG_W_ENOTSUP		(-8)	/* 本版不支持（如非 QUERY 的 opcode） */
#define KDG_W_EMISMATCH		(-9)	/* 响应的 question 与请求不符 */

/* ── 数据结构 ─────────────────────────────────────────────────────────── */

/* 解码后的域名。wire 为**未压缩、小写、以 root 结尾**的规范形式——
 * 它只用于缓存键与合并键（DNS 名大小写不敏感，RFC 4343 §2）；
 * 回包时调用方的问题区必须**原样**使用请求里的字节，不用这里的形态。 */
struct kdg_dname {
	u8  wire[KDG_DNS_MAX_NAME];
	u16 len;		/* 含结尾 root 字节 */
	u8  nlabels;
	u8  reserved_;
};

struct kdg_query {
	u16 id;			/* 原始 DNS ID，回包时必须恢复 */
	u16 flags;		/* 原始 flags，回包时按需改写 */
	u8  opcode;
	u8  rcode;
	struct kdg_dname qname;
	u16 qtype;
	u16 qclass;
	u16 question_len;	/* question 段在报文中的字节数 */
	u16 msg_len;		/* 报文总长，来自入参 */
	/* EDNS */
	bool has_edns;
	bool edns_do;		/* DNSSEC OK */
	bool edns_badvers;
	bool edns_has_ecs;	/* 带 ECS → 不参与跨调用方合并 */
	bool edns_has_cookie;
	u16 edns_udp_size;	/* 声明值，0 表示未声明 */
};

/* 单条 RR 的定位信息。不复制 rdata，只记偏移与长度，
 * 让「透明传递」不必二次解析。 */
struct kdg_rr_ref {
	struct kdg_dname name;
	u16 type;
	u16 class_;
	u32 ttl;		/* 原始值；对 OPT 而言这是 ext-rcode/flags，非 TTL */
	u16 rdata_off;
	u16 rdlen;
	u16 reserved_;
};

struct kdg_summary {
	/* header */
	u16 id;
	u8  opcode;
	u8  rcode;		/* 低 4 位 */
	u8  ext_rcode;		/* 来自 OPT，未出现则为 0 */
	bool qr, aa, tc, rd, ra, ad, cd, z;
	u16 qdcount, ancount, nscount, arcount;
	u16 counted_an, counted_ns, counted_ar;	/* 实际走到的条数 */

	/* EDNS */
	bool has_edns;
	bool edns_do;
	bool edns_badvers;
	u16 edns_udp_size;

	/* 缓存所需元信息 */
	u32 min_ttl;		/* 全部非 OPT RR 的最小 TTL；无 RR 时 = U32_MAX */
	u32 soa_ttl;		/* SOA RR 自身的 TTL；U32_MAX 表示无 */
	u32 soa_minimum;	/* SOA rdata 的 MINIMUM 字段；U32_MAX 表示无 */
	bool has_soa;

	/* 语义判定 */
	bool is_nxdomain;
	bool is_nodata;		/* NOERROR 但答案区空（区分于 NXDOMAIN，§8） */
	bool is_referral;	/* NS 在 authority、答案区空、无 SOA —— 非权威应答 */
	u16 question_bytes;	/* question 段总字节数 */
	bool question_ok;	/* question 段被完整解析 */
};

/* ── 接口 ─────────────────────────────────────────────────────────────── */

/* 解析一条 DNS 查询报文。拒绝非 QUERY opcode（本版只服务标准查询）。
 * 返回 0 或 KDG_W_E*。out 在函数内被完整初始化，失败时内容无意义。 */
int kdg_wire_parse_query(const u8 *msg, size_t len, struct kdg_query *out);

/* 解析一条 DNS 响应报文，产出缓存所需的元信息。
 * 不校验 question 是否与某请求匹配——那是 kdg_wire_match_response 的职责。 */
int kdg_wire_parse_response(const u8 *msg, size_t len, struct kdg_summary *out);

/* 校验 resp 是对 req 的合法响应：QR=1、opcode 一致、ID 一致、question 段
 * 逐字节一致、rcode 可用。这是「拒绝跨上游身份跳转」的落点（§8）。
 * qname/qtype 比较用**未压缩小写**形式，避免大小写或压缩差异导致误判。 */
int kdg_wire_match_response(const u8 *req, size_t reqlen,
			    const u8 *resp, size_t resplen,
			    struct kdg_summary *out);

/* 域名文本 <-> wire 规范形式。文本形式期望不带结尾点（"example.com"）；
 * 结尾单点表示根（"."）。用于配置解析与单测构造。 */
int kdg_wire_dname_from_text(const char *text, size_t textlen,
			     struct kdg_dname *out);
int kdg_wire_dname_to_text(const struct kdg_dname *n, char *buf, size_t buflen);

/* 单条 RR 的定位查询，供域名映射与反向映射使用。idx 从 0 起，
 * 越界返回 KDG_W_EARG。 */
int kdg_wire_get_answer_rr(const u8 *msg, size_t len, unsigned int idx,
			   struct kdg_rr_ref *out);

/*
 * 收集响应中所有 **非 OPT** RR 的 TTL 字段在报文里的字节偏移。
 *
 * 为什么排除 OPT：OPT 伪记录的 TTL 字段承载 ext-rcode/version/flags，
 * **不是生存时间**。缓存回包时若把它一起递减，会破坏 EDNS 语义
 * （方案 §8 明确点名这一点）。这里从源头排除，调用方无需再判。
 *
 * 返回写入的偏移个数（>=0），或负的 KDG_W_E*；
 * 当非 OPT RR 数超过 offs_cap 时返回 KDG_W_ECOUNT —— 调用方应据此
 * **放弃缓存该响应**，而不是少改几个 TTL（那会让超期数据看起来更新鲜）。
 */
int kdg_wire_collect_ttl_offs(const u8 *msg, size_t len,
			      u16 *offs, u16 offs_cap);

/*
 * 一条 A/AAAA 记录的定位信息。只记值与 TTL，**不复制 rdata**，也不记 RR 的
 * owner 名 —— 域名/IP 映射要的是「调用方问的那个名字」，而不是 CNAME 链末端
 * 的名字（见 kdg_wire_collect_addrs 的注释）。
 */
struct kdg_addr_ref {
	u16 type;		/* KDG_RRTYPE_A / KDG_RRTYPE_AAAA */
	u16 reserved_;
	u32 ttl;		/* 原始 TTL（秒） */
	u16 rdata_off;		/* rdata 在报文中的偏移 */
	u16 rdlen;		/* 4 或 16 */
};

/* 单次收集的地址上限。答案区多于这个数量时**整体拒绝**（返回 KDG_W_ECOUNT）
 * 而不是截断 —— 静默丢弃一部分地址会让「这个域名解析到了哪些 IP」这个事实
 * 变得不完整，调用方据此建立的映射会缺项。 */
#define KDG_WIRE_MAX_ADDRS	16

/*
 * 收集响应**答案区**里的全部 A/AAAA 记录。
 *
 * ⚠️ 刻意**不**看 RR 的 owner 名。递归解析器返回的是整条链，典型形态是
 *
 *     www.example.com.  CNAME  cdn.example.net.
 *     cdn.example.net.  A      1.2.3.4
 *
 * 而调用方（代理的域名路由）关心的是「应用问的那个名字」。若按 owner 名记录，
 * 映射会变成 1.2.3.4 → cdn.example.net，应用按 www.example.com 分流就落空。
 * 所以这里只取值，由调用方统一挂到它自己的 qname 上。
 *
 * 不做递归/不跟随 NS 授权段：答案区之外的记录不是这次查询的答案。
 * 返回值：写入的条数（>=0），或负的 KDG_W_E*（KDG_W_ECOUNT 表示多于 cap）。
 */
int kdg_wire_collect_addrs(const u8 *msg, size_t len,
			   struct kdg_addr_ref *out, u16 cap);

/* 该响应是否可缓存，以及可缓存多久（秒）。0 表示不可缓存。
 * 覆盖 §8 的全部规则：TTL=0、SERVFAIL、截断、超大、非 NOERROR/NXDOMAIN。 */
u32 kdg_wire_cacheable_ttl(const struct kdg_summary *s, bool allow_negative);

/*
 * 就地构造一个最小合规的**失败应答**（方案 §18 的严格模式要求）。
 *
 * 为什么必须做这件事：上游失效时**静默丢包**不是「严格」，只是把失败
 * 转嫁给调用方——客户端会一直等到自己的超时（实测 3 s+），而且拿不到任何
 * 可区分的信号。RFC 1035 的语义是「有响应、响应里说失败」。因此这里按
 * 请求原样回填 ID 与问题区，置 QR=1、给定 rcode、其余计数为 0。
 *
 * 三条刻意的取舍：
 *  1. **不回填 OPT**：EDNS0 里 OPT 的 TTL 字段承载 ext-rcode/版本/flags，
 *     要正确回填就得连 badvers 语义一起实现；而失败应答回填 OPT 并无收益
 *     （RFC 6891 允许应答方不实现 EDNS，客户端会退化）。少一个出错面。
 *  2. **保留 opcode/RD/CD，清掉 AA/TC/RA/AD/Z**：AD 尤其不能带——那是
 *     「已做 DNSSEC 验证」的声明，失败应答上带它是伪造安全状态（§8/§10.1）。
 *  3. **question 解析失败时不回填问题区**（QDCOUNT=0）而不是整体拒绝：
 *     畸形请求也应当收到 FORMERR，而不是被无声丢弃。
 *
 * 返回 KDG_W_OK 并写入 *out_len，或 KDG_W_EARG / KDG_W_ETRUNC / KDG_W_EBOUNDS。
 */
int kdg_wire_make_error_response(const u8 *query, size_t qlen, u8 rcode,
				 u8 *out, size_t out_cap, size_t *out_len);

#endif /* _KDG_WIRE_H */
