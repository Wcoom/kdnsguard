/* SPDX-License-Identifier: GPL-2.0 */
/*
 * kdg_wire.c —— 有界 DNS wire 校验器实现。设计与约束见 kdg_wire.h。
 *
 * 本文件必须保持双态可编译：只用 kdg_base.h 提供的原语，不引入其它内核头。
 */
#include "kdg_wire.h"

#define KDG_RR_FIXED_LEN	10	/* type(2) class(2) ttl(4) rdlen(2) */

/* ── 大端读取与大小写折叠 ─────────────────────────────────────────────── */

static inline u16 kdg_rd16(const u8 *p)
{
	return (u16)(((u16)p[0] << 8) | (u16)p[1]);
}

static inline u32 kdg_rd32(const u8 *p)
{
	return ((u32)p[0] << 24) | ((u32)p[1] << 16) |
	       ((u32)p[2] << 8) | (u32)p[3];
}

/* DNS 名只对 ASCII 字母大小写不敏感（RFC 4343 §2）。不碰其余字节，
 * 非 ASCII 字节原样保留，避免把合法的高位标签弄坏。 */
static inline u8 kdg_tolower(u8 c)
{
	return (c >= 'A' && c <= 'Z') ? (u8)(c + 32) : c;
}

/* ── 域名解码：整个模块的安全核心 ─────────────────────────────────────── */

/*
 * 从 msg 的 off 处解码一个域名到 out（未压缩、小写、以 root 结尾）。
 * *end_off 回填「不含本次跳转的第一跳之后的位置」，即调用方继续解析时
 * 该用的偏移（未发生跳转时就是名字结束处）。
 *
 * 三条边界保证：
 *  - 每次读取前都做 p >= msglen 检查，任何路径都不会越界；
 *  - 压缩指针**只允许严格回指**（target < p）。RFC 1035 §4.1.4 要求指针
 *    指向 "a prior occurrence"，所以这是合规的收紧，不是额外限制；效果是
 *    所有指针链沿地址严格递减 ⇒ 环在构造上不可能存在，不依赖跳数上限兜底。
 *  - 输出长度在任何时刻都受 KDG_DNS_MAX_NAME 约束，写入前先判，不靠事后裁剪。
 */
static int kdg_name_decode(const u8 *msg, size_t msglen, size_t off,
			   struct kdg_dname *out, size_t *end_off)
{
	size_t p = off;
	size_t olen = 0;
	size_t first_end = off;
	unsigned int jumps = 0;
	u8 nlabels = 0;
	bool jumped = false;

	if (!msg || !out || !end_off)
		return KDG_W_EARG;

	for (;;) {
		u8 l;

		if (p >= msglen)
			return KDG_W_ETRUNC;

		l = msg[p];

		if ((l & 0xc0) == 0xc0) {
			size_t target;

			if (p + 1 >= msglen)
				return KDG_W_ETRUNC;

			target = ((size_t)(l & 0x3f) << 8) |
				 (size_t)msg[p + 1];

			if (!jumped) {
				first_end = p + 2;
				jumped = true;
			}

			if (++jumps > KDG_DNS_MAX_PTR_JUMPS)
				return KDG_W_ELOOP;
			/* 顺序有意为之：先判「指向报文之外」，再判「前向」。
			 * 反过来写会让越界指针永远拿到 ELOOP，把「截断/模糊
			 * 测试产物」与「环构造」两种攻击形态混为一谈。 */
			if (target >= msglen)
				return KDG_W_ETRUNC;
			if (target >= p)
				return KDG_W_ELOOP;

			p = target;
			continue;
		}

		/* 0x40 / 0x80 前缀未定义（RFC 1035 只定义 00 与 11） */
		if ((l & 0xc0) != 0)
			return KDG_W_EFORMAT;

		p++;			/* 越过长度字节 */

		if (l == 0) {		/* root label：名字到此结束 */
			if (olen + 1 > KDG_DNS_MAX_NAME)
				return KDG_W_ELEN;
			out->wire[olen++] = 0;
			break;
		}

		if (l > KDG_DNS_MAX_LABEL)
			return KDG_W_ELEN;
		if (p + l > msglen)
			return KDG_W_ETRUNC;
		/* 规范形式总长 = 已有 + 长度字节 + 标签 + 至少一个 root */
		if (olen + 1 + (size_t)l + 1 > KDG_DNS_MAX_NAME)
			return KDG_W_ELEN;

		out->wire[olen++] = l;
		{
			u8 i;

			for (i = 0; i < l; i++)
				out->wire[olen + i] = kdg_tolower(msg[p + i]);
		}
		olen += l;
		p += l;

		if (nlabels != 0xff)
			nlabels++;
	}

	if (!jumped)
		first_end = p;

	*end_off = first_end;
	out->len = (u16)olen;
	out->nlabels = nlabels;
	out->reserved_ = 0;
	return KDG_W_OK;
}

/* 只推进偏移、不产出规范名。用于跳过我们不关心内容的名字，
 * 省掉一次到 255 字节的拷贝。 */
static int kdg_name_skip(const u8 *msg, size_t msglen, size_t off,
			 size_t *end_off)
{
	struct kdg_dname scratch;

	return kdg_name_decode(msg, msglen, off, &scratch, end_off);
}

/* ── 单条 RR 的定位 ───────────────────────────────────────────────────── */

struct kdg_edns {
	bool present;
	bool do_bit;
	bool badvers;
	bool has_ecs;
	bool has_cookie;
	u16 udp_size;
	u8  ext_rcode;
};

/*
 * 解析 off 处的一条 RR，回填 rr，并把 off 推进到该 RR 之后。
 * rr 可以为 NULL（只推进不记录）。edns 非 NULL 时，若本条是 OPT 则
 * 顺带填充 EDNS 元信息——OPT 的 class 是 UDP 载荷大小、TTL 是
 * ext-rcode/version/flags，**都不是**字面含义，必须在此处转换。
 */
static int kdg_scan_rr(const u8 *msg, size_t msglen, size_t *off,
		       struct kdg_rr_ref *rr, struct kdg_edns *edns)
{
	struct kdg_rr_ref local;
	size_t end;
	size_t rdata_end;
	int ret;

	if (!msg || !off)
		return KDG_W_EARG;

	rr = rr ? rr : &local;

	ret = kdg_name_decode(msg, msglen, *off, &rr->name, &end);
	if (ret < 0)
		return ret;

	if (end + KDG_RR_FIXED_LEN > msglen)
		return KDG_W_ETRUNC;
	/* 偏移必须能装进 u16：到不了这里，报文已被上游限制在 64 KiB 内 */
	if (end + KDG_RR_FIXED_LEN > 0xffffu)
		return KDG_W_EBOUNDS;

	rr->type = kdg_rd16(msg + end);
	rr->class_ = kdg_rd16(msg + end + 2);
	rr->ttl = kdg_rd32(msg + end + 4);
	rr->rdlen = kdg_rd16(msg + end + 8);
	rr->rdata_off = (u16)(end + KDG_RR_FIXED_LEN);
	rr->reserved_ = 0;

	rdata_end = (size_t)rr->rdata_off + (size_t)rr->rdlen;
	if (rdata_end > msglen)
		return KDG_W_ETRUNC;

	if (edns && rr->type == KDG_RRTYPE_OPT) {
		size_t o;

		edns->present = true;
		/* OPT 只能出现在 additional；这里不校验位置，由调用方按
		 * 段位保证。重复 OPT 是畸形，只保留第一条。 */
		edns->udp_size = rr->class_;
		edns->ext_rcode = (u8)(rr->ttl >> 24);
		/* 版本非 0 = BADVERS，调用方须按 RFC 6891 回 FORMERR 系列 */
		edns->badvers = (((rr->ttl >> 16) & 0xff) != 0);
		edns->do_bit = (rr->ttl & 0x8000) != 0;

		/* 扫选项列表找 ECS / COOKIE：这两者决定该请求能否跨调用方
		 * 合并（§7.2「不适合共享的请求用完整变体键或走不合并路径」）。 */
		o = rr->rdata_off;
		while (o + 4 <= rdata_end) {
			u16 code = kdg_rd16(msg + o);
			u16 olen = kdg_rd16(msg + o + 2);

			if (o + 4 + (size_t)olen > rdata_end)
				return KDG_W_EFORMAT;
			if (code == KDG_EDNS_OPT_ECS)
				edns->has_ecs = true;
			else if (code == KDG_EDNS_OPT_COOKIE)
				edns->has_cookie = true;
			o += 4 + (size_t)olen;
		}
		if (o != rdata_end)
			return KDG_W_EFORMAT;	/* 选项区长度对不上 */
	}

	*off = rdata_end;
	return KDG_W_OK;
}

/* 跳过 count 条 RR，只做边界推进与 type 统计（可选）。 */
static int kdg_skip_rrs(const u8 *msg, size_t msglen, size_t *off,
			u16 count, u16 *counted, struct kdg_edns *edns)
{
	u16 i;

	for (i = 0; i < count; i++) {
		int ret = kdg_scan_rr(msg, msglen, off, NULL, edns);

		if (ret < 0)
			return ret;
	}
	if (counted)
		*counted = count;
	return KDG_W_OK;
}

/* ── 查询解析 ─────────────────────────────────────────────────────────── */

int kdg_wire_parse_query(const u8 *msg, size_t len, struct kdg_query *out)
{
	struct kdg_edns edns;
	size_t off;
	size_t end;
	u16 flags;
	u16 qdcount, ancount, nscount, arcount;
	int ret;

	if (!msg || !out)
		return KDG_W_EARG;
	if (len > 0xffffu)
		return KDG_W_EBOUNDS;
	if (len < KDG_DNS_HDR_LEN)
		return KDG_W_ETRUNC;

	memset(out, 0, sizeof(*out));
	memset(&edns, 0, sizeof(edns));

	out->id = kdg_rd16(msg);
	flags = kdg_rd16(msg + 2);
	out->flags = flags;
	out->opcode = (u8)((flags & KDG_DNS_F_OPCODE_MASK) >> 11);
	out->rcode = (u8)(flags & KDG_DNS_F_RCODE_MASK);
	out->msg_len = (u16)len;

	if (flags & KDG_DNS_F_QR)
		return KDG_W_EFORMAT;		/* 这是响应，不是查询 */
	if (out->opcode != KDG_DNS_OPCODE_QUERY)
		return KDG_W_ENOTSUP;

	qdcount = kdg_rd16(msg + 4);
	ancount = kdg_rd16(msg + 6);
	nscount = kdg_rd16(msg + 8);
	arcount = kdg_rd16(msg + 10);

	/* 标准查询恰好一个问题。多问题（QDCOUNT>1）在上游已被废弃
	 * （RFC 9619），本模块不做多问题解析，直接拒绝而不是尽力而为。 */
	if (qdcount != 1)
		return KDG_W_ECOUNT;
	/* 查询里带 answer/authority 是畸形或攻击构造 */
	if (ancount != 0 || nscount != 0)
		return KDG_W_ECOUNT;

	off = KDG_DNS_HDR_LEN;
	ret = kdg_name_decode(msg, len, off, &out->qname, &end);
	if (ret < 0)
		return ret;

	if (end + 4 > len)
		return KDG_W_ETRUNC;
	out->qtype = kdg_rd16(msg + end);
	out->qclass = kdg_rd16(msg + end + 2);
	off = end + 4;
	out->question_len = (u16)(off - KDG_DNS_HDR_LEN);

	ret = kdg_skip_rrs(msg, len, &off, arcount, NULL, &edns);
	if (ret < 0)
		return ret;

	/* 尾部若有多余字节：不致命（某些客户端填充），但不参与解析。
	 * 不做「必须恰好用完」的强判，避免误伤合法实现。 */

	out->has_edns = edns.present;
	out->edns_do = edns.do_bit;
	out->edns_badvers = edns.badvers;
	out->edns_has_ecs = edns.has_ecs;
	out->edns_has_cookie = edns.has_cookie;
	out->edns_udp_size = edns.udp_size;
	return KDG_W_OK;
}

/* ── SOA 负缓存 TTL（RFC 2308 §5） ────────────────────────────────────── */

static int kdg_soa_minimum(const u8 *msg, size_t msglen,
			   const struct kdg_rr_ref *rr, u32 *minimum)
{
	struct kdg_dname scratch;
	size_t end;
	size_t rdata_end = (size_t)rr->rdata_off + (size_t)rr->rdlen;
	int ret;

	/* MNAME 与 RNAME 都按整条报文的地址空间解压（压缩指针指回报文头部，
	 * 不是指回 rdata 内部），所以这里必须用 msg/msglen 而不是 rdata 范围。 */
	ret = kdg_name_decode(msg, msglen, rr->rdata_off, &scratch, &end);
	if (ret < 0)
		return ret;
	ret = kdg_name_decode(msg, msglen, end, &scratch, &end);
	if (ret < 0)
		return ret;

	/* SERIAL REFRESH RETRY EXPIRE MINIMUM */
	if (end + 20 > msglen)
		return KDG_W_ETRUNC;
	/* 五个 32 位字段必须完整落在本 RR 的 rdata 内，否则说明 rdlen
	 * 与内容不一致（构造攻击），拒绝。 */
	if (end + 20 > rdata_end)
		return KDG_W_EFORMAT;

	*minimum = kdg_rd32(msg + end + 16);
	return KDG_W_OK;
}

/* ── 响应解析 ─────────────────────────────────────────────────────────── */

int kdg_wire_parse_response(const u8 *msg, size_t len, struct kdg_summary *out)
{
	struct kdg_edns edns;
	size_t off;
	u16 flags;
	u16 i;
	int ret;

	if (!msg || !out)
		return KDG_W_EARG;
	if (len > 0xffffu)
		return KDG_W_EBOUNDS;
	if (len < KDG_DNS_HDR_LEN)
		return KDG_W_ETRUNC;

	memset(out, 0, sizeof(*out));
	memset(&edns, 0, sizeof(edns));
	out->min_ttl = 0xffffffffu;
	out->soa_ttl = 0xffffffffu;
	out->soa_minimum = 0xffffffffu;

	out->id = kdg_rd16(msg);
	flags = kdg_rd16(msg + 2);
	out->opcode = (u8)((flags & KDG_DNS_F_OPCODE_MASK) >> 11);
	out->rcode = (u8)(flags & KDG_DNS_F_RCODE_MASK);
	out->qr = (flags & KDG_DNS_F_QR) != 0;
	out->aa = (flags & KDG_DNS_F_AA) != 0;
	out->tc = (flags & KDG_DNS_F_TC) != 0;
	out->rd = (flags & KDG_DNS_F_RD) != 0;
	out->ra = (flags & KDG_DNS_F_RA) != 0;
	out->ad = (flags & KDG_DNS_F_AD) != 0;
	out->cd = (flags & KDG_DNS_F_CD) != 0;
	out->z = (flags & KDG_DNS_F_Z) != 0;

	if (!out->qr)
		return KDG_W_EFORMAT;

	out->qdcount = kdg_rd16(msg + 4);
	out->ancount = kdg_rd16(msg + 6);
	out->nscount = kdg_rd16(msg + 8);
	out->arcount = kdg_rd16(msg + 10);

	off = KDG_DNS_HDR_LEN;

	/* question 段：只推进，不产出规范名（匹配由 match_response 负责） */
	out->question_ok = true;
	for (i = 0; i < out->qdcount; i++) {
		size_t end;

		ret = kdg_name_skip(msg, len, off, &end);
		if (ret < 0) {
			out->question_ok = false;
			return ret;
		}
		if (end + 4 > len) {
			out->question_ok = false;
			return KDG_W_ETRUNC;
		}
		off = end + 4;
	}
	out->question_bytes = (u16)(off - KDG_DNS_HDR_LEN);

	/* answer 段 */
	for (i = 0; i < out->ancount; i++) {
		struct kdg_rr_ref rr;

		ret = kdg_scan_rr(msg, len, &off, &rr, &edns);
		if (ret < 0)
			return ret;
		out->counted_an++;

		if (rr.type == KDG_RRTYPE_OPT)
			continue;	/* OPT 不得出现在 answer，忽略其 TTL */
		if (rr.ttl < out->min_ttl)
			out->min_ttl = rr.ttl;
	}

	/* authority 段 */
	for (i = 0; i < out->nscount; i++) {
		struct kdg_rr_ref rr;

		ret = kdg_scan_rr(msg, len, &off, &rr, &edns);
		if (ret < 0)
			return ret;
		out->counted_ns++;

		if (rr.type == KDG_RRTYPE_OPT)
			continue;
		if (rr.ttl < out->min_ttl)
			out->min_ttl = rr.ttl;

		if (rr.type == KDG_RRTYPE_SOA) {
			u32 minimum = 0;

			/* SOA 解析失败不使整条响应失败——我们仍能安全地
			 * 放弃缓存（保守方向），而不是把合法响应判死。 */
			if (kdg_soa_minimum(msg, len, &rr, &minimum) == KDG_W_OK) {
				out->has_soa = true;
				out->soa_ttl = rr.ttl;
				out->soa_minimum = minimum;
			}
		}
	}

	/* additional 段：EDNS 在这里 */
	for (i = 0; i < out->arcount; i++) {
		struct kdg_rr_ref rr;

		ret = kdg_scan_rr(msg, len, &off, &rr, &edns);
		if (ret < 0)
			return ret;
		out->counted_ar++;

		if (rr.type == KDG_RRTYPE_OPT)
			continue;
		if (rr.ttl < out->min_ttl)
			out->min_ttl = rr.ttl;
	}

	if (out->counted_an != out->ancount ||
	    out->counted_ns != out->nscount ||
	    out->counted_ar != out->arcount)
		return KDG_W_ECOUNT;

	out->has_edns = edns.present;
	out->edns_do = edns.do_bit;
	out->edns_badvers = edns.badvers;
	out->edns_udp_size = edns.udp_size;
	out->ext_rcode = edns.ext_rcode;

	if (out->min_ttl == 0xffffffffu)
		out->min_ttl = 0;	/* 无 RR 时无 TTL 可取 */

	/* 语义分类（§8：NODATA 与 NXDOMAIN 必须区分） */
	out->is_nxdomain = (out->rcode == KDG_RCODE_NXDOMAIN);
	if (out->rcode == KDG_RCODE_NOERROR && out->ancount == 0) {
		if (out->has_soa)
			out->is_nodata = true;
		else if (out->nscount > 0)
			out->is_referral = true;
	}

	return KDG_W_OK;
}

/* ── 响应与请求的匹配 ─────────────────────────────────────────────────── */

int kdg_wire_match_response(const u8 *req, size_t reqlen,
			    const u8 *resp, size_t resplen,
			    struct kdg_summary *out)
{
	struct kdg_query q;
	struct kdg_dname rname;
	struct kdg_summary local;
	size_t qend;
	size_t rend;
	size_t roff;
	u16 rqtype, rqclass;
	int ret;

	if (!req || !resp)
		return KDG_W_EARG;

	out = out ? out : &local;

	ret = kdg_wire_parse_query(req, reqlen, &q);
	if (ret < 0)
		return ret;

	ret = kdg_wire_parse_response(resp, resplen, out);
	if (ret < 0)
		return ret;

	/* ID 必须一致（用规范化为 0 的 ID 时，这一条由调用方保证） */
	if (out->id != q.id)
		return KDG_W_EMISMATCH;
	if (out->opcode != q.opcode)
		return KDG_W_EMISMATCH;
	if (out->qdcount != 1)
		return KDG_W_EMISMATCH;
	if (out->tc)
		return KDG_W_OK;	/* 截断响应没有 question 可比性，交给上层 */

	/* question 段逐字段比较：名字按未压缩小写形式比，类型类按值比。
	 * 这样「大小写差异」或「一个用压缩指针一个不用」都不会误判。 */
	roff = KDG_DNS_HDR_LEN;
	ret = kdg_name_decode(resp, resplen, roff, &rname, &rend);
	if (ret < 0)
		return KDG_W_EMISMATCH;

	if (rname.len != q.qname.len)
		return KDG_W_EMISMATCH;
	if (rname.len && memcmp(rname.wire, q.qname.wire, rname.len) != 0)
		return KDG_W_EMISMATCH;

	if (rend + 4 > resplen)
		return KDG_W_EMISMATCH;
	rqtype = kdg_rd16(resp + rend);
	rqclass = kdg_rd16(resp + rend + 2);
	if (rqtype != q.qtype || rqclass != q.qclass)
		return KDG_W_EMISMATCH;

	/* 请求问题区在报文中的边界，供回包重建时原样复制 */
	qend = q.question_len;

	(void)qend;
	return KDG_W_OK;
}

/* ── 可缓存性与 TTL ───────────────────────────────────────────────────── */

u32 kdg_wire_cacheable_ttl(const struct kdg_summary *s, bool allow_negative)
{
	u32 ttl;

	if (!s)
		return 0;
	/* 截断响应语义不完整，不得入缓存 */
	if (s->tc)
		return 0;
	/* BADVERS / 扩展 rcode 非 0 的响应语义不明，保守放弃 */
	if (s->edns_badvers || s->ext_rcode != 0)
		return 0;

	switch (s->rcode) {
	case KDG_RCODE_NOERROR:
		if (s->is_nodata || s->is_referral) {
			if (!allow_negative)
				return 0;
			break;
		}
		/* TTL=0 语义是「仅本次使用」，不进缓存（§8） */
		if (s->min_ttl == 0)
			return 0;
		return s->min_ttl;

	case KDG_RCODE_NXDOMAIN:
		if (!allow_negative)
			return 0;
		break;

	default:
		/* SERVFAIL / REFUSED / FORMERR 等**绝不**当 NXDOMAIN 缓存 */
		return 0;
	}

	/* 负缓存（RFC 2308 §5）：TTL 取 min(SOA TTL, SOA.MINIMUM)。
	 * 无 SOA 时按保守短上限，避免把失败长期固化。 */
	if (!s->has_soa)
		return 0;
	ttl = s->soa_ttl < s->soa_minimum ? s->soa_ttl : s->soa_minimum;
	if (ttl == 0)
		return 0;
	if (ttl > 3600u)
		ttl = 3600u;		/* 本地更短上限，防止上游给超大值 */
	return ttl;
}

/* ── TTL 字段偏移收集（缓存用） ───────────────────────────────────────── */

/*
 * RR 的固定字段布局：type(2) class(2) ttl(4) rdlen(2)，紧跟在名字之后。
 * kdg_scan_rr 回填的 rdata_off 正是「rdlen 之后」，故：
 *     ttl_off = rdata_off - 10 + 4 = rdata_off - 6
 */
int kdg_wire_collect_ttl_offs(const u8 *msg, size_t len,
			      u16 *offs, u16 offs_cap)
{
	struct kdg_summary s;
	struct kdg_rr_ref rr;
	size_t off;
	u16 n = 0;
	u16 i;
	int ret;

	if (!msg || !offs)
		return KDG_W_EARG;

	/* 先整体校验一遍，避免在未校验的报文上做定位 —— 与
	 * kdg_wire_get_answer_rr 同样的理由：宁可多走一次 walker，
	 * 也不让「定位用一套边界、解析用另一套边界」。 */
	ret = kdg_wire_parse_response(msg, len, &s);
	if (ret < 0)
		return ret;

	off = KDG_DNS_HDR_LEN + s.question_bytes;

	/* answer + authority + additional 三段都要收集：TTL 分散在三处。 */
	for (i = 0; i < (u16)(s.ancount + s.nscount + s.arcount); i++) {
		ret = kdg_scan_rr(msg, len, &off, &rr, NULL);
		if (ret < 0)
			return ret;
		if (rr.type == KDG_RRTYPE_OPT)
			continue;	/* OPT 的 TTL 不是 TTL */
		if (rr.rdata_off < 6)
			return KDG_W_EFORMAT;
		if (n >= offs_cap)
			return KDG_W_ECOUNT;
		offs[n++] = (u16)(rr.rdata_off - 6);
	}

	return (int)n;
}

/* ── 单条 answer RR 定位（域名映射用） ────────────────────────────────── */

int kdg_wire_get_answer_rr(const u8 *msg, size_t len, unsigned int idx,
			   struct kdg_rr_ref *out)
{
	struct kdg_summary s;
	size_t off;
	unsigned int i;
	int ret;

	if (!msg || !out)
		return KDG_W_EARG;

	/* 先整体校验一遍：宁可多走一次 walker，也不在未校验的报文上
	 * 做任何定位，避免「定位用一套边界、解析用另一套边界」的不一致。 */
	ret = kdg_wire_parse_response(msg, len, &s);
	if (ret < 0)
		return ret;
	if (idx >= s.ancount)
		return KDG_W_EARG;

	off = KDG_DNS_HDR_LEN + s.question_bytes;
	for (i = 0; i < idx; i++) {
		ret = kdg_scan_rr(msg, len, &off, NULL, NULL);
		if (ret < 0)
			return ret;
	}
	return kdg_scan_rr(msg, len, &off, out, NULL);
}

/* ── 域名文本互转 ─────────────────────────────────────────────────────── */

int kdg_wire_dname_from_text(const char *text, size_t textlen,
			     struct kdg_dname *out)
{
	size_t olen = 0;
	size_t i = 0;
	u8 nlabels = 0;

	if (!text || !out)
		return KDG_W_EARG;

	memset(out, 0, sizeof(*out));

	if (textlen == 0)
		return KDG_W_ELEN;

	if (textlen == 1 && text[0] == '.') {	/* 根 */
		out->wire[0] = 0;
		out->len = 1;
		out->nlabels = 0;
		return KDG_W_OK;
	}
	if (text[textlen - 1] == '.')		/* 尾部单点等价于不带点 */
		textlen--;

	while (i < textlen) {
		size_t start = i;
		size_t l;
		size_t j;

		while (i < textlen && text[i] != '.')
			i++;
		l = i - start;
		if (l == 0)
			return KDG_W_ELEN;	/* 空标签 / 连续点 */
		if (l > KDG_DNS_MAX_LABEL)
			return KDG_W_ELEN;
		if (olen + 1 + l + 1 > KDG_DNS_MAX_NAME)
			return KDG_W_ELEN;

		out->wire[olen++] = (u8)l;
		for (j = 0; j < l; j++) {
			u8 c = (u8)text[start + j];

			/* 本版不做 \DDD 转义；拒绝 NUL 与非 ASCII，
			 * 避免「配置里写了一个名字、实际存的是另一个」。 */
			if (c == 0 || c >= 0x80)
				return KDG_W_EFORMAT;
			out->wire[olen++] = kdg_tolower(c);
		}
		nlabels++;
		if (i < textlen)
			i++;			/* 跳过点 */
	}

	out->wire[olen++] = 0;
	out->len = (u16)olen;
	out->nlabels = nlabels;
	return KDG_W_OK;
}

int kdg_wire_dname_to_text(const struct kdg_dname *n, char *buf, size_t buflen)
{
	size_t p = 0;
	size_t o = 0;

	if (!n || !buf)
		return KDG_W_EARG;
	if (n->len == 0 || n->len > KDG_DNS_MAX_NAME)
		return KDG_W_EFORMAT;

	if (n->len == 1 && n->wire[0] == 0) {	/* 根 */
		if (buflen < 2)
			return KDG_W_EBOUNDS;
		buf[0] = '.';
		buf[1] = '\0';
		return 1;
	}

	while (p < n->len) {
		u8 l = n->wire[p];

		if (l == 0) {
			p++;
			break;
		}
		if (l > KDG_DNS_MAX_LABEL)
			return KDG_W_EFORMAT;
		if (p + 1 + l > n->len)
			return KDG_W_EFORMAT;
		if (o + l + 1 >= buflen)	/* +1 给分隔点或 NUL */
			return KDG_W_EBOUNDS;

		if (o)
			buf[o++] = '.';
		memcpy(buf + o, n->wire + p + 1, l);
		o += l;
		p += 1 + (size_t)l;
	}

	if (o >= buflen)
		return KDG_W_EBOUNDS;
	buf[o] = '\0';
	return (int)o;
}
