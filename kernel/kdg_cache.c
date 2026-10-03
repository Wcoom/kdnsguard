/* SPDX-License-Identifier: GPL-2.0 */
/*
 * kdg_cache.c —— DNS 缓存核心逻辑实现。设计与约束见 kdg_cache.h。
 *
 * 本文件双态可编译：只用 kdg_base.h 与 kdg_wire.h 提供的原语，不引入内核头。
 * 存储、锁与分配在 kdg_cache_tab.c（内核专属）。
 */
#include "kdg_cache.h"

/* ── 键 ──────────────────────────────────────────────────────────────── */

int kdg_cache_key_from_query(const struct kdg_query *q, u32 net_id,
			     u32 profile_gen, struct kdg_cache_key *out)
{
	if (!q || !out)
		return -KDG_CKE_BADARG;

	memset(out, 0, sizeof(*out));

	/*
	 * 带 ECS 或 DNS Cookie 的请求：**拒绝缓存与合并**，而不是把它们
	 * 并进键里。方案 §7.2 允许「完整变体键或者走不缓存/不合并路径」，
	 * 这里选后者，理由是：
	 *   - ECS 的语义就是「按来源子网给不同答案」，把子网并进键等于
	 *     对每个客户端各存一份，缓存命中率归零，却仍要付内存与查找成本；
	 *   - Cookie 是逐客户端的挑战/应答，天然不可共享；
	 *   - 这两类请求在真实负载里占比很低，拒绝它们的代价远小于
	 *     让它们污染整个缓存与合并表。
	 */
	if (q->edns_has_ecs || q->edns_has_cookie)
		return -KDG_CKE_NOTCACHEABLE;

	if (q->qname.len == 0 || q->qname.len > KDG_CACHE_MAX_QNAME)
		return -KDG_CKE_BADARG;
	if (q->qclass == 0)
		return -KDG_CKE_BADARG;

	memcpy(out->qname, q->qname.wire, q->qname.len);
	out->qname_len = q->qname.len;
	out->qtype = q->qtype;
	out->qclass = q->qclass;
	out->net_id = net_id;
	out->profile_gen = profile_gen;

	/* RD/CD/DO/EDNS 都要进键：它们会改变上游的返回语义。
	 * 尤其 CD（禁用 DNSSEC 验证）与 DO（要 DNSSEC 记录）—— 混在一起
	 * 会让开了 DO 的调用方拿到没有 RRSIG 的缓存结果。 */
	if (q->flags & KDG_DNS_F_RD)
		out->flags |= KDG_CKF_RD;
	if (q->flags & KDG_DNS_F_CD)
		out->flags |= KDG_CKF_CD;
	if (q->edns_do)
		out->flags |= KDG_CKF_DO;
	if (q->has_edns)
		out->flags |= KDG_CKF_EDNS;

	return KDG_CKE_OK;
}

/* FNV-1a：无查表、无分配、对短输入足够分散，适合内核侧哈希表。 */
static u32 fnv1a(u32 h, const u8 *p, size_t n)
{
	size_t i;

	for (i = 0; i < n; i++) {
		h ^= p[i];
		h *= 16777619u;
	}
	return h;
}

u32 kdg_cache_key_hash(const struct kdg_cache_key *k)
{
	u32 h = 2166136261u;
	/* 只哈希**参与相等比较**的字段：reserved_ 必须排除，否则同一逻辑键
	 * 会因结构体填充字节不同而散进不同桶，缓存命中率凭空变差。 */
	u8 tail[14];

	h = fnv1a(h, k->qname, k->qname_len);

	tail[0] = (u8)(k->qname_len >> 8);
	tail[1] = (u8)k->qname_len;
	tail[2] = (u8)(k->qtype >> 8);
	tail[3] = (u8)k->qtype;
	tail[4] = (u8)(k->qclass >> 8);
	tail[5] = (u8)k->qclass;
	tail[6] = k->flags;
	tail[7] = 0;
	tail[8] = (u8)(k->net_id >> 24);
	tail[9] = (u8)(k->net_id >> 16);
	tail[10] = (u8)(k->net_id >> 8);
	tail[11] = (u8)k->net_id;
	tail[12] = (u8)(k->profile_gen >> 8);
	tail[13] = (u8)k->profile_gen;

	return fnv1a(h, tail, sizeof(tail));
}

bool kdg_cache_key_eq(const struct kdg_cache_key *a,
		      const struct kdg_cache_key *b)
{
	if (a->qname_len != b->qname_len)
		return false;
	if (a->qtype != b->qtype || a->qclass != b->qclass)
		return false;
	if (a->flags != b->flags)
		return false;
	if (a->net_id != b->net_id || a->profile_gen != b->profile_gen)
		return false;
	if (a->qname_len && memcmp(a->qname, b->qname, a->qname_len) != 0)
		return false;
	return true;
}

/* ── 新鲜度 ──────────────────────────────────────────────────────────── */

bool kdg_cache_fresh(const struct kdg_cache_tmpl *t, u64 now_ms)
{
	if (!t || t->ttl_ms == 0)
		return false;
	/* 用无符号减法：即使调用方传入的 now_ms 早于 stored_ms（时钟源切换、
	 * 测试构造），也不会得到一个巨大的「已过去时间」而误判为新鲜。 */
	if (now_ms < t->stored_ms)
		return false;
	return (now_ms - t->stored_ms) < (u64)t->ttl_ms;
}

/* ── 回包重封装 ──────────────────────────────────────────────────────── */

/* 走一遍调用方问题区的名字，返回其 wire 长度；失败返回 0。
 * 目的有二：确认它**未被压缩**、确认它与模板的问题区**等长**。
 * 前者不确认的话，逐字节替换会把一个压缩指针当成名字字节写坏；
 * 后者不确认的话，替换会越界或错位。 */
static u16 caller_qname_len(const u8 *q, size_t qlen)
{
	size_t p = KDG_DNS_HDR_LEN;
	size_t total = 0;

	for (;;) {
		u8 l;

		if (p >= qlen)
			return 0;
		l = q[p];
		if (l & 0xc0)
			return 0;	/* 压缩指针：此处不接受 */
		p++;
		total += (size_t)l + 1;
		if (total > KDG_CACHE_MAX_QNAME)
			return 0;
		if (l == 0)
			break;
		if (p + l > qlen)
			return 0;
		p += l;
	}
	return (u16)total;
}

int kdg_cache_repack(const struct kdg_cache_tmpl *t, u64 now_ms,
		     const u8 *caller_query, size_t caller_query_len,
		     u8 *out, size_t out_cap, size_t *out_len)
{
	u32 elapsed_sec;
	u16 i;

	if (!t || !t->msg || !caller_query || !out || !out_len)
		return -KDG_CRE_BADARG;

	*out_len = 0;

	if (!kdg_cache_fresh(t, now_ms))
		return -KDG_CRE_STALE;
	if (t->msg_len > out_cap)
		return -KDG_CRE_SMALL;

	/* 模板侧自检：问题区必须从报文头之后开始、未压缩、且落在报文内。 */
	if (t->qname_off != KDG_DNS_HDR_LEN || t->qname_len == 0)
		return -KDG_CRE_PACK;
	if ((size_t)t->qname_off + (size_t)t->qname_len + 4 > t->msg_len)
		return -KDG_CRE_PACK;
	if (t->msg[t->qname_off] & 0xc0)
		return -KDG_CRE_PACK;

	if (caller_qname_len(caller_query, caller_query_len) != t->qname_len)
		return -KDG_CRE_PACK;

	memcpy(out, t->msg, t->msg_len);

	/* 1) 恢复调用方的 DNS ID。方案 §7.3：上游 ID 规范为 0、回包时恢复，
	 *    不按 16 位 ID 索引（那会在 ID 碰撞时串包）。 */
	out[0] = caller_query[0];
	out[1] = caller_query[1];

	/* 2) 问题区用调用方的**原始字节**，保住它的大小写（§7.2「原样保留」）。
	 *    不能拿 kdg_wire 解析出的 qname —— 那是小写规范化的。 */
	memcpy(out + KDG_DNS_HDR_LEN, caller_query + KDG_DNS_HDR_LEN,
	       t->qname_len);

	/* 3) 逐 TTL 字段扣掉已流逝的秒数。**绝不刷回原值**（§8）。
	 *    向下取整到秒：早 0.9 秒取到也算 0 秒，宁可多给一点 TTL，
	 *    也不要因为取整把 TTL 提前削掉一秒而让缓存过早失效。 */
	elapsed_sec = (u32)((now_ms - t->stored_ms) / 1000u);
	if (elapsed_sec) {
		for (i = 0; i < t->n_ttl; i++) {
			u16 o = t->ttl_offs[i];
			u32 ttl;

			if ((size_t)o + 4 > t->msg_len)
				return -KDG_CRE_PACK;

			ttl = ((u32)out[o] << 24) | ((u32)out[o + 1] << 16) |
			      ((u32)out[o + 2] << 8) | (u32)out[o + 3];
			ttl = (ttl > elapsed_sec) ? (ttl - elapsed_sec) : 0;

			out[o] = (u8)(ttl >> 24);
			out[o + 1] = (u8)(ttl >> 16);
			out[o + 2] = (u8)(ttl >> 8);
			out[o + 3] = (u8)ttl;
		}
	}

	*out_len = t->msg_len;
	return 0;
}
