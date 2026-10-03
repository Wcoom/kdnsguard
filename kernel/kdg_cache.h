/* SPDX-License-Identifier: GPL-2.0 */
/*
 * kdg_cache.h —— DNS 缓存的核心逻辑（方案 §8）。
 *
 * 本文件保持**双态可编译**，理由与 kdg_wire.c / kdg_http.c 相同：本树
 * CONFIG_KUNIT=m，设备构建里跑不了 KUnit 用例，而缓存里最容易错的两块
 * ——回包重封装（改 ID、换问题区、逐条递减 TTL）与淘汰决策——恰恰是
 * 必须靠语料反复验证的。宿主机上有 ASan/UBSan，跑几百条用例的成本近乎为零。
 *
 * 存储、锁与内存分配**不在本文件**：那些是内核专属的，放在 kdg_cache_tab.c。
 * 这里只有纯逻辑：键的构造与比较、新鲜度判定、回包重封装、淘汰候选选择。
 *
 * 与方案 §8 的逐条对应：
 *  - 「只对查找、引用计数和替换持短锁」→ 重封装在锁外做，本文件全程不加锁
 *  - 「按经过的时间降低 TTL，绝不把 TTL 刷回原值」→ kdg_cache_repack()
 *  - 「OPT 的 TTL 字段不是普通 TTL，不能一起递减」→ TTL 偏移在录入时就
 *    排除了 OPT（见 kdg_cache_tmpl_build 的调用方 kdg_doh 侧）
 *  - 「TTL=0 不进入持久缓存」→ kdg_cache_key_flags 侧不拦，由 ttl_ms==0 判定
 *  - 「SERVFAIL/网络错误不当成 NXDOMAIN 缓存」→ 由 kdg_wire_cacheable_ttl 把关
 */
#ifndef _KDG_CACHE_H
#define _KDG_CACHE_H

#include "kdg_base.h"
#include "kdg_wire.h"

/* 单条缓存项最多记录多少个 TTL 字段偏移。典型响应 < 10 条 RR；
 * 超过上限就**不缓存**（而不是少改几个 TTL —— 那会给出 TTL 偏大的响应，
 * 在缓存过期后仍被调用方当作新鲜数据）。 */
#define KDG_CACHE_MAX_TTL_OFF	64

/* 规范问题区的上限（与 kdg_wire 的域名上限一致）。 */
#define KDG_CACHE_MAX_QNAME	KDG_DNS_MAX_NAME

/* ── 缓存键的语义位（方案 §7.2 的合并键去掉 netns/profile 后的部分）──── */
#define KDG_CKF_RD	(1u << 0)	/* 请求带 RD */
#define KDG_CKF_CD	(1u << 1)	/* 请求带 CD（不做 DNSSEC 验证） */
#define KDG_CKF_DO	(1u << 2)	/* EDNS DO 位 */
#define KDG_CKF_EDNS	(1u << 3)	/* 请求带 OPT（EDNS0） */
#define KDG_CKF_ECS	(1u << 4)	/* 请求带 ECS —— 不缓存、不合并 */
#define KDG_CKF_COOKIE	(1u << 5)	/* 请求带 DNS Cookie —— 同上 */

struct kdg_cache_key {
	u8  qname[KDG_CACHE_MAX_QNAME];	/* 规范小写、未压缩、以 root 结尾 */
	u16 qname_len;
	u16 qtype;
	u16 qclass;
	u8  flags;			/* KDG_CKF_* */
	u8  reserved_;
	u32 net_id;			/* Android netId；P2 阶段恒为 0 */
	u32 profile_gen;		/* 上游 profile 代际 */
};

/* 由已解析的查询构造键。
 * 返回 0，或 -KDG_CKE_NOTCACHEABLE 表示该查询按策略不进缓存/不合并。 */
#define KDG_CKE_OK		0
#define KDG_CKE_NOTCACHEABLE	1
#define KDG_CKE_BADARG		2

int kdg_cache_key_from_query(const struct kdg_query *q, u32 net_id,
			     u32 profile_gen, struct kdg_cache_key *out);

/* ── 引用不可变的响应模板 ─────────────────────────────────────────────
 * 这些指针都指向缓存项自己的存储，调用期间必须保持有效（由调用方持引用）。 */
struct kdg_cache_tmpl {
	const u8 *msg;			/* 完整响应报文（ID 位无关紧要，回包时会覆盖） */
	u16 msg_len;
	u16 qname_off;			/* 问题区名字在报文中的偏移（固定 12） */
	u16 qname_len;			/* 该名字的 wire 长度 */
	const u16 *ttl_offs;		/* 各非 OPT RR 的 TTL 字段偏移 */
	u16 n_ttl;
	u64 stored_ms;			/* 录入时刻（单调，含休眠——见 .c 的说明） */
	u32 ttl_ms;			/* 有效期 */
};

/*
 * 判断模板是否仍然新鲜。now_ms 必须与 stored_ms 来自同一个时钟源。
 */
bool kdg_cache_fresh(const struct kdg_cache_tmpl *t, u64 now_ms);

/*
 * 用调用方的原始查询重封装出给它的响应（方案 §8「绝不把 TTL 刷回原值」）。
 *
 * caller_query 必须是调用方提交的**原始 wire 查询**——不能用 kdg_wire 解析
 * 出来的 qname，因为那是小写规范化的，会丢掉调用方原本的大小写，而
 * 方案 §7.2 要求「每个调用方问题区原样保留」。
 *
 * 返回 0 或负错误码：
 *   -KDG_CRE_PACK  结构不匹配（问题区长度对不上、模板问题区被压缩过等）
 *   -KDG_CRE_STALE 已过期（调用方应先查 kdg_cache_fresh）
 *   -KDG_CRE_SMALL 输出缓冲区不足
 */
#define KDG_CRE_OK	0
#define KDG_CRE_PACK	1
#define KDG_CRE_STALE	2
#define KDG_CRE_SMALL	3
#define KDG_CRE_BADARG	4

int kdg_cache_repack(const struct kdg_cache_tmpl *t, u64 now_ms,
		     const u8 *caller_query, size_t caller_query_len,
		     u8 *out, size_t out_cap, size_t *out_len);

/* TTL 字段偏移的收集在 kdg_wire（kdg_wire_collect_ttl_offs）——
 * 那里已有经过语料验证的 RR 遍历器，缓存侧不该再写一份。
 * 它同样**排除 OPT**，理由见 kdg_wire.h。 */

/* 键的哈希（FNV-1a）。用于内核侧的哈希表。 */
u32 kdg_cache_key_hash(const struct kdg_cache_key *k);

/* 键的相等比较。 */
bool kdg_cache_key_eq(const struct kdg_cache_key *a,
		      const struct kdg_cache_key *b);

#endif /* _KDG_CACHE_H */
