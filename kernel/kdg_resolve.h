/* SPDX-License-Identifier: GPL-2.0 */
/*
 * kdg_resolve.h —— 解析编排：把「校验查询 → 查缓存 → 上游 DoH → 回填缓存 → 回包」串起来。
 *
 * 这一层是 P2 的骨架。方案把 DNS 处理拆成「有界校验 / 缓存+合并 / 上游传输」
 * 三块，本文件负责把它们按正确顺序接起来，并且**每一段的边界都显式处理**：
 * 缓存命中就不碰网络；上游失败不落缓存；不可缓存的响应仍然要正确回包。
 */
#ifndef _KDG_RESOLVE_H
#define _KDG_RESOLVE_H

#include "kdg_base.h"
#include "kdg_doh.h"

/* 解析结果的来源，用于统计与诊断。 */
enum kdg_source {
	KDG_SRC_CACHE	= 0,	/* 缓存命中 */
	KDG_SRC_JOINED	= 1,	/* 与在途的同名查询合并（singleflight） */
	KDG_SRC_UPSTREAM = 2,	/* 真正走了一次上游 */
};

struct kdg_resolve_req {
	const struct kdg_doh_cfg *cfg;
	u32 net_id;		/* Android netId；P2 阶段恒为 0 */
	u32 profile_gen;	/* 上游 profile 代际，进缓存键 */
};

/*
 * 完成一次解析。qwire 是调用方的**原始** wire 查询；rwire 接收给它的响应。
 * 返回 0 或负 errno（与 kdg_doh_query 一致）。
 * *src 回填本次结果的来源。
 */
int kdg_resolve(const struct kdg_resolve_req *req,
		const u8 *qwire, size_t qlen,
		u8 *rwire, size_t *rlen,
		enum kdg_source *src);

struct kdg_resolve_stats {
	u64 total;
	u64 from_cache;
	u64 from_joined;
	u64 from_upstream;
	u64 cache_put_ok;
	u64 cache_put_fail;
	u64 invalid_query;	/* 查询本身没通过有界校验 */
	u64 invalid_response;	/* 上游响应没通过校验，拒绝回包 */
	u64 not_cacheable;	/* 按策略不缓存（ECS/Cookie/TTL=0 等） */
};
void kdg_resolve_get_stats(struct kdg_resolve_stats *out);

#endif /* _KDG_RESOLVE_H */
