/* SPDX-License-Identifier: GPL-2.0 */
/*
 * kdg_cache_tab.h —— DNS 缓存的**内核侧存储层**（哈希表 + CLOCK 淘汰 + 内存核算）。
 *
 * 与 kdg_cache.c 的分工：
 *   kdg_cache.c     纯逻辑（键、新鲜度、回包重封装）——双态可编译、宿主可测
 *   kdg_cache_tab.c 存储与并发——内核专属，不可宿主测试
 * 这样切分的理由：真正需要海量语料反复验证的是「报文改写的边界」，
 * 而那部分完全在 kdg_cache.c 里；存储层的正确性主要靠并发不变式，
 * 靠单测覆盖不了，得靠真机压测。
 *
 * 并发模型（方案 §8「只对查找、引用计数和替换持短锁」）：
 *   锁内：查表、置 pins、插入、淘汰
 *   锁外：kdg_cache_repack() —— 重封装要 memcpy 整条报文并改写每个 TTL
 *
 * 因此存在一个必须正面解决的窗口：**锁外使用期间条目不能被释放**。
 * 用两层状态应付：
 *   pins  活跃使用者计数，>0 时淘汰器不许回收该槽位
 *   ref   CLOCK 的二次机会位，与 pins 无关
 * 淘汰器扫不到任何 pins==0 的槽位时**放弃插入**而不是强行回收 ——
 * 宁可有界地少缓存几条，也不能给出 use-after-free。
 */
#ifndef _KDG_CACHE_TAB_H
#define _KDG_CACHE_TAB_H

#include <linux/types.h>

#include "kdg_cache.h"

/* 方案 §7.4 的初值。均为「调试初值」而非实测最优值 —— 原文如此标注。 */
#define KDG_CACHE_DEF_SLOTS	4096
#define KDG_CACHE_DEF_MEM_TARGET (4u * 1024 * 1024)
#define KDG_CACHE_DEF_MEM_MAX	 (8u * 1024 * 1024)

struct kdg_cache;

int  kdg_cache_tab_init(void);
void kdg_cache_tab_exit(void);

/*
 * 查表。命中时返回 0 并把该槽位**钉住**（pins+1），填好 view；
 * 调用方用完必须调 kdg_cache_unpin()。未命中返回 -ENOENT。
 * 命中但已过期返回 -ESTALE（并已把该条目摘除）。
 */
int kdg_cache_get(const struct kdg_cache_key *key, u64 now_ms,
		  struct kdg_cache_tmpl *view, void **pin_token);

/* 解除钉住。可与上一步的 token 配对，幂等。 */
void kdg_cache_unpin(void *token);

/*
 * 插入/替换。msg 会被复制一份（调用方的缓冲随即可以释放）。
 * ttl_ms==0 或 TTL 字段数超过 KDG_CACHE_MAX_TTL_OFF 时**拒绝插入**并返回相应错误。
 * 返回 0、-ENOSPC（TTL 字段过多）、-EINVAL（不可缓存）、-ENOMEM。
 */
int kdg_cache_put(const struct kdg_cache_key *key, const u8 *msg,
		  size_t msg_len, u64 now_ms, u32 ttl_ms);

/* 按范围清空。net_id 为 0 表示清空全部（FLUSH_CACHE 用）。 */
void kdg_cache_flush(u32 net_id);

struct kdg_cache_stats {
	u32 slots;		/* 槽位总数 */
	u32 entries;		/* 有效条目数 */
	u32 pinned;		/* 当前被钉住的条目数 */
	u32 evictions;		/* 累计淘汰数 */
	u32 put_rejected;	/* 因资源不足或策略被拒的插入数 */
	u64 hits;
	u64 misses;
	u64 stale;
	u64 expunged_oversize;
	u32 mem_bytes;		/* 当前占用（按条目核算） */
	u32 mem_max_bytes;
};
void kdg_cache_stats(struct kdg_cache_stats *out);

#endif /* _KDG_CACHE_TAB_H */
