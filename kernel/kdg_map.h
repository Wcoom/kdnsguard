/* SPDX-License-Identifier: GPL-2.0 */
/*
 * kdg_map.h —— IP ↔ 域名 的有界关联表（方案 §12.2）。
 *
 * ## 为什么需要它
 *
 * DNS 一旦从代理挪进内核，代理就失去了它原先**由 DNS 应答触发**的域名/IP
 * 映射。它随后只看到一个连接连到某个**真实 IP**，却不知道这个连接原本是要
 * 访问哪个域名 —— 而它的分流规则大量按域名写。方案 §12.2 因此要求内核
 * 「以 network + profile + IP + domain + expire + provenance 存有界关联，
 * 并提供查询接口」。
 *
 * ## 方向只有反查（IP → 域名集合）
 *
 * 代理手上的输入是「一个新连接的目标 IP」，它要的是「可能是哪些域名」。
 * 正查（域名 → IP）在本期**没有消费者**，还要多维护一套索引与更新路径，
 * 故不做 —— 这是有意的范围裁剪，不是遗漏。
 *
 * ## 同 IP 的多个域名必须保留歧义
 *
 * 方案 §12.2 点名：「同 IP 的多个域名必须保留集合和歧义，不能简单『最后一个
 * 域名覆盖所有连接』」。因此一个条目持有一**组**域名（上限
 * KDG_MAP_MAX_NAMES），不是一个。返回时把整组交给调用方，由它连同 SNI /
 * 协议元信息一起裁决 —— 在内核里替它猜一个「最可能的域名」才是错的。
 *
 * ## 并发模型：结果不逃逸锁
 *
 * 与 kdg_cache_tab 不同，这里的查询**在锁内把结果拷进调用方的缓冲**就结束，
 * 没有任何引用逃逸到锁外。于是不需要 pins/retired 那套两段式生命周期 ——
 * 那套复杂度是为「锁外重封装整条报文」付出的，这里没有对应需求。
 */
#ifndef _KDG_MAP_H
#define _KDG_MAP_H

#include <linux/types.h>

#include "kdg_wire.h"
#include "uapi/kdnsguard.h"

/* 槽位数。每个条目约 0.6 KiB（见 kdg_map.c 的尺寸注释），512 槽约 320 KiB。 */
#define KDG_MAP_DEF_SLOTS	512

/* 一个 IP 最多关联多少个域名（歧义集合的宽度上限）。 */
#define KDG_MAP_MAX_NAMES	4

/* 域名长度上界用 UAPI 的 KDG_MAP_NAME_MAX —— 它既是响应载荷的契约上界，
 * 也是本表的存储上界。**不在这里另立一个常量**：两处定义迟早会漂移，
 * 而漂移的表现是「内核产出了客户端缓冲装不下的 item」。 */

/* TTL 夹取范围：下界避免记录一个马上过期的项（TTL=0 根本不记），
 * 上界避免一条陈旧的关联长期留在表里 —— 内核侧 TTL 的语义是**上限**，
 * 不是「权威有效期」。 */
#define KDG_MAP_MIN_TTL_MS	1000u
#define KDG_MAP_MAX_TTL_MS	3600000u	/* 1 小时 */

/* 单次反查的结果。名字按 wire 形式（未压缩）返回，长度另给。 */
struct kdg_map_result {
	u8  names[KDG_MAP_MAX_NAMES][KDG_MAP_NAME_MAX];
	u16 lens[KDG_MAP_MAX_NAMES];
	u32 ttl_ms[KDG_MAP_MAX_NAMES];
	u32 profile_gen;	/* provenance：这些关联是在哪一代 profile 下建立的 */
	u8  count;
	bool truncated;		/* 条目里还有更多域名，本次被上限截断 */
	u16 reserved_;
};

struct kdg_map_stats {
	u32 slots;
	u32 entries;
	u32 evictions;
	u32 record_rejected;	/* 因超长/上限被丢掉的记录 */
	u32 lookup_misses;
	u64 lookup_hits;
	u64 truncated;		/* 结果被上限截断的次数 */
	u32 mem_bytes;
	u32 mem_max_bytes;
};

int  kdg_map_init(void);
void kdg_map_exit(void);

/*
 * 记录：把 qname 关联到 ans[] 里的每一个地址上。
 *
 * msg 是响应报文本身（ans[].rdata_off 指向其中），qname 是**调用方问的那个
 * 名字**的 wire 形式 —— 不是 RR 的 owner 名，理由见 kdg_wire_collect_addrs。
 *
 * 无返回值：这是旁路记账，任何失败都只影响「代理能不能按域名分流」，绝不能
 * 反过来影响 DNS 应答本身。
 */
void kdg_map_record(u32 net_id, u32 profile_gen,
		    const u8 *qname, u16 qname_len,
		    const u8 *msg, size_t msglen,
		    const struct kdg_addr_ref *ans, u16 nans);

/*
 * 反查。命中返回 0 并填 out；未命中（含条目已过期、profile 代际不符）返回
 * -ENOENT。profile_gen 必须与记录时一致，否则视为不命中 —— 换上游之后旧关联
 * 不再可信，这与缓存的失效口径一致（缓存键里也含 profile_gen）。
 *
 * addr_len 是地址字节数（4 或 16），同时充当族判别式；cap 是调用方要的上限
 * （截到 [1, KDG_MAP_MAX_NAMES]）。cap 给得比条目实际持有的名字少时，多余的
 * 记进 out->truncated —— 调用方据此知道「还有别的候选」，而不是误以为这个 IP
 * 只对应它拿到的这几个域名。
 */
int kdg_map_lookup(u32 net_id, u32 profile_gen,
		   u8 addr_len, const u8 *addr, u8 cap,
		   struct kdg_map_result *out);

/* net_id 为 0 表示清空全部。 */
void kdg_map_flush(u32 net_id);

void kdg_map_get_stats(struct kdg_map_stats *out);

#endif /* _KDG_MAP_H */
