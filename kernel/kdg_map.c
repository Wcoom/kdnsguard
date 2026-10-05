/* SPDX-License-Identifier: GPL-2.0 */
/*
 * kdg_map.c —— IP ↔ 域名 有界关联表。设计、不变量与范围裁剪见 kdg_map.h。
 *
 * 双态可编译（宿主 gcc + ASan/UBSan 可跑）：本文件只依赖 kdg_base.h 提供的
 * 类型与控制流原语，以及 host_kernel.h 里的容器/锁/分配替身 —— 与
 * kdg_cache_tab.c 同一套路。这样淘汰、过期、歧义集合、上限截断这些**纯逻辑**
 * 能在宿主机上用可控时钟反复压，不必靠真机碰运气。
 */
#define pr_fmt(fmt)	KBUILD_MODNAME ": map: " fmt

#ifdef KDG_HOST_TEST
#include "host_kernel.h"
#else
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/list.h>
#include <linux/hashtable.h>
#include <linux/timekeeping.h>
#include <linux/ktime.h>
#endif

#include "kdg_map.h"
#include "kdg_bpfpub.h"

/* 哈希桶数取 2 的幂。1024 桶 / 512 槽 => 平均链长 0.5。 */
#define KDG_MAP_HASH_BITS	10

/* ── 时钟 ────────────────────────────────────────────────────────────────
 * 与缓存同一口径：用 CLOCK_BOOTTIME（含休眠），否则设备睡一小时醒来后
 * 一条本该过期的关联仍然「新鲜」（方案 §9.3）。
 * 宿主态用可写全局变量，让测试能精确推进时间。 */
#ifdef KDG_HOST_TEST
u64 kdg_map_host_now_ms;
#define kdg_map_now_ms()	(kdg_map_host_now_ms)
#else
static inline u64 kdg_map_now_ms(void)
{
	return div_u64(ktime_get_boottime_ns(), NSEC_PER_MSEC);
}
#endif

struct kdg_map_name {
	u16 len;
	u16 reserved_;
	u64 expires_ms;
	u8  wire[KDG_MAP_NAME_MAX];
};

struct kdg_map_entry {
	struct hlist_node hnode;
	u32 net_id;
	u32 profile_gen;
	u8  addr_len;		/* 4 或 16，同时充当地址族的判别式 */
	u8  nnames;
	u8  ref;		/* CLOCK 二次机会位 */
	/* 歧义集合满时换掉过某个域名。**必须记下来**：否则调用方拿到 4 个
	 * 候选却不知道「还有别的」，会把一份不完整的分流依据当成完整的用。
	 * 没有这一位，响应里的 truncated 就永远是 0，成了死字段。 */
	u8  lost;
	u64 expires_ms;		/* 全部名字里最早的到期时间 */
	u8  addr[16];
	struct kdg_map_name names[KDG_MAP_MAX_NAMES];
};

struct kdg_map {
	struct hlist_head	*buckets;
	struct kdg_map_entry	*slots;
	u32			nslots;
	u32			hand;		/* CLOCK 指针 */
	u32			alloc_hint;	/* 空闲槽扫描起点 */
	u32			entries;
	spinlock_t		lock;

	u32 evictions;
	u32 record_rejected;
	u32 lookup_misses;
	u64 lookup_hits;
	u64 truncated;
};

static struct kdg_map *g_map;

/* ── 内部工具 ─────────────────────────────────────────────────────────── */

static u32 kdg_map_hash(u32 net_id, u32 profile_gen, u8 addr_len,
			const u8 *addr)
{
	u32 h = net_id * 0x9e3779b1u + profile_gen * 0x85ebca6bu + addr_len;
	u32 i;

	/* FNV-1a 风格：地址字节逐个混入。地址是攻击者可控的（域名解析结果），
	 * 必须逐字节参与，不能只看前 4 字节 —— 否则同一个 /24 里的地址会
	 * 全挤在一个桶里。 */
	for (i = 0; i < addr_len; i++)
		h = (h ^ addr[i]) * 0x01000193u;
	return h;
}

static u32 kdg_map_ttl_ms(u32 ttl_s)
{
	u64 ms;

	if (!ttl_s)
		return 0;	/* TTL=0：不记录，与缓存同口径 */
	if (ttl_s > KDG_MAP_MAX_TTL_MS / 1000u)
		return KDG_MAP_MAX_TTL_MS;
	ms = (u64)ttl_s * 1000u;
	if (ms < KDG_MAP_MIN_TTL_MS)
		ms = KDG_MAP_MIN_TTL_MS;
	return (u32)ms;
}

static void kdg_map_entry_clear(struct kdg_map_entry *e)
{
	if (!e->nnames && !e->hnode.pprev && !e->hnode.next)
		return;		/* 本来就空，幂等 */
	hlist_del_init(&e->hnode);
	e->net_id = 0;
	e->profile_gen = 0;
	e->addr_len = 0;
	e->nnames = 0;
	e->ref = 0;
	e->lost = 0;
	e->expires_ms = 0;
	memset(e->addr, 0, sizeof(e->addr));
}

/* 重算条目的最小到期时间。全部名字都过期时返回 false。 */
static bool kdg_map_entry_recompute(struct kdg_map_entry *e, u64 now)
{
	u64 min = 0;
	u8 i, live = 0;

	for (i = 0; i < e->nnames; i++) {
		if (e->names[i].len == 0 || e->names[i].expires_ms <= now)
			continue;
		if (!live || e->names[i].expires_ms < min)
			min = e->names[i].expires_ms;
		live++;
	}
	if (!live)
		return false;
	e->expires_ms = min;
	return true;
}

/*
 * 取一个可用槽位，返回的槽位保证是**已清空**的。
 *
 * ⚠️ 必须显式处理「空闲槽」这一档。最初只写了「已过期」与 CLOCK 两档，而
 * CLOCK 那一档以 `addr_len==0`（空闲）为「跳过」判据 —— 于是表还没满时
 * 一个槽位也分不出来，表现为「记录成功但什么都查不到」，真机上会非常难查。
 *
 * 都找不到就返回 NULL，调用方**放弃本次记录**而不是强行回收：宁可有界地少记
 * 一条关联，也不能把还在被别人引用（ref 刚置位）的条目挪走。
 */
static struct kdg_map_entry *kdg_map_slot_locked(struct kdg_map *m, u64 now)
{
	u32 i, scanned;

	/* 第一遍：空闲槽（最常见）或已整体过期的槽。从 alloc_hint 起扫，
	 * 让常见情形摊还到 O(1)，不必每次都从 0 开始。 */
	for (i = 0; i < m->nslots; i++) {
		u32 idx = (m->alloc_hint + i) % m->nslots;
		struct kdg_map_entry *e = &m->slots[idx];

		if (!e->addr_len) {
			m->alloc_hint = (idx + 1) % m->nslots;
			return e;
		}
		if (e->expires_ms <= now) {
			kdg_map_entry_clear(e);
			if (m->entries)
				m->entries--;
			m->evictions++;
			m->alloc_hint = (idx + 1) % m->nslots;
			return e;
		}
	}

	/* 第二遍：CLOCK。最多扫两轮，第二轮必然清光所有 ref。 */
	for (scanned = 0; scanned < 2 * m->nslots; scanned++) {
		struct kdg_map_entry *e = &m->slots[m->hand];

		m->hand = (m->hand + 1) % m->nslots;
		if (!e->addr_len)
			continue;	/* 走到这里说明第一遍没扫到，只可能是并发，留给下一轮 */
		if (e->ref) {
			e->ref = 0;
			continue;
		}
		kdg_map_entry_clear(e);
		if (m->entries)
			m->entries--;
		m->evictions++;
		return e;
	}
	return NULL;
}

static struct kdg_map_entry *kdg_map_find_locked(struct kdg_map *m,
						 u32 net_id, u32 profile_gen,
						 u8 addr_len, const u8 *addr)
{
	u32 h = kdg_map_hash(net_id, profile_gen, addr_len, addr);
	struct kdg_map_entry *e;

	hlist_for_each_entry(e, &m->buckets[h & ((1u << KDG_MAP_HASH_BITS) - 1)],
			     hnode) {
		if (e->net_id != net_id || e->profile_gen != profile_gen)
			continue;
		if (e->addr_len != addr_len)
			continue;
		if (memcmp(e->addr, addr, addr_len) != 0)
			continue;
		return e;
	}
	return NULL;
}

/* ── 对外接口 ─────────────────────────────────────────────────────────── */

int kdg_map_init(void)
{
	struct kdg_map *m;
	size_t buckets = (size_t)1 << KDG_MAP_HASH_BITS;

	m = kzalloc(sizeof(*m), GFP_KERNEL);
	if (!m)
		return -ENOMEM;

	m->nslots = KDG_MAP_DEF_SLOTS;
	m->buckets = kvcalloc(buckets, sizeof(*m->buckets), GFP_KERNEL);
	m->slots = kvcalloc(m->nslots, sizeof(*m->slots), GFP_KERNEL);
	if (!m->buckets || !m->slots) {
		kvfree(m->buckets);
		kvfree(m->slots);
		kfree(m);
		return -ENOMEM;
	}
	spin_lock_init(&m->lock);
	g_map = m;

	pr_info("就绪：%u 槽（条目 %zu B，合计约 %u KiB）/ %zu 桶\n",
		m->nslots, sizeof(struct kdg_map_entry),
		(u32)((m->nslots * sizeof(struct kdg_map_entry)) / 1024),
		buckets);
	return 0;
}

void kdg_map_exit(void)
{
	struct kdg_map *m = g_map;

	if (!m)
		return;
	g_map = NULL;
	/* ⚠️ 必须 kvfree：buckets/slots 来自 kvcalloc，而 slots 有 316 KiB，
	 * 必然落在 vmalloc 区。用 kfree 释放 vmalloc 地址 → 真机 rmmod 时
	 * "Unable to handle kernel paging request" + panic 重启（实测发生过，
	 * 见 docs/P4-mapping.md 的复盘）。宿主 shim 把 kfree/kvfree 都映射成
	 * free，所以**宿主单测抓不到这一类**——这也是为什么 build.sh 里加了
	 * 配对审计。 */
	kvfree(m->buckets);
	kvfree(m->slots);
	kfree(m);   /* 这个确实是 kzalloc 来的，用 kfree */
}

void kdg_map_record(u32 net_id, u32 profile_gen,
		    const u8 *qname, u16 qname_len,
		    const u8 *msg, size_t msglen,
		    const struct kdg_addr_ref *ans, u16 nans)
{
	struct kdg_map *m = g_map;
	u64 now;
	u16 i;

	if (!m || !qname || !msg || !ans || !nans)
		return;
	/* 过长的名字**不记**（见 kdg_map.h：截断存储会让调用方按一个不存在的
	 * 域名分流，比查不到更糟）。qname_len 为 0 也不记。 */
	if (qname_len == 0 || qname_len > KDG_MAP_NAME_MAX) {
		m->record_rejected++;
		return;
	}

	now = kdg_map_now_ms();

	spin_lock(&m->lock);
	for (i = 0; i < nans; i++) {
		struct kdg_map_entry *e;
		struct kdg_map_name *slot = NULL;
		u32 ttl_ms;
		u8 j;
		bool found = false;

		if (ans[i].rdlen != 4 && ans[i].rdlen != 16)
			continue;
		/* 偏移必须落在**这次调用者给的报文**里。collect_addrs 已经保证过
		 * 一次，这里再查一次不是多余：这条路径会把 rdata_off 当成指针用，
		 * 一旦上游有别的调用方直接构造 addr_ref 传进来，越界读就发生在
		 * 内核里。判据用真实长度，不用 0xffff 这种形式上的上界。 */
		if ((size_t)ans[i].rdata_off + ans[i].rdlen > msglen)
			continue;
		ttl_ms = kdg_map_ttl_ms(ans[i].ttl);
		if (!ttl_ms)
			continue;

		e = kdg_map_find_locked(m, net_id, profile_gen, ans[i].rdlen,
					msg + ans[i].rdata_off);
		if (!e) {
			u32 h;

			e = kdg_map_slot_locked(m, now);
			if (!e) {
				m->record_rejected++;
				continue;
			}
			e->net_id = net_id;
			e->profile_gen = profile_gen;
			e->addr_len = ans[i].rdlen;
			memcpy(e->addr, msg + ans[i].rdata_off, ans[i].rdlen);
			h = kdg_map_hash(net_id, profile_gen, ans[i].rdlen,
					 e->addr);
			hlist_add_head(&e->hnode,
				       &m->buckets[h & ((1u << KDG_MAP_HASH_BITS) - 1)]);
			m->entries++;
		}

		/* 同一条目里已有的名字 → 刷新到期时间（TTL 以最新应答为准）。 */
		for (j = 0; j < e->nnames; j++) {
			if (e->names[j].len == qname_len &&
			    memcmp(e->names[j].wire, qname, qname_len) == 0) {
				e->names[j].expires_ms = now + ttl_ms;
				found = true;
				break;
			}
		}
		if (found) {
			kdg_map_entry_recompute(e, now);
			continue;
		}

		if (e->nnames < KDG_MAP_MAX_NAMES) {
			slot = &e->names[e->nnames++];
		} else {
			/* 歧义集合已满：换掉**最早到期**的那个。保留最近见过的
			 * 关联比拒绝新记录更贴近「这个 IP 现在被谁用着」。 */
			u8 victim = 0;

			for (j = 1; j < e->nnames; j++)
				if (e->names[j].expires_ms <
				    e->names[victim].expires_ms)
					victim = j;
			slot = &e->names[victim];
			e->lost = 1;
			m->record_rejected++;
		}
		slot->len = qname_len;
		slot->expires_ms = now + ttl_ms;
		memcpy(slot->wire, qname, qname_len);
		kdg_map_entry_recompute(e, now);
	}
	spin_unlock(&m->lock);

	/*
	 * 发布到 BPF 表（若用户空间挂接过一张）。
	 *
	 * ⚠️ 必须放在 spin_unlock **之后**：map_update_elem 对哈希表可能要分配
	 * 元素，在自旋锁里做这件事是「原子上下文里睡眠」，会立刻炸出来。
	 * 两次遍历 ans[] 的代价可以忽略（一次应答几条到几十条地址）。
	 * 发布是旁路：失败只丢计数，绝不影响上面的记账，更不影响 DNS 应答。
	 */
	if (kdg_bpfpub_active() && nans) {
		u64 h = kdg_bpf_domain_hash(qname, qname_len);
		u16 i;

		for (i = 0; i < nans; i++) {
			size_t off = ans[i].rdata_off;

			if (ans[i].rdlen != 4 && ans[i].rdlen != 16)
				continue;
			if (off + ans[i].rdlen > msglen)
				continue;
			kdg_bpfpub_publish(ans[i].rdlen == 4 ? KDG_BPF_AF_INET :
					   KDG_BPF_AF_INET6,
					   msg + off, ans[i].rdlen, h,
					   kdg_map_ttl_ms(ans[i].ttl),
					   KDG_BPF_F_UPSTREAM);
		}
	}
}

int kdg_map_lookup(u32 net_id, u32 profile_gen,
		   u8 addr_len, const u8 *addr, u8 cap,
		   struct kdg_map_result *out)
{
	struct kdg_map *m = g_map;
	struct kdg_map_entry *e;
	u64 now;
	u8 i, n = 0;

	if (!m || !addr || !out)
		return -EINVAL;
	if (addr_len != 4 && addr_len != 16)
		return -EINVAL;
	if (cap == 0 || cap > KDG_MAP_MAX_NAMES)
		return -EINVAL;
	memset(out, 0, sizeof(*out));

	now = kdg_map_now_ms();

	spin_lock(&m->lock);
	e = kdg_map_find_locked(m, net_id, profile_gen, addr_len, addr);
	if (!e || !kdg_map_entry_recompute(e, now)) {
		m->lookup_misses++;
		spin_unlock(&m->lock);
		return -ENOENT;
	}

	out->profile_gen = e->profile_gen;
	for (i = 0; i < e->nnames; i++) {
		const struct kdg_map_name *nm = &e->names[i];
		u32 left;

		if (nm->len == 0 || nm->expires_ms <= now)
			continue;
		if (n >= cap) {
			/* 还有活着的候选没装下 —— 这是**有信息量**的截断，
			 * 不能当成"就这几个"。 */
			out->truncated = true;
			m->truncated++;
			break;
		}
		memcpy(out->names[n], nm->wire, nm->len);
		out->lens[n] = nm->len;
		left = (u32)(nm->expires_ms - now);
		if (left == 0)
			left = 1;	/* 已过期项上面已跳过，这里只防 0 被误读成"无期限" */
		out->ttl_ms[n] = left;
		n++;
	}
	if (!n) {
		m->lookup_misses++;
		spin_unlock(&m->lock);
		return -ENOENT;
	}
	/* 存储侧丢过域名 ⇒ 即使本次 cap 装得下，结果也是不完整的。 */
	if (e->lost)
		out->truncated = true;
	out->count = n;
	e->ref = 1;
	m->lookup_hits++;
	spin_unlock(&m->lock);
	return 0;
}

void kdg_map_flush(u32 net_id)
{
	struct kdg_map *m = g_map;
	u32 i;

	if (!m)
		return;
	spin_lock(&m->lock);
	for (i = 0; i < m->nslots; i++) {
		struct kdg_map_entry *e = &m->slots[i];

		if (!e->addr_len)
			continue;
		if (net_id && e->net_id != net_id)
			continue;
		kdg_map_entry_clear(e);
		if (m->entries)
			m->entries--;
	}
	spin_unlock(&m->lock);
}

void kdg_map_get_stats(struct kdg_map_stats *out)
{
	struct kdg_map *m = g_map;

	if (!out)
		return;
	memset(out, 0, sizeof(*out));
	if (!m)
		return;
	spin_lock(&m->lock);
	out->slots = m->nslots;
	out->entries = m->entries;
	out->evictions = m->evictions;
	out->record_rejected = m->record_rejected;
	out->lookup_misses = m->lookup_misses;
	out->lookup_hits = m->lookup_hits;
	out->truncated = m->truncated;
	out->mem_bytes = (u32)(m->nslots * sizeof(struct kdg_map_entry) +
			       ((size_t)1 << KDG_MAP_HASH_BITS) *
			       sizeof(struct hlist_head));
	out->mem_max_bytes = out->mem_bytes;
	spin_unlock(&m->lock);
}
