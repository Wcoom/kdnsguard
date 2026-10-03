/* SPDX-License-Identifier: GPL-2.0 */
/*
 * kdg_cache_tab.c —— DNS 缓存的内核侧存储层实现。设计见 kdg_cache_tab.h。
 */
#define pr_fmt(fmt)	KBUILD_MODNAME ": cache: " fmt

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/list.h>
#include <linux/hashtable.h>
#include <linux/atomic.h>
#include <linux/vmalloc.h>

#include "kdg_cache_tab.h"

struct kdg_cache_entry {
	struct hlist_node	hnode;		/* 哈希链 */
	struct list_head	free_node;	/* 空闲链（仅 valid==false 时在链上） */
	struct kdg_cache_key	key;
	u8		       *msg;		/* 不可变响应模板 */
	u16		       *ttl_offs;
	u16			msg_len;
	u16			n_ttl;
	u16			qname_len;
	u32			ttl_ms;
	u64			stored_ms;
	u32			hits;
	u32			mem;		/* 本条目的核算占用 */
	atomic_t		pins;		/* 活跃使用者；>0 时不可回收 */
	bool			valid;
	bool			ref;		/* CLOCK 二次机会位 */
};

struct kdg_cache {
	struct hlist_head	*buckets;
	u32			hash_bits;
	struct kdg_cache_entry	*slots;
	u32			nslots;
	u32			hand;		/* CLOCK 指针 */
	struct list_head	free_list;	/* 空闲槽 */
	u32			entries;
	u32			mem_bytes;
	u32			mem_max;
	spinlock_t		lock;

	u64			hits, misses, stale, evictions, put_rejected;
};

static struct kdg_cache *g_cache;

/* ── 内部工具（均在持锁状态下调用） ──────────────────────────────────── */

/*
 * 释放槽位并推回空闲链。
 *
 * **只有这一条路径会 push 空闲链**，且以 valid 作幂等判据：`slot_clear`
 * 对 !valid 的槽位直接返回，故不会重复入链。这让「空闲槽一定在链上、
 * 有效槽一定不在链上」成为一条可依赖的不变式。
 */
static void slot_clear(struct kdg_cache *c, struct kdg_cache_entry *e)
{
	if (!e->valid)
		return;

	hlist_del_init(&e->hnode);
	kfree(e->msg);
	kfree(e->ttl_offs);
	e->msg = NULL;
	e->ttl_offs = NULL;

	/* 无符号减法：即便核算出现偏差也不会回绕成一个巨大的值 */
	c->mem_bytes = (c->mem_bytes >= e->mem) ? (c->mem_bytes - e->mem) : 0;
	if (c->entries)
		c->entries--;

	e->valid = false;
	e->ref = false;
	e->mem = 0;
	list_add_tail(&e->free_node, &c->free_list);
}

/* 从空闲链取一个槽位；无则返回 NULL。 */
static struct kdg_cache_entry *slot_alloc(struct kdg_cache *c)
{
	struct kdg_cache_entry *e;

	if (list_empty(&c->free_list))
		return NULL;
	e = list_first_entry(&c->free_list, struct kdg_cache_entry, free_node);
	list_del_init(&e->free_node);
	return e;
}

/*
 * CLOCK 淘汰候选：从 hand 起扫最多两圈。
 * 只考虑 **valid** 的槽位（无效的都在空闲链上，不归这里管）；
 * 跳过被钉住的（有人正在锁外使用）；未被引用过的直接选，引用过的清掉
 * 引用位给第二次机会。找不到可回收者时返回 NULL —— 调用方据此**放弃插入**，
 * 而不是强行回收（那会是 use-after-free）。
 */
static struct kdg_cache_entry *pick_victim(struct kdg_cache *c)
{
	u32 i;

	for (i = 0; i < c->nslots * 2; i++) {
		struct kdg_cache_entry *e = &c->slots[c->hand];

		c->hand = (c->hand + 1) % c->nslots;

		if (!e->valid)
			continue;
		if (atomic_read(&e->pins))
			continue;
		if (!e->ref)
			return e;
		e->ref = false;
	}
	return NULL;
}

/* ── 生命周期 ────────────────────────────────────────────────────────── */

int kdg_cache_tab_init(void)
{
	struct kdg_cache *c;
	u32 nbuckets, bits = 0, i;

	c = kzalloc(sizeof(*c), GFP_KERNEL);
	if (!c)
		return -ENOMEM;

	c->nslots = KDG_CACHE_DEF_SLOTS;
	c->mem_max = KDG_CACHE_DEF_MEM_MAX;
	spin_lock_init(&c->lock);
	INIT_LIST_HEAD(&c->free_list);

	/*
	 * ⚠️ 必须用 kvcalloc 而不是 kcalloc。
	 *
	 * 4096 个槽位约 1.5 MB。kcalloc 走 kmalloc，需要**连续的物理页**
	 * （约 order-9）。这在运行数小时、内存已碎片化的手机上基本必失败 ——
	 * 实测真机 insmod 报 "Out of memory"，而 vmalloc 空间绰绰有余。
	 * 槽位数组只是被索引访问，完全不需要物理连续。
	 */
	c->slots = kvcalloc(c->nslots, sizeof(*c->slots), GFP_KERNEL);
	if (!c->slots) {
		kfree(c);
		return -ENOMEM;
	}
	for (i = 0; i < c->nslots; i++) {
		INIT_HLIST_NODE(&c->slots[i].hnode);
		INIT_LIST_HEAD(&c->slots[i].free_node);
		list_add_tail(&c->slots[i].free_node, &c->free_list);
	}

	/* 桶数取槽位的 1/4（上取到 2 的幂）：链表平均长度 4 左右，
	 * 期望 O(1) 查找，桶数组本身又只占几 KB。 */
	nbuckets = c->nslots / 4;
	while ((1u << bits) < nbuckets)
		bits++;
	c->hash_bits = bits;
	c->buckets = kvcalloc(1u << bits, sizeof(*c->buckets), GFP_KERNEL);
	if (!c->buckets) {
		kvfree(c->slots);
		kfree(c);
		return -ENOMEM;
	}

	/*
	 * 槽位数组本身是**预先**分配的固定开销，必须一开始就计入预算 ——
	 * 否则「8 MiB 上限」会被这 1.5 MB 悄悄突破。
	 * 相应地，每个条目的 e->mem 只核算**载荷**（报文 + 偏移表），
	 * 不重复计入槽位结构体，slot_clear 的扣减才与这里的预扣对称。
	 */
	c->mem_bytes = (u32)(c->nslots * sizeof(*c->slots));
	if (c->mem_bytes > c->mem_max) {
		/* 槽位本身就超预算：这是配置错误，宁可拒绝启动也不要
		 * 在运行期表现成「无论如何都存不进东西」。 */
		pr_err("槽位数组 %u KiB 已超过内存上限 %u KiB\n",
		       c->mem_bytes / 1024, c->mem_max / 1024);
		kvfree(c->buckets);
		kvfree(c->slots);
		kfree(c);
		return -EINVAL;
	}

	g_cache = c;
	pr_info("就绪：%u 槽位（结构 %u KiB）/ %u 桶 / 内存上限 %u KiB\n",
		c->nslots, c->mem_bytes / 1024, 1u << c->hash_bits,
		c->mem_max / 1024);
	return 0;
}

void kdg_cache_tab_exit(void)
{
	struct kdg_cache *c = g_cache;
	u32 i;

	if (!c)
		return;
	g_cache = NULL;

	spin_lock(&c->lock);
	for (i = 0; i < c->nslots; i++)
		slot_clear(c, &c->slots[i]);
	spin_unlock(&c->lock);

	kvfree(c->buckets);
	kvfree(c->slots);
	kfree(c);
}

/* ── 查表 ────────────────────────────────────────────────────────────── */

int kdg_cache_get(const struct kdg_cache_key *key, u64 now_ms,
		  struct kdg_cache_tmpl *view, void **pin_token)
{
	struct kdg_cache *c = g_cache;
	struct kdg_cache_entry *e;
	u32 h;
	int ret = -ENOENT;

	if (!c || !key || !view || !pin_token)
		return -EINVAL;
	*pin_token = NULL;

	h = kdg_cache_key_hash(key);

	spin_lock(&c->lock);

	hlist_for_each_entry(e, &c->buckets[hash_min(h, c->hash_bits)], hnode) {
		struct kdg_cache_tmpl probe;

		if (!e->valid || !kdg_cache_key_eq(&e->key, key))
			continue;

		probe.stored_ms = e->stored_ms;
		probe.ttl_ms = e->ttl_ms;

		if (!kdg_cache_fresh(&probe, now_ms)) {
			/* 过期即摘除：留着只会让后续查找继续走这条链，
			 * 而它占的内存应当立刻让给别的条目。 */
			slot_clear(c, e);
			c->stale++;
			ret = -ESTALE;
			goto out;
		}

		atomic_inc(&e->pins);
		e->ref = true;		/* CLOCK 的「最近用过」 */
		e->hits++;
		c->hits++;

		view->msg = e->msg;
		view->msg_len = e->msg_len;
		view->qname_off = KDG_DNS_HDR_LEN;
		view->qname_len = e->qname_len;
		view->ttl_offs = e->ttl_offs;
		view->n_ttl = e->n_ttl;
		view->stored_ms = e->stored_ms;
		view->ttl_ms = e->ttl_ms;

		*pin_token = e;
		ret = 0;
		goto out;
	}

	c->misses++;

out:
	spin_unlock(&c->lock);
	return ret;
}

void kdg_cache_unpin(void *token)
{
	struct kdg_cache_entry *e = token;

	/* 槽位在 pins>0 期间不会被回收，故此处读到的是稳定的指针；
	 * 计数本身用原子操作即可，无需持锁。 */
	if (e)
		atomic_dec(&e->pins);
}

/* ── 插入 ────────────────────────────────────────────────────────────── */

int kdg_cache_put(const struct kdg_cache_key *key, const u8 *msg,
		  size_t msg_len, u64 now_ms, u32 ttl_ms)
{
	struct kdg_cache *c = g_cache;
	struct kdg_cache_entry *slot = NULL, *e;
	u16 offs[KDG_CACHE_MAX_TTL_OFF];
	u8 *msg_copy = NULL;
	u16 *offs_copy = NULL;
	u32 mem, h;
	int n_ttl, ret = 0;

	if (!c || !key || !msg || msg_len == 0 || msg_len > 0xffff)
		return -EINVAL;
	/* TTL==0 的语义是「仅本次使用」，不入缓存（方案 §8）。 */
	if (ttl_ms == 0)
		return -EINVAL;

	/* 报文副本与偏移表都在**锁外**准备：kmalloc(GFP_KERNEL) 会睡眠，
	 * 不能放进持 spinlock 的区间。 */
	n_ttl = kdg_wire_collect_ttl_offs(msg, msg_len, offs,
					  KDG_CACHE_MAX_TTL_OFF);
	if (n_ttl < 0) {
		/* 收集不满（RR 太多）时**不缓存**该响应 —— 少改几个 TTL 会
		 * 让超期数据看起来更新鲜，那比不缓存危险得多。 */
		return (n_ttl == KDG_W_ECOUNT) ? -ENOSPC : -EINVAL;
	}

	/* 只核算载荷：槽位结构体的开销已在 init 时一次性预扣。 */
	mem = (u32)msg_len + (u32)n_ttl * (u32)sizeof(u16);
	if (mem > c->mem_max)
		return -ENOSPC;		/* 单条即超上限：绝不缓存 */

	msg_copy = kmemdup(msg, msg_len, GFP_KERNEL);
	if (!msg_copy)
		return -ENOMEM;
	if (n_ttl > 0) {
		offs_copy = kmemdup(offs, (size_t)n_ttl * sizeof(u16),
				    GFP_KERNEL);
		if (!offs_copy) {
			kfree(msg_copy);
			return -ENOMEM;
		}
	}

	h = kdg_cache_key_hash(key);

	spin_lock(&c->lock);

	/* 1) 同名条目优先就地替换 —— 否则同一域名反复解析会把缓存挤满同键条目。
	 *    但若该条目正被别人使用（pins>0），不能就地改写其载荷，
	 *    改走「占一个新槽位、旧的留给淘汰」的路径。 */
	hlist_for_each_entry(e, &c->buckets[hash_min(h, c->hash_bits)], hnode) {
		if (!e->valid || !kdg_cache_key_eq(&e->key, key))
			continue;
		if (atomic_read(&e->pins))
			break;
		slot_clear(c, e);
		list_del_init(&e->free_node);	/* 刚放回空闲链，立刻取回 */
		slot = e;
		break;
	}

	/* 2) 腾预算：先把总占用降到能把本条装下（这一步会产出空闲槽）。 */
	while (c->mem_bytes + mem > c->mem_max && c->entries > 0) {
		struct kdg_cache_entry *v = pick_victim(c);

		if (!v)
			break;
		c->evictions++;
		slot_clear(c, v);
	}

	/* 3) 取槽位：先要空闲的，没有才淘汰。 */
	if (!slot)
		slot = slot_alloc(c);
	if (!slot) {
		struct kdg_cache_entry *v = pick_victim(c);

		if (v) {
			c->evictions++;
			slot_clear(c, v);
			slot = slot_alloc(c);
		}
	}
	if (!slot) {
		/* 全部槽位都被钉住：**有界地放弃**插入。宁可少缓存几条，
		 * 也不能回收正在被读的条目。 */
		ret = -ENOSPC;
		goto out;
	}

	slot->key = *key;
	slot->msg = msg_copy;
	slot->msg_len = (u16)msg_len;
	slot->ttl_offs = offs_copy;
	slot->n_ttl = (u16)n_ttl;
	slot->qname_len = key->qname_len;
	slot->ttl_ms = ttl_ms;
	slot->stored_ms = now_ms;
	slot->hits = 0;
	slot->mem = mem;
	slot->ref = true;		/* 刚写入，给一次不被立即淘汰的机会 */
	atomic_set(&slot->pins, 0);
	slot->valid = true;

	hlist_add_head(&slot->hnode, &c->buckets[hash_min(h, c->hash_bits)]);
	c->entries++;
	c->mem_bytes += mem;

	/* 载荷归属权已转移给槽位 */
	msg_copy = NULL;
	offs_copy = NULL;

out:
	if (ret)
		c->put_rejected++;
	spin_unlock(&c->lock);
	kfree(msg_copy);
	kfree(offs_copy);
	return ret;
}

/* ── 清空与统计 ──────────────────────────────────────────────────────── */

void kdg_cache_flush(u32 net_id)
{
	struct kdg_cache *c = g_cache;
	u32 i;

	if (!c)
		return;

	spin_lock(&c->lock);
	for (i = 0; i < c->nslots; i++) {
		struct kdg_cache_entry *e = &c->slots[i];

		if (!e->valid)
			continue;
		/* net_id==0 表示「全部」；否则只清该网络的。
		 * 方案 §8 要求「每网络/策略视图隔离」。 */
		if (net_id && e->key.net_id != net_id)
			continue;
		if (atomic_read(&e->pins))
			continue;	/* 正在被使用，本轮跳过 */
		slot_clear(c, e);
	}
	spin_unlock(&c->lock);
}

void kdg_cache_stats(struct kdg_cache_stats *out)
{
	struct kdg_cache *c = g_cache;
	u32 i, pinned = 0;

	if (!out)
		return;
	memset(out, 0, sizeof(*out));
	if (!c)
		return;

	spin_lock(&c->lock);
	for (i = 0; i < c->nslots; i++) {
		if (c->slots[i].valid && atomic_read(&c->slots[i].pins))
			pinned++;
	}
	out->slots = c->nslots;
	out->entries = c->entries;
	out->pinned = pinned;
	out->evictions = (u32)c->evictions;
	out->put_rejected = (u32)c->put_rejected;
	out->hits = c->hits;
	out->misses = c->misses;
	out->stale = c->stale;
	out->mem_bytes = c->mem_bytes;
	out->mem_max_bytes = c->mem_max;
	spin_unlock(&c->lock);
}
