/* SPDX-License-Identifier: GPL-2.0 */
/*
 * kdg_sflight.c —— 同名查询合并实现。语义与边界见 kdg_sflight.h。
 */
#define pr_fmt(fmt)	KBUILD_MODNAME ": sflight: " fmt

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/hashtable.h>
#include <linux/atomic.h>
#include <linux/completion.h>
#include <linux/jiffies.h>

#include "kdg_sflight.h"

struct kdg_flight {
	struct hlist_node	node;
	struct kdg_cache_key	key;
	struct completion	done;
	atomic_t		refs;
	u32			n_waiters;	/* 只数搭车者，不含 owner */
	bool			published;
	int			status;		/* 0 或负 errno */
	u8		       *resp;
	size_t			resp_len;
};

static struct {
	struct hlist_head	*buckets;
	u32			hash_bits;
	spinlock_t		lock;
	u32			inflight;
	u32			waiters;
	u64			joined, owned, rejected_full, timeouts;
} g_sf;

int kdg_sflight_init(void)
{
	u32 bits = 0, nbuckets = KDG_SF_MAX_FLIGHTS / 4;

	while ((1u << bits) < nbuckets)
		bits++;

	g_sf.buckets = kvcalloc(1u << bits, sizeof(*g_sf.buckets),
				GFP_KERNEL);
	if (!g_sf.buckets)
		return -ENOMEM;

	g_sf.hash_bits = bits;
	spin_lock_init(&g_sf.lock);
	return 0;
}

void kdg_sflight_exit(void)
{
	struct kdg_flight *f;
	struct hlist_node *tmp;
	u32 i;

	if (!g_sf.buckets)
		return;

	spin_lock(&g_sf.lock);
	for (i = 0; i < (1u << g_sf.hash_bits); i++) {
		hlist_for_each_entry_safe(f, tmp, &g_sf.buckets[i], node) {
			hlist_del_init(&f->node);
			/* 卸载路径上不应还有在途者；这里只做兜底回收，
			 * 不 complete —— 真有 waiter 的话它应当早已超时。 */
			kfree(f->resp);
			kfree(f);
		}
	}
	g_sf.inflight = 0;
	g_sf.waiters = 0;
	spin_unlock(&g_sf.lock);

	kvfree(g_sf.buckets);
	g_sf.buckets = NULL;
}

int kdg_sflight_begin(const struct kdg_cache_key *key, struct kdg_flight **out)
{
	struct kdg_flight *f;
	u32 h;

	if (!g_sf.buckets || !key || !out)
		return -EINVAL;
	*out = NULL;

	h = kdg_cache_key_hash(key);

	spin_lock(&g_sf.lock);

	hlist_for_each_entry(f, &g_sf.buckets[hash_min(h, g_sf.hash_bits)],
			     node) {
		if (f->published || !kdg_cache_key_eq(&f->key, key))
			continue;

		/* 有在途的同名查询：搭车。
		 * waiter 数有上限（方案 §7.4 初值 128）—— 无界挂载会让一个
		 * 恶意域名把内存吃光，也会让结果复制阶段变成 O(n) 的放大点。 */
		if (f->n_waiters >= KDG_SF_MAX_WAITERS) {
			g_sf.rejected_full++;
			spin_unlock(&g_sf.lock);
			return -EAGAIN;
		}

		f->n_waiters++;
		g_sf.waiters++;
		atomic_inc(&f->refs);
		*out = f;
		g_sf.joined++;
		spin_unlock(&g_sf.lock);
		return KDG_SF_WAIT;
	}

	if (g_sf.inflight >= KDG_SF_MAX_FLIGHTS) {
		/* 在途不同查询已达硬上限（方案 §7.4 的 1024）：拒绝新建，
		 * 让调用方自己决定是排队还是直接返回 EAGAIN。 */
		g_sf.rejected_full++;
		spin_unlock(&g_sf.lock);
		return -EAGAIN;
	}

	f = kzalloc(sizeof(*f), GFP_KERNEL);
	if (!f) {
		spin_unlock(&g_sf.lock);
		return -ENOMEM;
	}

	f->key = *key;
	init_completion(&f->done);
	atomic_set(&f->refs, 1);	/* owner 自己持一个引用 */
	hlist_add_head(&f->node, &g_sf.buckets[hash_min(h, g_sf.hash_bits)]);
	g_sf.inflight++;
	g_sf.owned++;

	*out = f;
	spin_unlock(&g_sf.lock);
	return KDG_SF_OWNER;
}

int kdg_sflight_wait(struct kdg_flight *f, u32 timeout_ms,
		     u8 *out, size_t cap, size_t *outlen)
{
	long r;

	if (!f || !out || !outlen)
		return -EINVAL;
	*outlen = 0;

	/* 可中断等待：调用方（字符设备 write）被打断时应能脱离，
	 * 而不是黏在这条查询上直到 owner 跑完。 */
	r = wait_for_completion_interruptible_timeout(&f->done,
						      msecs_to_jiffies(timeout_ms));
	if (r < 0) {
		spin_lock(&g_sf.lock);
		if (g_sf.waiters)
			g_sf.waiters--;
		spin_unlock(&g_sf.lock);
		return -ERESTARTSYS;
	}
	if (r == 0) {
		spin_lock(&g_sf.lock);
		if (g_sf.waiters)
			g_sf.waiters--;
		g_sf.timeouts++;
		spin_unlock(&g_sf.lock);
		return -ETIMEDOUT;
	}

	spin_lock(&g_sf.lock);
	if (g_sf.waiters)
		g_sf.waiters--;
	spin_unlock(&g_sf.lock);

	/* complete_all 有 release 语义，故此处读到的 status/resp 是发布后的值 */
	if (f->status)
		return f->status;
	if (f->resp_len > cap)
		return -EMSGSIZE;

	memcpy(out, f->resp, f->resp_len);
	*outlen = f->resp_len;
	return 0;
}

void kdg_sflight_publish(struct kdg_flight *f, int status,
			 const u8 *resp, size_t resp_len)
{
	if (!f)
		return;

	/* 先把结果复制进来：owner 用的上游缓冲在其返回后就会被释放。 */
	if (status == 0 && resp && resp_len) {
		f->resp = kmemdup(resp, resp_len, GFP_KERNEL);
		if (!f->resp)
			status = -ENOMEM;
		else
			f->resp_len = resp_len;
	}
	f->status = status;

	/* 从合并表移除后才 complete：这样后来的请求不会再挂到一个
	 * 已完成（或已失败）的查询上，而会去查缓存 —— owner 已经把
	 * 成功结果写进去了。
	 * 先摘链再唤醒，避免「被唤醒者立刻返回、而它还挂在表里」的窗口。 */
	spin_lock(&g_sf.lock);
	if (!f->published) {
		hlist_del_init(&f->node);
		if (g_sf.inflight)
			g_sf.inflight--;
		f->published = true;
	}
	spin_unlock(&g_sf.lock);

	complete_all(&f->done);
}

void kdg_sflight_release(struct kdg_flight *f)
{
	if (!f)
		return;
	if (atomic_dec_and_test(&f->refs)) {
		kfree(f->resp);
		kfree(f);
	}
}

void kdg_sflight_stats(struct kdg_sflight_stats *out)
{
	if (!out)
		return;
	memset(out, 0, sizeof(*out));

	spin_lock(&g_sf.lock);
	out->inflight = g_sf.inflight;
	out->waiters = g_sf.waiters;
	out->joined = g_sf.joined;
	out->owned = g_sf.owned;
	out->rejected_full = g_sf.rejected_full;
	out->timeouts = g_sf.timeouts;
	spin_unlock(&g_sf.lock);
}
