/* SPDX-License-Identifier: GPL-2.0 */
/*
 * kdg_quota.c —— 每调用方配额实现。设计见 kdg_quota.h。
 */
#define pr_fmt(fmt)	KBUILD_MODNAME ": quota: " fmt

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/spinlock.h>
#include <linux/timekeeping.h>
#include <linux/ktime.h>
#include <linux/hash.h>
#include <linux/math64.h>

#include "kdg_quota.h"

/*
 * 参数。与方案 §7.4 的其它初值一样，这是**调试初值而非实测最优值**。
 * 取值刻意宽松：配额要拦的是「跑飞的调用方」，不是正常浏览 —— 一个页面
 * 加载几十个子资源、每个几个域名，峰值也就几十次/秒。
 */
static uint kdg_quota_rate = 500;	/* 每秒补充多少 token */
module_param_named(quota_rate, kdg_quota_rate, uint, 0644);
MODULE_PARM_DESC(quota_rate, "每调用方每秒可发起的查询数（默认 500）");

static uint kdg_quota_burst = 1000;	/* 桶容量（可瞬时突发多少次） */
module_param_named(quota_burst, kdg_quota_burst, uint, 0644);
MODULE_PARM_DESC(quota_burst, "每调用方的突发上限（默认 1000）");

struct kdg_bucket {
	u32	uid;
	u32	tokens;
	u64	last_ms;
	u64	denied;
	bool	used;
};

static struct {
	struct kdg_bucket	buckets[KDG_QUOTA_BUCKETS];
	spinlock_t		lock;
	u64			allowed;
	u64			denied;
} g_q;

/* 探测窗口：哈希冲突时的线性探测步数。步数小是有意的 ——
 * 冲突的代价只是「两个 UID 共用合理配额」，而不是失败。 */
#define KDG_QUOTA_PROBE		8

int kdg_quota_init(void)
{
	memset(&g_q, 0, sizeof(g_q));
	spin_lock_init(&g_q.lock);
	return 0;
}

void kdg_quota_exit(void)
{
	/* 全是内嵌数组，无外部分配。 */
}

void kdg_quota_reset(void)
{
	spin_lock(&g_q.lock);
	memset(g_q.buckets, 0, sizeof(g_q.buckets));
	g_q.allowed = 0;
	g_q.denied = 0;
	spin_unlock(&g_q.lock);
}

static inline u64 now_ms(void)
{
	return div_u64(ktime_get_boottime_ns(), NSEC_PER_MSEC);
}

int kdg_quota_charge(u32 uid)
{
	u32 rate = READ_ONCE(kdg_quota_rate);
	u32 burst = READ_ONCE(kdg_quota_burst);
	struct kdg_bucket *b = NULL, *freest = NULL;
	u64 now, add;
	u32 base, i;
	int ret;

	if (rate == 0 || burst == 0)
		return 0;		/* 关掉配额 */

	now = now_ms();
	base = hash_32(uid, 8) & (KDG_QUOTA_BUCKETS - 1);

	spin_lock(&g_q.lock);

	for (i = 0; i < KDG_QUOTA_PROBE; i++) {
		struct kdg_bucket *c =
			&g_q.buckets[(base + i) & (KDG_QUOTA_BUCKETS - 1)];

		if (c->used && c->uid == uid) {
			b = c;
			break;
		}
		if (!c->used && (!freest || c->last_ms < freest->last_ms))
			freest = c;
	}

	if (!b) {
		if (freest) {
			/* 空槽优先 */
			b = freest;
		} else {
			/* 窗口里全是别人的桶：替换最久未用的那个。
			 * 这是**有界**的取舍 —— 宁可让一个长期不活跃的调用方
			 * 丢掉历史令牌，也不让新调用方被永久拒绝。 */
			u32 oldest = base;

			for (i = 1; i < KDG_QUOTA_PROBE; i++) {
				u32 k = (base + i) & (KDG_QUOTA_BUCKETS - 1);

				if (g_q.buckets[k].last_ms <
				    g_q.buckets[oldest].last_ms)
					oldest = k;
			}
			b = &g_q.buckets[oldest];
		}
		b->uid = uid;
		b->tokens = burst;	/* 新调用方从满桶开始 */
		b->last_ms = now;
		b->denied = 0;
		b->used = true;
	}

	/* 按经过时间补 token；空闲很久则直接补满（上面封顶到 burst）。 */
	if (now > b->last_ms) {
		add = div_u64((now - b->last_ms) * (u64)rate, 1000u);
		if (add >= burst) {
			b->tokens = burst;
		} else {
			u64 t = (u64)b->tokens + add;

			b->tokens = (t > burst) ? burst : (u32)t;
		}
		b->last_ms = now;
	}

	if (b->tokens > 0) {
		b->tokens--;
		g_q.allowed++;
		ret = 0;
	} else {
		b->denied++;
		g_q.denied++;
		ret = -EAGAIN;
	}

	spin_unlock(&g_q.lock);
	return ret;
}

void kdg_quota_stats(struct kdg_quota_stats *out)
{
	u32 used = 0, i;

	if (!out)
		return;
	memset(out, 0, sizeof(*out));

	spin_lock(&g_q.lock);
	for (i = 0; i < KDG_QUOTA_BUCKETS; i++) {
		if (g_q.buckets[i].used)
			used++;
	}
	out->allowed = g_q.allowed;
	out->denied = g_q.denied;
	out->buckets_used = used;
	out->rate_per_sec = READ_ONCE(kdg_quota_rate);
	out->burst = READ_ONCE(kdg_quota_burst);
	spin_unlock(&g_q.lock);
}
