/* SPDX-License-Identifier: GPL-2.0 */
/*
 * kdg_pool.c —— 上游 DoH 持久连接池。设计与并发模型见 kdg_pool.h。
 *
 * 本文件**只做策略**：槽位、排队、超期取消、空闲关闭、谁在等谁。
 * 建连/握手/收发/协议全在 kdg_upstream.c 里 —— 分开的直接好处是这个文件
 * 不依赖 mbedTLS 与 nghttp2，因而可以在宿主上用 gcc + ASan 跑并发测试
 * （见 tests/test_pool.c）。并发正确性是这里全部的风险所在，能测是硬要求。
 */
#define pr_fmt(fmt)	KBUILD_MODNAME ": pool: " fmt

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/mutex.h>
#include <linux/list.h>
#include <linux/wait.h>
#include <linux/kthread.h>
#include <linux/completion.h>
#include <linux/jiffies.h>
#include <linux/ktime.h>
#include <linux/timekeeping.h>
#include <linux/atomic.h>

#include "kdg.h"
#include "kdg_pool.h"
#include "kdg_upstream.h"

/* 槽位表上限。与同名合并的 waiter 上限（方案 §7.4 的 128）取同一个数，
 * 因为两者描述的是同一件事：同一时刻最多有多少个调用方在等上游。 */
#define KDG_POOL_MAX_REQS	128

/* 方案 §6.3：「空闲连接 60–180 秒关闭、无保活」。取区间中点。
 *
 * ⚠️ 允许被覆盖**只为宿主测试**（tests/test_pool.c 把它压到几百毫秒，
 * 否则「空闲关闭」这条路径要跑一分半才验得到）。产品构建不定义它，
 * 因此取值仍然由方案说了算 —— 这个开关改的是测试时长，不是行为语义。 */
#ifndef KDG_POOL_IDLE_MS
#define KDG_POOL_IDLE_MS	90000
#endif

/* 调用方等待自己的上限 = 它自己的 deadline + 这个余量。
 * 余量存在的意义是「这个上限只在池实现出错时才会触发」：正常路径下驱动
 * 线程的超期扫描一定在 deadline 内结算每一个槽位。见 kdg_pool_query。 */
#define KDG_POOL_WAIT_MARGIN_MS	2000

/* 对端不支持 h2 之后的抑制窗口。不抑制的话每次查询都要白建一次连接
 * （只有看到 ALPN 才能知道它不支持）；抑制太久又会让「上游后来升级了」
 * 迟迟不被发现。一分钟是这两者之间的取舍。 */
#define KDG_POOL_H1_SUPPRESS_MS	60000

/* 从 TLS 搬字节的临时区。**与一条流多大无关**：它只决定「一次读多少」。 */
#define KDG_POOL_IN_BUF		4096

/* ── 槽位 ────────────────────────────────────────────────────────────── */

enum kdg_slot_state {
	KDG_SLOT_FREE = 0,
	KDG_SLOT_ALLOC,		/* 已取出，调用方正在填字段 */
	KDG_SLOT_QUEUED,	/* 已入队，等驱动线程提交成流 */
	KDG_SLOT_INFLIGHT,	/* 已是 H2 流，等响应 */
	KDG_SLOT_DONE,		/* 有结果了，等调用方取走（或等驱动线程归还） */
};

struct kdg_pool_req {
	struct completion	done;
	struct kdg_h2_stream	st;
	struct list_head	node;		/* QUEUED 时挂在 pending 链上 */
	u8		       *body;		/* 查询报文的**本层副本** */
	size_t			body_len;
	int			result;		/* 最终 errno，0 表示成功 */
	int32_t			stream_id;
	u64			expire_ms;	/* 绝对到期时刻 */
	u8			state;
	bool			rst_sent;	/* 已为该流发过 RST_STREAM */
	/* 调用方已超时离开，收尾与释放的责任转给驱动线程。只在锁内改。 */
	bool			abandoned;
};

/* ── 池 ──────────────────────────────────────────────────────────────── */

struct kdg_pool {
	struct mutex		lock;
	struct list_head	pending;
	struct kdg_pool_req	*reqs;
	unsigned int		n_reqs;
	unsigned int		slots_used;
	unsigned int		n_inflight;

	struct task_struct	*thread;
	struct wait_queue_head	wq;
	bool			stopping;

	/* 当前连接。NULL 表示没有连接 —— **只有它非空时上游才可用**，
	 * 因此不需要另设 connected/h2_ready 这类能与之不同步的布尔量。 */
	struct kdg_upstream	*up;
	/* 连接身份。与进来的 cfg 不一致就重建。cfg_valid 的用处是区分
	 * 「还没设过」与「设过但恰好都是零值」。 */
	struct kdg_doh_cfg	cfg;
	bool			cfg_valid;
	bool			h1_only;	/* 对端 ALPN 不是 h2 */
	u64			h1_until_ms;
	/* 上游身份变了的待办。**只由驱动线程执行**：拆连接这件事只有它有权做，
	 * 因为只有它知道此刻没有一次读正拿着那个对象（见 check_identity 的注释）。 */
	bool			rebuild;
	/* 对端声明的并发流上限的**缓存**。驱动线程负责刷新，其他线程只读 ——
	 * nghttp2 的会话不是线程安全的，从别的线程去读它的 remote_settings
	 * 就是并发访问协议栈内部状态。 */
	u32			stream_limit;

	u64			idle_since_ms;	/* 0 = 有活、或还没进入空闲计时 */
	atomic_t		outstanding;	/* QUEUED + INFLIGHT 的槽数 */
	/* 正在 kdg_pool_query 里、尚未返回的调用方数。卸载时用它等人走完，
	 * 而不是靠「上层保证没有调用方了」这句注释 —— 见 kdg_pool_shutdown。 */
	atomic_t		active;

	u8			inbuf[KDG_POOL_IN_BUF];
	struct kdg_pool_stats	stat;
};

static struct kdg_pool g_pool;

static inline u64 kdg_pool_now_ms(void)
{
	/* 与缓存/mbedTLS 同一口径：CLOCK_BOOTTIME，含休眠（方案 §9.3）。 */
	return div_u64(ktime_get_boottime_ns(), NSEC_PER_MSEC);
}

/* ── 槽位原语（全部在 g_pool.lock 下调用）────────────────────────────── */

static struct kdg_pool_req *kdg_pool_alloc_slot_locked(void)
{
	unsigned int i;

	if (g_pool.slots_used >= g_pool.n_reqs)
		return NULL;

	for (i = 0; i < g_pool.n_reqs; i++) {
		struct kdg_pool_req *r = &g_pool.reqs[i];

		if (r->state != KDG_SLOT_FREE)
			continue;

		/* memset 会清掉内嵌的 completion，紧接着的 init_completion
		 * 把它重新立好 —— 顺序是必须的，反过来就是拿未初始化对象用。 */
		memset(r, 0, sizeof(*r));
		init_completion(&r->done);
		INIT_LIST_HEAD(&r->node);
		r->state = KDG_SLOT_ALLOC;
		g_pool.slots_used++;
		return r;
	}
	return NULL;
}

/*
 * 把槽位推到终态并唤醒调用方。
 *
 * **这是唯一会 complete() 的地方**，因此「outstanding 递减一次」与「调用方
 * 被唤醒一次」在构造上同步 —— 不存在「醒来了但计数没减」的窗口。
 */
static void kdg_pool_to_done_locked(struct kdg_pool_req *r, int result)
{
	if (r->state != KDG_SLOT_QUEUED && r->state != KDG_SLOT_INFLIGHT)
		return;

	if (r->state == KDG_SLOT_QUEUED)
		list_del_init(&r->node);
	else
		g_pool.n_inflight--;

	r->result = result;
	r->state = KDG_SLOT_DONE;
	r->st.in_flight = false;
	atomic_dec(&g_pool.outstanding);
	complete(&r->done);
}

/*
 * 归还槽位。**前提是协议栈已经彻底忘掉这条流**（st.in_flight == false）——
 * 见 kdg_pool.h 里关于串台的那条说明。
 */
static void kdg_pool_free_slot_locked(struct kdg_pool_req *r)
{
	/* ALLOC 态（还没入队）没有流，可直接归还；DONE 态要等流彻底关闭。 */
	if (r->state != KDG_SLOT_ALLOC && r->state != KDG_SLOT_DONE)
		return;
	if (r->st.in_flight) {
		/* 不该发生：settle/reap 只把 !in_flight 的流推到 DONE。
		 * 真发生了就留在 DONE，由驱动线程下一轮收尾 —— 绝不冒险复用。 */
		WARN_ON_ONCE(1);
		return;
	}

	kfree(r->body);
	r->body = NULL;
	r->abandoned = false;
	r->rst_sent = false;
	r->state = KDG_SLOT_FREE;
	if (g_pool.slots_used)
		g_pool.slots_used--;
}

/*
 * 结算：把到达终态的流交给调用方。
 *
 * 条件里的 `!st.in_flight` 是这份实现最容易写错的地方：END_STREAM 只说明
 * 「响应收齐了」，而 nghttp2 紧接着还会在 on_stream_close 回调里写这个收集
 * 结构。必须等它彻底关掉流，槽位才可以复用。正常路径下这两个回调发生在
 * **同一次 mem_recv 内**，因此这里不会引入任何延迟。
 */
static void kdg_pool_settle_locked(void)
{
	unsigned int i;

	for (i = 0; i < g_pool.n_reqs; i++) {
		struct kdg_pool_req *r = &g_pool.reqs[i];

		if (r->state != KDG_SLOT_INFLIGHT || r->st.in_flight)
			continue;
		if (!r->st.done && !r->st.err)
			continue;

		if (r->st.err) {
			kdg_pool_to_done_locked(r, r->st.err);
		} else if (!r->st.status_seen) {
			pr_warn_ratelimited("H2 响应缺少 :status\n");
			kdg_pool_to_done_locked(r, -EBADMSG);
		} else if (r->st.status != 200) {
			/* 与 H1 路径同一套验收标准（方案 §8）：非 200 不当 DNS 用。 */
			pr_warn_ratelimited("DoH 上游返回 HTTP %u\n", r->st.status);
			kdg_pool_to_done_locked(r, -EPROTO);
		} else if (!r->st.ct_ok) {
			pr_warn_ratelimited("Content-Type 不是 application/dns-message\n");
			kdg_pool_to_done_locked(r, -EBADMSG);
		} else {
			kdg_pool_to_done_locked(r, 0);
		}
	}
}

/*
 * 归还被放弃的槽位。**只有驱动线程调用** —— 调用方走了就不该再碰它。
 *
 * 在途的不能直接推终态：nghttp2 之后还会回调它。这里只发一次 RST_STREAM，
 * 等 on_stream_close 把 in_flight 清掉、settle 推到 DONE 之后，下一轮再归还。
 */
static void kdg_pool_reap_locked(void)
{
	unsigned int i;

	for (i = 0; i < g_pool.n_reqs; i++) {
		struct kdg_pool_req *r = &g_pool.reqs[i];

		if (r->state == KDG_SLOT_FREE || !r->abandoned)
			continue;

		if (r->state == KDG_SLOT_INFLIGHT) {
			if (!r->rst_sent && g_pool.up) {
				kdg_upstream_reset_stream(g_pool.up,
							  r->stream_id);
				r->rst_sent = true;
				g_pool.stat.stream_resets_sent++;
			}
			continue;
		}
		if (r->state == KDG_SLOT_QUEUED)
			kdg_pool_to_done_locked(r, -ECANCELED);
		/* 走到这里 state 必为 DONE 且 !in_flight */
		kdg_pool_free_slot_locked(r);
	}
}

/*
 * 超期扫描。到期的请求**由池自己取消**，而不是让调用方干等自己的上限 ——
 * 后者会把「上游慢」变成「池的 deadline 加余量」，误差随实现变化。
 */
static void kdg_pool_sweep_locked(void)
{
	u64 now = kdg_pool_now_ms();
	unsigned int i;

	for (i = 0; i < g_pool.n_reqs; i++) {
		struct kdg_pool_req *r = &g_pool.reqs[i];

		if (r->state != KDG_SLOT_QUEUED && r->state != KDG_SLOT_INFLIGHT)
			continue;
		if (r->abandoned || now < r->expire_ms)
			continue;

		if (r->state == KDG_SLOT_QUEUED) {
			kdg_pool_to_done_locked(r, -ETIMEDOUT);
			continue;
		}

		/* 在途：记下错误并发 RST，但**不**在这里推终态 —— 要等
		 * on_stream_close 清掉 in_flight，settle 才敢交付。 */
		if (!r->st.err)
			r->st.err = -ETIMEDOUT;
		if (!r->rst_sent && g_pool.up) {
			kdg_upstream_reset_stream(g_pool.up, r->stream_id);
			r->rst_sent = true;
			g_pool.stat.stream_resets_sent++;
		}
		g_pool.stat.upstream_timeouts++;
	}
}

/* 拆连接。**必须确认没有在途流**，或者紧跟着 fail_all —— 因为拆掉之后
 * 槽位里还标着 in_flight 的流永远不会被协议栈关掉。 */
static void kdg_pool_close_conn_locked(const char *reason)
{
	if (!g_pool.up)
		return;

	kdg_upstream_close(g_pool.up);
	g_pool.up = NULL;
	g_pool.idle_since_ms = 0;
	g_pool.stream_limit = 0;
	pr_info("上游连接已关闭（%s）\n", reason);
}

/*
 * 连接级失败：在途与排队的全部失败掉。
 *
 * ⚠️ 调用前必须已经 close_conn —— 会话一销毁，nghttp2 就不可能再回调，
 * `in_flight` 才敢由我们自己清零。顺序反过来就是 use-after-free
 * （回调往已归还的槽位写）。函数的形状刻意做成「先拆、再清」两步，
 * 就是为了让这个前提在每一处调用点都看得见。
 */
static void kdg_pool_fail_all_locked(int err)
{
	unsigned int i;

	for (i = 0; i < g_pool.n_reqs; i++) {
		struct kdg_pool_req *r = &g_pool.reqs[i];

		if (r->state != KDG_SLOT_QUEUED && r->state != KDG_SLOT_INFLIGHT)
			continue;
		r->st.in_flight = false;
		kdg_pool_to_done_locked(r, err);
	}
}

/*
 * 只失败**已经发出去**的流。上游身份变化时用。
 *
 * 与 fail_all 的区别是队列里那部分：它们**还没绑定任何上游**，重连之后
 * 照常提交即可 —— 换个上游不该让还没发出去的请求白失败一次。而发出去的
 * 那些结果是旧上游给的，照旧回给调用方等于「换了上游却当没换」
 * （方案 §8「拒绝跨上游身份跳转」）。
 */
static void kdg_pool_fail_inflight_locked(int err)
{
	unsigned int i;

	for (i = 0; i < g_pool.n_reqs; i++) {
		struct kdg_pool_req *r = &g_pool.reqs[i];

		if (r->state != KDG_SLOT_INFLIGHT)
			continue;
		r->st.in_flight = false;
		kdg_pool_to_done_locked(r, err);
	}
}

/* 只失败还没提交成流的那些。建连失败时用 —— 那时并不存在在途流。 */
static void kdg_pool_fail_pending_locked(int err)
{
	unsigned int i;

	for (i = 0; i < g_pool.n_reqs; i++) {
		struct kdg_pool_req *r = &g_pool.reqs[i];

		if (r->state == KDG_SLOT_QUEUED)
			kdg_pool_to_done_locked(r, err);
	}
}

static void kdg_pool_conn_failed_locked(int err)
{
	g_pool.stat.conn_errors++;
	kdg_pool_close_conn_locked("连接级错误");
	kdg_pool_fail_all_locked(err);
}

/* ── 连接身份 ────────────────────────────────────────────────────────── */

static bool kdg_pool_identity_same_locked(const struct kdg_doh_cfg *cfg)
{
	return g_pool.cfg_valid &&
	       g_pool.cfg.ip_be == cfg->ip_be &&
	       g_pool.cfg.port_be == cfg->port_be &&
	       strcmp(g_pool.cfg.hostname, cfg->hostname) == 0 &&
	       strcmp(g_pool.cfg.path, cfg->path) == 0;
}

/*
 * 上游身份变了就重建连接。**在途流会被失败掉**而不是让它们跑完 —— 它们
 * 发往的是旧上游，把结果照旧回给调用方等于「换了上游却当没换」，与方案 §8
 * 「拒绝跨上游身份跳转」是同一立场。是否重试是编排层的决策。
 */
static void kdg_pool_check_identity_locked(const struct kdg_doh_cfg *cfg)
{
	bool changed = g_pool.cfg_valid;

	if (kdg_pool_identity_same_locked(cfg))
		return;

	if (changed) {
		/*
		 * ⚠️ 这里**只记意图，不拆连接**。
		 *
		 * 本函数跑在**调用方**线程上，而驱动线程可能正阻塞在一次
		 * `kdg_upstream_read()` 里 —— 那一段是**不持 g_pool.lock 的**
		 * （读要阻塞到有数据，不能占着锁）。调用方此时去
		 * `kdg_upstream_close()`，就是把它脚下的对象 free 掉：
		 * tls/socket/nghttp2 会话全没了，而驱动线程手里还攥着指针。
		 * 这是标准的 use-after-free，而且只在「恰好同时」出现。
		 *
		 * 拆连接是驱动线程的独占权限：只有它知道此刻没有读在用这个对象。
		 * 于是这里留下一个待办，由驱动线程在下一轮循环的开头执行。
		 */
		pr_info("上游身份变化，等待驱动线程重建连接\n");
		g_pool.rebuild = true;

		/* 换了上游就该重新试一次 h2 协商，否则一次偶然的非 h2 响应
		 * 会把新上游也永久锁在 H1 兼容路径上。 */
		g_pool.h1_only = false;
		g_pool.h1_until_ms = 0;
	}

	g_pool.cfg = *cfg;
	g_pool.cfg_valid = true;
}

static int kdg_pool_connect_locked(void)
{
	int ret;

	if (g_pool.up)
		return 0;

	ret = kdg_upstream_open(&g_pool.up, &g_pool.cfg, g_pool.cfg.deadline_ms);
	if (ret) {
		if (ret == -EPROTONOSUPPORT) {
			/* 方案 §6.4：H1 是兼容路径。这里**有意不实现 H1
			 * keep-alive** —— 一条「协商结果不支持 h2」的连接不值得
			 * 再养一套分帧与边界状态机。关掉它，把请求交回
			 * kdg_doh.c 已有的一次性 H1 实现，两份代码各自简单。 */
			g_pool.h1_only = true;
			g_pool.h1_until_ms = kdg_pool_now_ms() + KDG_POOL_H1_SUPPRESS_MS;
		}
		return ret;
	}

	g_pool.idle_since_ms = 0;
	g_pool.stat.connects++;
	return 0;
}

/* ── 驱动 ────────────────────────────────────────────────────────────── */

/* 把排队的请求提交成流。 */
static void kdg_pool_pump_locked(void)
{
	if (list_empty(&g_pool.pending))
		return;

	if (!g_pool.up) {
		int ret;

		if (g_pool.h1_only && kdg_pool_now_ms() < g_pool.h1_until_ms) {
			kdg_pool_fail_pending_locked(-EPROTONOSUPPORT);
			return;
		}

		ret = kdg_pool_connect_locked();
		if (ret) {
			kdg_pool_fail_pending_locked(ret);
			return;
		}
	}

	while (g_pool.n_inflight < kdg_upstream_stream_limit(g_pool.up) &&
	       !list_empty(&g_pool.pending)) {
		struct kdg_pool_req *r = list_first_entry(&g_pool.pending,
						struct kdg_pool_req, node);
		int32_t id;

		if (kdg_upstream_submit(g_pool.up, r->body, r->body_len,
					&r->st, &id) != 0) {
			kdg_pool_conn_failed_locked(-EBADMSG);
			return;
		}
		list_del_init(&r->node);
		r->stream_id = id;
		r->state = KDG_SLOT_INFLIGHT;
		g_pool.n_inflight++;
	}

	if (kdg_upstream_flush(g_pool.up) != 0)
		kdg_pool_conn_failed_locked(-EBADMSG);

	g_pool.stream_limit = kdg_upstream_stream_limit(g_pool.up);
}

static void kdg_pool_service_locked(void)
{
	kdg_pool_sweep_locked();
	kdg_pool_settle_locked();
	kdg_pool_reap_locked();
}

/* 一轮驱动：先结算与扫超期，再读一批（read 内部会喂协议栈）。 */
static void kdg_pool_drive_once(void)
{
	int n;

	mutex_lock(&g_pool.lock);
	kdg_pool_service_locked();
	/* RST_STREAM 与 SETTINGS ACK 之类要立刻送出去，不能等下一次读回来 */
	if (g_pool.up && kdg_upstream_flush(g_pool.up) != 0)
		kdg_pool_conn_failed_locked(-EBADMSG);
	mutex_unlock(&g_pool.lock);

	if (!g_pool.up)
		return;

	n = kdg_upstream_read(g_pool.up, g_pool.inbuf, sizeof(g_pool.inbuf));
	if (n == -EAGAIN)
		return;			/* 滴答到期、没数据 —— 回去再扫一遍 */
	if (n < 0) {
		mutex_lock(&g_pool.lock);
		kdg_pool_conn_failed_locked(n);
		mutex_unlock(&g_pool.lock);
		return;
	}

	mutex_lock(&g_pool.lock);
	kdg_pool_settle_locked();
	kdg_pool_reap_locked();
	if (g_pool.up && kdg_upstream_dead(g_pool.up))
		kdg_pool_conn_failed_locked(kdg_upstream_err(g_pool.up));
	mutex_unlock(&g_pool.lock);
}

/* ── 驱动线程 ────────────────────────────────────────────────────────── */

static bool kdg_pool_has_work(void)
{
	return kthread_should_stop() ||
	       READ_ONCE(g_pool.stopping) ||
	       atomic_read(&g_pool.outstanding) > 0 ||
	       !list_empty(&g_pool.pending);
}

static int kdg_pool_thread(void *arg)
{
	(void)arg;

	while (!kthread_should_stop()) {
		bool busy;

		mutex_lock(&g_pool.lock);
		if (g_pool.rebuild) {
			/* 先拆再清，顺序是硬的（见 fail_all 的注释）。只失败
			 * 已发出去的流：队列里的那些还没绑定任何上游，重连后
			 * 照常提交 —— 触发本次重建的那条请求就在队列里，它本来就
			 * 是冲着新上游来的。 */
			kdg_pool_close_conn_locked("上游变更");
			kdg_pool_fail_inflight_locked(-ESTALE);
			g_pool.rebuild = false;
		}
		kdg_pool_service_locked();
		kdg_pool_pump_locked();
		busy = atomic_read(&g_pool.outstanding) > 0;
		mutex_unlock(&g_pool.lock);

		if (busy) {
			kdg_pool_drive_once();
			continue;
		}

		/*
		 * 没在途请求了。连接留不留？方案 §6.3 要求 60–180 秒空闲后关闭。
		 * 两个分支的区别只在于「还要不要醒过来」：连接已关就无限期睡
		 * （方案 §9.3「无请求时 worker 睡眠」），连接还在就按剩余空闲
		 * 时间睡一个定时器 —— 那是**每次连接一次**的定时器，不是周期轮询。
		 */
		mutex_lock(&g_pool.lock);
		if (g_pool.up) {
			u64 now = kdg_pool_now_ms();
			u64 wait_ms;

			if (!g_pool.idle_since_ms)
				g_pool.idle_since_ms = now;

			if (now - g_pool.idle_since_ms >= KDG_POOL_IDLE_MS) {
				g_pool.stat.idle_closes++;
				kdg_pool_close_conn_locked("空闲超时");
				mutex_unlock(&g_pool.lock);
				continue;	/* 下一轮走无限期睡眠分支 */
			}
			wait_ms = KDG_POOL_IDLE_MS - (now - g_pool.idle_since_ms);
			mutex_unlock(&g_pool.lock);
			wait_event_timeout(g_pool.wq, kdg_pool_has_work(),
					   msecs_to_jiffies(wait_ms));
			continue;
		}
		mutex_unlock(&g_pool.lock);
		wait_event(g_pool.wq, kdg_pool_has_work());
	}

	/* 退出：把还可能有人等的槽位全部失败掉，再拆连接。
	 * 正常卸载时调用方早已退场（见 kdg_pool.h 的交接约定），这里是兜底。 */
	mutex_lock(&g_pool.lock);
	kdg_pool_close_conn_locked("驱动线程退出");
	kdg_pool_fail_all_locked(-ESHUTDOWN);
	/* 被放弃的槽位从此再没人管（驱动线程是唯一会归还它们的人），
	 * 在这里一并还掉，免得卸载时留下几个孤儿 body。 */
	kdg_pool_reap_locked();
	mutex_unlock(&g_pool.lock);
	return 0;
}

static int kdg_pool_ensure_thread(void)
{
	struct task_struct *t;
	int ret = 0;

	if (READ_ONCE(g_pool.thread))
		return 0;

	/* 懒启动：模块加载时不建线程，第一次真要查上游时才建（方案 §9.3）。
	 * kthread_run 放在锁内：新线程第一件事就是抢这把锁，放外面会多出
	 * 一个「建好了但还没登记」的窗口，而那个窗口里第二个调用方会再建一个。 */
	mutex_lock(&g_pool.lock);
	if (!g_pool.thread) {
		t = kthread_run(kdg_pool_thread, NULL, "kdg_pool");
		if (IS_ERR(t)) {
			ret = (int)PTR_ERR(t);
			pr_err("驱动线程创建失败: %d\n", ret);
		} else {
			g_pool.thread = t;
		}
	}
	mutex_unlock(&g_pool.lock);
	return ret;
}

/* ── 对外接口 ────────────────────────────────────────────────────────── */

int kdg_pool_init(void)
{
	/*
	 * 全量清零再重建 —— init 的语义就是「一个全新的池」。
	 *
	 * 逐字段手工复位是这里最容易漏的地方：连接、上游身份、h1 抑制窗口、
	 * 统计量，少复位一个就是跨生命周期（在真机上是跨模块重载，在宿主测试
	 * 里是跨用例）的状态泄漏 —— 而「上一个用例留下的状态」会让后一个用例
	 * 的失败与被测代码毫无关系。清零只做一次，列清单要维护一辈子。
	 *
	 * ⚠️ 清零必须在**没有任何线程在跑**时进行：shutdown 已保证驱动线程退出、
	 * 调用方离场，本函数由模块 init（或测试）在同样前提下调用。
	 */
	memset(&g_pool, 0, sizeof(g_pool));

	mutex_init(&g_pool.lock);
	INIT_LIST_HEAD(&g_pool.pending);
	init_waitqueue_head(&g_pool.wq);
	atomic_set(&g_pool.outstanding, 0);
	atomic_set(&g_pool.active, 0);

	/* ⚠️ 必须 kvcalloc：128 个槽 ≈ 23 KiB，超出 kmalloc 单次分配的上限
	 * （本机 PAGE_SIZE=4 KiB、kmalloc 最高 8 KiB），kmalloc 会直接返回
	 * NULL 而**不会**回落到 vmalloc。相应地释放必须用 kvfree —— 用 kfree
	 * 释放 vmalloc 地址会 panic 重启（2026-10-05 在 kdg_map_exit 上正是
	 * 这么把手机重启过一次）。tools/build.sh 有配对门禁守着这一条。 */
	g_pool.reqs = kvcalloc(KDG_POOL_MAX_REQS, sizeof(struct kdg_pool_req),
			       GFP_KERNEL);
	if (!g_pool.reqs)
		return -ENOMEM;
	g_pool.n_reqs = KDG_POOL_MAX_REQS;
	return 0;
}

void kdg_pool_shutdown(void)
{
	struct task_struct *t = NULL;

	if (!g_pool.reqs)
		return;

	mutex_lock(&g_pool.lock);
	g_pool.stopping = true;
	if (g_pool.thread) {
		t = g_pool.thread;
		g_pool.thread = NULL;
	}
	mutex_unlock(&g_pool.lock);
	wake_up_all(&g_pool.wq);

	if (t)
		kthread_stop(t);

	/*
	 * 等所有调用方离场，再放掉槽位表。
	 *
	 * 为什么不靠「上层已经保证没有调用方了」那句话：kdg_chardev_exit 与
	 * kdg_listener_stop 确实各自等了（active_ops / kthread_stop），但那是
	 * **调用点的纪律** —— 将来多一个查询入口、或某条路径没等干净，症状就是
	 * 「往已释放的槽位表里写」这种与本次改动看不出因果关系的偶发 panic。
	 * 一个计数器就把它变成结构上的保证，代价是一次原子读。
	 */
	wait_event(g_pool.wq, atomic_read(&g_pool.active) == 0);

	mutex_lock(&g_pool.lock);
	kvfree(g_pool.reqs);
	g_pool.reqs = NULL;
	g_pool.n_reqs = 0;
	g_pool.slots_used = 0;
	g_pool.n_inflight = 0;
	mutex_unlock(&g_pool.lock);
}

int kdg_pool_query(const struct kdg_doh_cfg *cfg,
		   const u8 *qwire, size_t qlen,
		   u8 *rwire, size_t *rlen)
{
	struct kdg_pool_req *r;
	u32 deadline;
	u64 expire;
	unsigned long left;
	int ret;

	if (!cfg || !qwire || !rwire || !rlen)
		return -EINVAL;
	if (qlen == 0 || qlen > KDG_MAX_WIRE_MSG)
		return -EMSGSIZE;
	if (*rlen == 0)
		return -EMSGSIZE;

	ret = kdg_pool_ensure_thread();
	if (ret)
		return ret;

	deadline = cfg->deadline_ms ? cfg->deadline_ms : KDG_DEFAULT_DEADLINE_MS;

	/*
	 * 到期时刻在**取锁之前**算好。取锁可能要等驱动线程做完一次握手的
	 * 收尾；若从取到锁之后才起算，调用方的实际等待会变成「等待时长 +
	 * deadline」，与它请求的语义不符 —— 它要的从来是「这次查询多久没
	 * 结果就算失败」。
	 */
	expire = kdg_pool_now_ms() + deadline;

	mutex_lock(&g_pool.lock);

	/*
	 * 装载闸门：判定 stopping 与自增 active 必须在**同一段临界区**里。
	 * 分两次取锁会留下这个窗口 —— 调用方读到 stopping==false，紧接着
	 * 卸载线程置位、看到 active==0、放掉槽位表，而调用方正要往里写。
	 */
	if (g_pool.stopping) {
		mutex_unlock(&g_pool.lock);
		return -ESHUTDOWN;
	}
	atomic_inc(&g_pool.active);

	/* 对端已明确不支持 h2：不要再白建连接，直接交回 H1 兼容路径。
	 * （计数在 out_caller 统一做 —— 首次发现与后续抑制走的是同一条
	 * 出口，在那里算才不会漏掉「发现的那一次」。） */
	if (g_pool.h1_only && kdg_pool_now_ms() < g_pool.h1_until_ms) {
		ret = -EPROTONOSUPPORT;
		goto out_caller;
	}

	kdg_pool_check_identity_locked(cfg);

	r = kdg_pool_alloc_slot_locked();
	if (!r) {
		g_pool.stat.rejected++;
		ret = -EAGAIN;
		goto out_caller;
	}

	/* 报文拷进槽位，而不是持有调用方的指针：调用方超时离开之后它的栈/堆
	 * 可能已经不在了，而流可能还在飞。 */
	r->body = kmemdup(qwire, qlen, GFP_KERNEL);
	if (!r->body) {
		kdg_pool_free_slot_locked(r);
		ret = -ENOMEM;
		goto out_caller;
	}
	r->body_len = qlen;
	r->st.resp = rwire;
	r->st.resp_cap = *rlen;
	r->expire_ms = expire;
	r->state = KDG_SLOT_QUEUED;
	list_add_tail(&r->node, &g_pool.pending);
	atomic_inc(&g_pool.outstanding);
	g_pool.idle_since_ms = 0;	/* 有活了，空闲计时重来 */
	g_pool.stat.queries++;
	if (g_pool.up)
		g_pool.stat.reused++;	/* 池化的直接证据：连接早就在了 */

	mutex_unlock(&g_pool.lock);
	wake_up(&g_pool.wq);

	left = wait_for_completion_timeout(&r->done,
			msecs_to_jiffies(deadline + KDG_POOL_WAIT_MARGIN_MS));

	mutex_lock(&g_pool.lock);

	if (!left && r->state != KDG_SLOT_DONE) {
		/*
		 * **正常路径下到不了这里**：驱动线程的超期扫描会在 deadline
		 * 内结算每一个槽位。真到了这里说明池实现有问题，此时绝不能
		 * 自己释放槽位 —— 协议栈可能还持有它的指针。标记放弃，
		 * 由驱动线程收尾（它会在 in_flight 清掉之后归还）。
		 *
		 * 注意这里**不**释放 r：out_caller 只做「调用方离场」的记账。
		 */
		r->abandoned = true;
		g_pool.stat.wait_timeouts++;
		pr_err_ratelimited("请求等待超出上限，已交由驱动线程收尾\n");
		ret = -ETIMEDOUT;
		goto out_caller;
	}

	ret = r->result;
	if (ret == 0) {
		size_t n = r->st.resp_len;

		if (n > *rlen)
			ret = -EMSGSIZE;
		else
			*rlen = n;
	}
	/* 归还。此刻 nghttp2 已经忘掉这条流（settle 的前置条件），安全。 */
	kdg_pool_free_slot_locked(r);

out_caller:
	if (ret == -EPROTONOSUPPORT)
		g_pool.stat.h1_fallbacks++;	/* 本次查询由 H1 兼容路径接手 */
	if (atomic_dec_and_test(&g_pool.active))
		wake_up(&g_pool.wq);
	mutex_unlock(&g_pool.lock);
	return ret;
}

/*
 * ⚠️ 本函数会取 g_pool.lock，而驱动线程**建连期间**（做 TCP 连接与 TLS
 * 握手）也持有它 —— 所以一次 GET_HEALTH 最坏要等一个 deadline。这是有意的
 * 取舍：诊断接口不该为了「永远不阻塞」而绕过锁去读正在被改的状态。
 */
void kdg_pool_get_stats(struct kdg_pool_stats *out)
{
	unsigned int i, queued = 0;

	if (!out)
		return;

	mutex_lock(&g_pool.lock);
	*out = g_pool.stat;
	for (i = 0; i < g_pool.n_reqs; i++)
		if (g_pool.reqs[i].state == KDG_SLOT_QUEUED)
			queued++;
	out->inflight = g_pool.n_inflight;
	out->queued = queued;
	out->stream_limit = g_pool.stream_limit;
	out->slots_used = g_pool.slots_used;
	out->slots_max = g_pool.n_reqs;
	out->connected = g_pool.up ? 1 : 0;
	mutex_unlock(&g_pool.lock);
}
