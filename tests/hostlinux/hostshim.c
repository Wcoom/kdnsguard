/* SPDX-License-Identifier: GPL-2.0 */
/*
 * hostshim.c —— hostshim.h 里那几个没法写成宏/内联的原语。
 */
#include "hostshim.h"

unsigned long host_warn_count;
unsigned long host_err_count;
unsigned long host_info_count;
unsigned long host_warn_log_count;

int host_warn_on_once(int cond)
{
	if (!cond)
		return 0;
	host_warn_count++;
	return 1;
}

/* ── 等待队列 ────────────────────────────────────────────────────────── */

static pthread_mutex_t g_wq_reg_lock = PTHREAD_MUTEX_INITIALIZER;

/*
 * 等待队列登记表：kthread_stop 要能「唤醒线程可能正在睡的任何地方」，
 * 而宿主没有 wake_up_process 那种按 task 唤醒的能力，只能广播所有 wq。
 *
 * ⚠️ 用**定长数组 + 指针去重**而不是链表，是被一次真实故障逼出来的：
 * 链式登记表在「同一个 wq 被 init 两次」时会形成自环（第二次 init 把
 * wq->next 指回它自己，因为上一次的头就是它），于是广播遍历永不终止 ——
 * 症状是「线程函数明明已经返回、pthread_join 却永不返回」，从现象完全
 * 反推不到这里。数组表对重复登记天然幂等，且不受 wq 结构体被整体清零
 * 的影响（指针存在表里，不在 wq 里）。
 */
#define HOST_MAX_WQ 8
static struct wait_queue_head *g_wq_tab[HOST_MAX_WQ];
static unsigned int g_wq_n;

static void host_wq_register(struct wait_queue_head *w)
{
	unsigned int i;

	assert(pthread_mutex_lock(&g_wq_reg_lock) == 0);
	for (i = 0; i < g_wq_n; i++) {
		if (g_wq_tab[i] == w) {
			assert(pthread_mutex_unlock(&g_wq_reg_lock) == 0);
			return;
		}
	}
	assert(g_wq_n < HOST_MAX_WQ);
	g_wq_tab[g_wq_n++] = w;
	assert(pthread_mutex_unlock(&g_wq_reg_lock) == 0);
}

void host_wq_init(struct wait_queue_head *w)
{
	pthread_condattr_t ca;

	assert(pthread_mutex_init(&w->m, NULL) == 0);
	assert(pthread_condattr_init(&ca) == 0);
	/* 单调时钟：用 CLOCK_REALTIME 的话，测试里任何一次系统时间跳变都可能
	 * 让超时永远不触发，那会表现成测试挂死而不是失败。 */
	assert(pthread_condattr_setclock(&ca, CLOCK_MONOTONIC) == 0);
	assert(pthread_cond_init(&w->c, &ca) == 0);
	pthread_condattr_destroy(&ca);

	host_wq_register(w);
}

void host_wake_all(struct wait_queue_head *w)
{
	assert(pthread_mutex_lock(&w->m) == 0);
	assert(pthread_cond_broadcast(&w->c) == 0);
	assert(pthread_mutex_unlock(&w->m) == 0);
}

struct timespec host_deadline_after(long ms)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	ts.tv_sec += ms / 1000;
	ts.tv_nsec += (ms % 1000) * 1000000L;
	if (ts.tv_nsec >= 1000000000L) {
		ts.tv_nsec -= 1000000000L;
		ts.tv_sec += 1;
	}
	return ts;
}

/* ── completion ──────────────────────────────────────────────────────── */

void init_completion(struct completion *c)
{
	pthread_condattr_t ca;

	assert(pthread_mutex_init(&c->m, NULL) == 0);
	assert(pthread_condattr_init(&ca) == 0);
	assert(pthread_condattr_setclock(&ca, CLOCK_MONOTONIC) == 0);
	assert(pthread_cond_init(&c->c, &ca) == 0);
	pthread_condattr_destroy(&ca);
	c->done = false;
}

void host_complete(struct completion *c)
{
	assert(pthread_mutex_lock(&c->m) == 0);
	c->done = true;
	assert(pthread_cond_broadcast(&c->c) == 0);
	assert(pthread_mutex_unlock(&c->m) == 0);
}

long host_wait_completion_timeout(struct completion *c, unsigned long tmo_ms)
{
	struct timespec dl = host_deadline_after((long)tmo_ms);
	long rv;

	assert(pthread_mutex_lock(&c->m) == 0);
	while (!c->done) {
		if (pthread_cond_timedwait(&c->c, &c->m, &dl) != 0)
			break;
	}
	rv = c->done ? 1 : 0;
	assert(pthread_mutex_unlock(&c->m) == 0);
	return rv;
}

static void host_wq_broadcast_all(void)
{
	unsigned int i;

	assert(pthread_mutex_lock(&g_wq_reg_lock) == 0);
	for (i = 0; i < g_wq_n; i++)
		host_wake_all(g_wq_tab[i]);
	assert(pthread_mutex_unlock(&g_wq_reg_lock) == 0);
}

/* ── kthread ─────────────────────────────────────────────────────────── */

struct task_struct {
	pthread_t	 tid;
	int	       (*fn)(void *);
	void		*arg;
	const char	*name;
	atomic_bool	 should_stop;
	atomic_bool	 running;
};

/* 每个线程一份：kthread_should_stop() 必须只看**当前**线程的标志，
 * 与内核按 task_struct 判断一致。用全局变量会让一个线程的停止标志
 * 影响另一个线程 —— 那正是这个 shim 最不该引入的错误。 */
static __thread struct task_struct *tls_task;

static void *host_thread_main(void *p)
{
	struct task_struct *t = p;

	tls_task = t;
	atomic_store(&t->running, true);
	t->fn(t->arg);
	atomic_store(&t->running, false);
	return NULL;
}

struct task_struct *host_kthread_run(int (*fn)(void *), void *arg,
				     const char *name)
{
	struct task_struct *t = calloc(1, sizeof(*t));

	assert(t != NULL);
	t->fn = fn;
	t->arg = arg;
	t->name = name;
	atomic_init(&t->should_stop, false);
	atomic_init(&t->running, false);
	assert(pthread_create(&t->tid, NULL, host_thread_main, t) == 0);
	return t;
}

int host_kthread_stop(struct task_struct *t)
{
	if (!t)
		return 0;

	atomic_store(&t->should_stop, true);

	/* 内核的 kthread_stop 走 wake_up_process，能把线程从**任意**等待点
	 * 唤醒。宿主没有这个能力，所以改为广播所有已登记的等待队列 ——
	 * 等价于「唤醒它可能正在睡的地方」。 */
	host_wq_broadcast_all();

	assert(pthread_join(t->tid, NULL) == 0);
	free(t);
	return 0;
}

bool host_kthread_should_stop(void)
{
	return tls_task ? atomic_load(&tls_task->should_stop) : false;
}
