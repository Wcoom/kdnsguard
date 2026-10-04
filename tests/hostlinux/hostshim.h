/* SPDX-License-Identifier: GPL-2.0 */
/*
 * hostshim.h —— 让 kdg_pool.c 在宿主 gcc 上跑起来的内核替身。
 *
 * ⚠️ 这个 shim **只**服务 `tests/test_pool.c`。它模拟的是**同步语义**
 * （互斥、条件变量、超时、线程），不是内核语义；能不能用它证明池实现正确，
 * 取决于「池用到的原语在两边语义是否一致」。这里逐条列出依据：
 *
 *   wait_event(wq, cond)      ↔ 持 wq 锁判条件、不满足则睡。内核用
 *                                prepare_to_wait+schedule 得到同一效果
 *                                （判条件与入睡之间不会被 wake_up 穿过）。
 *   wait_event_timeout(...)   ↔ pthread_cond_timedwait，单调时钟。内核的
 *                                jiffies 超时同样是单调的。
 *   completion                ↔ 计数为 1 的信号量。池里每个槽位的
 *                                complete() 由 to_done_locked 保证只发一次，
 *                                所以 bool 语义与内核的计数语义在此等价。
 *   kthread_run/stop          ↔ pthread。kthread_should_stop() 走线程局部，
 *                                与内核的「每个 kthread 一个标志」一致。
 *   mutex                     ↔ **ERRORCHECK** 互斥锁：递归加锁会当场报错，
 *                                把「同一把锁重复取」这类错误变成显式失败，
 *                                而不是静默死锁。
 *
 * 它**不**模拟的东西（因此这些风险只能真机验证）：内核抢占、RCU、
 * kmalloc 的 GFP 语义、以及 kfree 与 kvfree 的区别 —— 后者尤其要注意，
 * 宿主把两者都映射成 free，**分配器类别错误在宿主上永远测不出来**
 * （2026-10-05 就是这么把手机重启过一次的，见 tools/build.sh 的配对门禁）。
 */
#ifndef KDG_HOSTSHIM_H
#define KDG_HOSTSHIM_H

#include <assert.h>
#include <errno.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

typedef uint8_t  u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;
typedef int8_t   s8;
typedef int16_t  s16;
typedef int32_t  s32;
typedef int64_t  s64;

/* UAPI 头（include/uapi/kdnsguard.h）用的是 __uN/__sN 拼法，宿主上由内核的
 * <linux/types.h> 提供。这里等价补齐，让那份头能原样解析 —— 它必须能在宿主
 * 上解析，否则 ABI 布局断言就无从谈起（见 clients/rust/kdg-client/tests/layout.rs）。 */
typedef uint8_t  __u8;
typedef uint16_t __u16;
typedef uint32_t __u32;
typedef uint64_t __u64;
typedef int8_t   __s8;
typedef int16_t  __s16;
typedef int32_t  __s32;
typedef int64_t  __s64;
typedef __u32    __be32;
typedef __u16    __be16;
#ifndef __user
#define __user
#endif

#ifndef __maybe_unused
#define __maybe_unused __attribute__((unused))
#endif
#ifndef ARRAY_SIZE
#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))
#endif

/* ── 诊断 ────────────────────────────────────────────────────────────── */

extern unsigned long host_warn_count;
extern unsigned long host_err_count;
extern unsigned long host_info_count;      /* pr_info 的次数 */
extern unsigned long host_warn_log_count;  /* pr_warn 的次数 */

/* ⚠️ 这几个宏**必须真的引用它们的参数**。写成 `#define pr_info(...) ((void)0)`
 * 会让被测代码里那些「只用于日志」的参数变成未使用参数，而 -Wextra 会把它
 * 报成错误 —— 那就成了「替身不忠实导致被测代码通不过」的假失败。
 * 内核的 pr_info 当然会引用它们，替身照做。 */
static inline void host_log_sink(const char *fmt, ...) { (void)fmt; }
static inline int host_log_count(unsigned long *ctr)
{ (*ctr)++; return 0; }

#define pr_info(fmt, ...)  do { host_log_count(&host_info_count); \
				host_log_sink((fmt), ##__VA_ARGS__); } while (0)
#define pr_warn(fmt, ...)  do { host_log_count(&host_warn_log_count); \
				host_log_sink((fmt), ##__VA_ARGS__); } while (0)
#define pr_err(fmt, ...)   do { host_log_count(&host_err_count); \
				host_log_sink((fmt), ##__VA_ARGS__); } while (0)
#define pr_warn_ratelimited(fmt, ...) pr_warn((fmt), ##__VA_ARGS__)
#define pr_err_ratelimited(fmt, ...)  pr_err((fmt), ##__VA_ARGS__)
#define WARN_ON_ONCE(c) host_warn_on_once(!!(c))

#define KBUILD_MODNAME "kdg_pool"

/* ── 类型与算术 ──────────────────────────────────────────────────────── */

#define NSEC_PER_MSEC 1000000ULL
#define GFP_KERNEL 0
#define div_u64(a, b) ((a) / (b))
#define clamp_val(v, lo, hi) ((v) < (lo) ? (lo) : ((v) > (hi) ? (hi) : (v)))
#define container_of(p, t, m) ((t *)((char *)(p) - offsetof(t, m)))
#define IS_ERR(p) ((unsigned long)(void *)(p) >= (unsigned long)-4095)
#define PTR_ERR(p) ((long)(p))
#define ERR_PTR(e) ((void *)(long)(e))

typedef long long ktime_t;

static inline u64 ktime_get_boottime_ns(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (u64)ts.tv_sec * 1000000000ULL + (u64)ts.tv_nsec;
}

/* ── 分配 ────────────────────────────────────────────────────────────── */

/* 与内核一致：只在**第一次**为真时计数并返回真。 */
int host_warn_on_once(int cond);

static inline void *kmalloc(size_t n, int f) { (void)f; return malloc(n); }
static inline void *kzalloc(size_t n, int f)
{ (void)f; return calloc(1, n); }
static inline void *kvcalloc(size_t n, size_t s, int f)
{ (void)f; return calloc(n, s); }
static inline void *kmemdup(const void *p, size_t n, int f)
{ void *o; (void)f; o = malloc(n); if (o) memcpy(o, p, n); return o; }
#define kfree free
#define kvfree free

/* ── 互斥 ────────────────────────────────────────────────────────────── */

struct mutex { pthread_mutex_t m; };

static inline void mutex_init(struct mutex *mu)
{
	pthread_mutexattr_t a;

	assert(pthread_mutexattr_init(&a) == 0);
	assert(pthread_mutexattr_settype(&a, PTHREAD_MUTEX_ERRORCHECK) == 0);
	assert(pthread_mutex_init(&mu->m, &a) == 0);
	pthread_mutexattr_destroy(&a);
}
static inline void mutex_lock(struct mutex *mu)
{
	int r = pthread_mutex_lock(&mu->m);

	/* EDEADLK 走这里就说明池里出现了「同一线程重复取同一把锁」 */
	assert(r == 0);
}
static inline void mutex_unlock(struct mutex *mu)
{
	assert(pthread_mutex_unlock(&mu->m) == 0);
}

/* ── 原子 ────────────────────────────────────────────────────────────── */

typedef atomic_int atomic_t;
typedef atomic_long atomic64_t;  /* kdg.h 的 per-netns 计数用到；本测试不碰它们 */
#define atomic_set(a, v) atomic_store((a), (v))
#define atomic_read(a) atomic_load(a)
#define atomic_inc(a) ((void)atomic_fetch_add((a), 1))
#define atomic_dec(a) ((void)atomic_fetch_sub((a), 1))
#define atomic_dec_and_test(a) (atomic_fetch_sub((a), 1) == 1)

/* READ_ONCE：内核用它表达「单次读取、不撕裂、编译器别优化掉」。
 * 宿主上 volatile 限定访问是等价物。 */
#define READ_ONCE(v) (*(volatile __typeof__(v) *)&(v))
#define WRITE_ONCE(v, x) (*(volatile __typeof__(v) *)&(v) = (x))

/* ── 链表 ────────────────────────────────────────────────────────────── */

struct list_head { struct list_head *next, *prev; };

static inline void INIT_LIST_HEAD(struct list_head *l)
{ l->next = l; l->prev = l; }
static inline int list_empty(const struct list_head *l) { return l->next == l; }
static inline void list_add_tail(struct list_head *n, struct list_head *h)
{ n->prev = h->prev; n->next = h; h->prev->next = n; h->prev = n; }
static inline void list_del_init(struct list_head *n)
{ n->prev->next = n->next; n->next->prev = n->prev; INIT_LIST_HEAD(n); }
#define list_first_entry(h, t, m) container_of((h)->next, t, m)

/* ── 等待队列 ────────────────────────────────────────────────────────── */

struct wait_queue_head {
	pthread_mutex_t m;
	pthread_cond_t  c;
};

typedef struct wait_queue_head wait_queue_head_t;

void host_wq_init(struct wait_queue_head *w);
#define init_waitqueue_head(w) host_wq_init(w)
#define wake_up(w) host_wake_all(w)
#define wake_up_all(w) host_wake_all(w)
void host_wake_all(struct wait_queue_head *w);

struct timespec host_deadline_after(long ms);

/* 判条件与入睡之间不会被 wake 穿过：条件在持 wq 锁的情况下判定，
 * wake_up 也要先取同一把锁。这正是内核 prepare_to_wait 提供的性质。 */
#define wait_event(wq, cond)						\
	do {								\
		pthread_mutex_lock(&(wq).m);				\
		while (!(cond))						\
			pthread_cond_wait(&(wq).c, &(wq).m);		\
		pthread_mutex_unlock(&(wq).m);				\
	} while (0)

/* 返回条件最终是否成立（内核返回剩余 jiffies，池不使用返回值）。 */
#define wait_event_timeout(wq, cond, tmo)				\
	({								\
		long __rv;						\
		struct timespec __dl = host_deadline_after((long)(tmo));\
		pthread_mutex_lock(&(wq).m);				\
		while (!(cond)) {					\
			if (pthread_cond_timedwait(&(wq).c, &(wq).m,	\
						   &__dl) != 0)		\
				break;					\
		}							\
		__rv = (cond) ? 1 : 0;					\
		pthread_mutex_unlock(&(wq).m);				\
		__rv;							\
	})

/* ── completion ──────────────────────────────────────────────────────── */

struct completion {
	pthread_mutex_t m;
	pthread_cond_t  c;
	bool		done;
};

void init_completion(struct completion *c);
void host_complete(struct completion *c);
long host_wait_completion_timeout(struct completion *c, unsigned long tmo_ms);
#define complete(c) host_complete(c)
#define wait_for_completion_timeout(c, tmo) \
	host_wait_completion_timeout((c), (unsigned long)(tmo))

/* ── jiffies：宿主上 1 jiffy == 1 ms ─────────────────────────────────── */
#define msecs_to_jiffies(ms) ((unsigned long)(ms))

/* ── kthread ─────────────────────────────────────────────────────────── */

struct task_struct;

struct task_struct *host_kthread_run(int (*fn)(void *), void *arg,
				     const char *name);
int  host_kthread_stop(struct task_struct *t);
bool host_kthread_should_stop(void);

#define kthread_run(fn, arg, name) host_kthread_run((fn), (arg), (name))
#define kthread_stop(t) host_kthread_stop(t)
#define kthread_should_stop() host_kthread_should_stop()

#endif /* KDG_HOSTSHIM_H */
