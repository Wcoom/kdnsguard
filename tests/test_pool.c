/* SPDX-License-Identifier: GPL-2.0 */
/*
 * test_pool.c —— 连接池状态机的宿主并发测试（gcc + ASan/UBSan + pthread）。
 *
 * 为什么这一段代码值得单独被测：池里全部的风险都是**并发**风险 ——
 * 槽位双重释放、协议栈回调打到已复用的槽上（串台）、唤醒丢失导致挂死、
 * 锁序倒置。这些在真机上表现成「手机重启」或「没响应且无日志」，几乎无法
 * 事后定位；而在宿主上 ASan 会在越界/双重释放的当场报出来、超时会挂死
 * 而不是给出错误结果，两者都是**可判定**的。
 *
 * 被测文件是 kernel/kdg_pool.c **原文**（不是副本、不是镜像），依靠
 * tests/hostlinux/ 下那一组 <linux/…> 替身编译。kdg_upstream_* 在这里被替换成
 * 一个可编排的替身（真正的实现在 kdg_upstream.c，它要 mbedTLS 与 nghttp2，
 * 宿主上跑不起来也不该跑 —— 那部分是协议栈的活，不是池的）。
 */
#include "hostlinux/hostshim.h"

#include <sched.h>
#include <unistd.h>

#include "../../kernel/kdg.h"
#include "../../kernel/kdg_pool.h"
#include "../../kernel/kdg_upstream.h"
#include "../../kernel/kdg_h2stream.h"

/* ── 断言 ────────────────────────────────────────────────────────────── */

static int g_failures;
static int g_checks;

#define CHECK(cond, ...)						\
	do {								\
		g_checks++;						\
		if (!(cond)) {						\
			g_failures++;					\
			printf("  ✗ %s:%d: %s", __func__, __LINE__, #cond);\
			printf("  (" __VA_ARGS__);			\
			printf(")\n");					\
		}							\
	} while (0)

#define CHECK_EQ(a, b)							\
	do {								\
		long long __a = (long long)(a), __b = (long long)(b);	\
		g_checks++;						\
		if (__a != __b) {					\
			g_failures++;					\
			printf("  ✗ %s:%d: %s == %s  (%lld != %lld)\n",	\
			       __func__, __LINE__, #a, #b, __a, __b);	\
		}							\
	} while (0)

#define TEST(name)	printf("· %s\n", name)

/* 响应缓冲按 8 字节对齐：mbedTLS/nghttp2 真实现里这类缓冲会被按字访问，
 * 对齐不当属于「宿主上测不出、设备上偶发」的那类问题，不值得冒。 */
#define ALIGNED_BUF(name) u8 name[KDG_MAX_WIRE_MSG] __attribute__((aligned(8)))

/* ⚠️ 不能写成 `(struct timespec){ 0, ms * 1000000L }`：tv_nsec 必须 < 10^9，
 * 而 1200 ms 就已经是 1.2e9 —— nanosleep 会直接返回 EINVAL，于是「阻塞
 * 1.2 秒」变成「立刻返回」，测试还在跑、却已经什么都没验到。这个坑真的
 * 踩了一次：放弃路径的用例因此一直没走到它该走的分支。 */
static void test_sleep_ms(long ms)
{
	struct timespec ts = { ms / 1000, (ms % 1000) * 1000000L };

	nanosleep(&ts, NULL);
}

/* ── 上游替身 ────────────────────────────────────────────────────────── */

enum up_mode {
	UP_OK = 0,	/* 立刻交付响应 */
	UP_HOLD,	/* 永不交付（考超期取消与调用方放弃） */
	UP_DIE,		/* 交付若干条之后连接级失败 */
	UP_SLOW,	/* 每次 read 先睡 g_read_block_ms */
};

struct kdg_upstream {
	unsigned int id;
};

struct stub_stream {
	struct kdg_h2_stream *st;
	int32_t               id;
	bool                  delivered;	/* 已收到 END_STREAM */
	bool                  closed;		/* 已 on_stream_close */
};

static struct {
	int		 mode;
	int		 open_result;	/* 非 0 时 open 直接失败 */
	u32		 stream_limit;
	long		 read_block_ms;
	unsigned int	 die_after;	/* UP_DIE：交付这么多条之后就死 */
	atomic_int	 opens;
	atomic_int	 submits;
	atomic_int	 resets;
	atomic_int	 delivered;
	atomic_int	 next_sid;
	bool		 dead;
	/* ⚠️ 这个标记是整份测试里最关键的一条断言载体：池归还槽位的前提是
	 * 「协议栈已经彻底忘掉这条流」。若某次 submit 拿到的 st 指针，与一条
	 * **还没 close** 的旧流是同一块内存，就说明槽位在旧流还活着时被复用了 ——
	 * 也就是串台。替身看得见这件事（它持有全部未关闭流的指针），池自己看不见。 */
	bool		 reuse_while_live;
	struct stub_stream streams[256];
	unsigned int	 n_streams;
	pthread_mutex_t	 lock;
} g_stub;

/* 每个用例一个**干净**的池：统计量是累计的，连接身份与 h1 抑制窗口也
 * 会跨用例留痕（那正是它们该有的行为），不重建就会让后一个用例去承担
 * 前一个用例的状态 —— 测出来的失败与被测代码无关。 */
static void stub_reset(void)
{
	kdg_pool_shutdown();
	assert(kdg_pool_init() == 0);

	memset(&g_stub, 0, sizeof(g_stub));
	g_stub.mode = UP_OK;
	g_stub.stream_limit = KDG_UPSTREAM_STREAMS_INIT;
	pthread_mutex_init(&g_stub.lock, NULL);
}

static struct stub_stream *stub_find(int32_t id)
{
	unsigned int i;

	for (i = 0; i < g_stub.n_streams; i++)
		if (g_stub.streams[i].id == id && !g_stub.streams[i].closed)
			return &g_stub.streams[i];
	return NULL;
}

/*
 * 推进一步。**刻意把「收到 END_STREAM」与「流被关闭」分成两次调用**：
 * 真实 nghttp2 在多数情况下把它们放在同一次 mem_recv 里，但两者并不是
 * 同一件事 —— 只要本地一侧还没结束（请求体没发完、或被流控挡住），
 * END_STREAM 到了、流对象却仍然活着。池必须在**后者**才敢交付槽位，
 * 把两件事合成一步的替身会让这条不变量永远测不到（实测：合并时，
 * 「结算不要求 in_flight 已清」这个缺陷注入进去是全绿的）。
 */
static bool stub_step_locked(void)
{
	unsigned int i;

	for (i = 0; i < g_stub.n_streams; i++) {
		struct stub_stream *s = &g_stub.streams[i];

		if (s->delivered && !s->closed) {
			s->st->in_flight = false;	/* on_stream_close */
			s->closed = true;
			return true;
		}
	}

	for (i = 0; i < g_stub.n_streams; i++) {
		struct stub_stream *s = &g_stub.streams[i];
		struct kdg_h2_stream *st = s->st;
		static const u8 payload[] = { 0xAA, 0xBB, 0xCC, 0xDD };

		if (s->closed || s->delivered)
			continue;

		if (st->resp_cap < sizeof(payload)) {
			st->err = -EMSGSIZE;
		} else {
			memcpy(st->resp, payload, sizeof(payload));
			st->resp_len = sizeof(payload);
			st->status = 200;
			st->status_seen = true;
			st->ct_ok = true;
		}
		st->done = true;	/* END_STREAM；in_flight 仍为真 */
		s->delivered = true;
		atomic_fetch_add(&g_stub.delivered, 1);
		return true;
	}
	return false;
}

/* ── 被测代码调用的 upstream 接口（替身实现）────────────────────────── */

int kdg_upstream_open(struct kdg_upstream **out, const struct kdg_doh_cfg *cfg,
		      u32 deadline_ms)
{
	(void)cfg;
	(void)deadline_ms;

	atomic_fetch_add(&g_stub.opens, 1);
	if (g_stub.open_result)
		return g_stub.open_result;

	*out = calloc(1, sizeof(struct kdg_upstream));
	assert(*out);
	(*out)->id = (unsigned int)atomic_load(&g_stub.opens);
	return 0;
}

void kdg_upstream_close(struct kdg_upstream *u)
{
	unsigned int i;

	/*
	 * ⚠️ 这里必须模拟「会话被销毁，它手上所有的流一并消失」。
	 *
	 * 真实现里 `kdg_h2_session_free()` 调 `nghttp2_session_del()`，此后
	 * nghttp2 **不可能**再拿任何旧的 stream_user_data 回调 —— 这正是池在
	 * 连接级失败路径上敢自己把 `st.in_flight` 清掉、敢立刻复用槽位的依据。
	 * 替身若只 free 掉 u 而留着流表不变，就会在槽位被复用时报出「旧流还
	 * 活着」——一个**替身制造的假故障**，而且它只在重连之后的复用发生时
	 * 才出现，表现为 8 次里红 7 次的偶发。
	 * 教训：替身必须模拟真实对象**销毁时的后果**，不能只模拟它的接口。
	 */
	pthread_mutex_lock(&g_stub.lock);
	for (i = 0; i < g_stub.n_streams; i++) {
		struct stub_stream *s = &g_stub.streams[i];

		if (s->closed)
			continue;
		s->st->in_flight = false;
		s->closed = true;
	}
	pthread_mutex_unlock(&g_stub.lock);

	free(u);
}

int kdg_upstream_submit(struct kdg_upstream *u, const u8 *body, size_t len,
			struct kdg_h2_stream *st, int32_t *stream_id)
{
	int32_t id;

	(void)u;
	(void)body;
	(void)len;

	pthread_mutex_lock(&g_stub.lock);
	id = atomic_fetch_add(&g_stub.next_sid, 1) + 1;

	/* 串台检测：这块 st 内存是否还被一条没关闭的旧流持有 */
	for (unsigned int i = 0; i < g_stub.n_streams; i++)
		if (!g_stub.streams[i].closed && g_stub.streams[i].st == st)
			g_stub.reuse_while_live = true;

	if (g_stub.n_streams < ARRAY_SIZE(g_stub.streams))
		g_stub.streams[g_stub.n_streams++] =
			(struct stub_stream){ .st = st, .id = id };
	/* in_flight 在锁内先置：驱动线程可能在 submit 返回之前就开始投递，
	 * 顺序反了会让投递把 in_flight 清掉、随后又被 submit 置回真 ——
	 * 那条流从此永远不会结算（真实现里不存在这个竞态，因为整个协议栈
	 * 只有一个线程在跑，这里是被替身的并发写暴露出来的）。 */
	st->in_flight = true;
	pthread_mutex_unlock(&g_stub.lock);

	*stream_id = id;
	atomic_fetch_add(&g_stub.submits, 1);
	return 0;
}

int kdg_upstream_read(struct kdg_upstream *u, u8 *buf, size_t cap)
{
	bool got;

	(void)u;
	(void)buf;
	(void)cap;

	if (g_stub.read_block_ms > 0)
		test_sleep_ms(g_stub.read_block_ms);

	/*
	 * ⚠️ 这个看似多余的读**是这份替身里最要紧的一行之一**：它模拟真实现
	 * 在阻塞读返回之后仍然要解引用那条连接（`u->tls` / `u->h2`）。
	 * 没有它，替身就变成「读完就什么都不碰」——于是「调用方趁驱动线程
	 * 阻塞在读里的时候把连接 free 掉」这类 use-after-free 在宿主上
	 * 永远看不见（真机上则是随机 panic）。替身不碰这个对象，就没有资格
	 * 声称测过这个对象。
	 */
	if (!u || !u->id)
		return -EIO;

	pthread_mutex_lock(&g_stub.lock);

	if (g_stub.mode == UP_DIE &&
	    (unsigned int)atomic_load(&g_stub.delivered) >= g_stub.die_after) {
		g_stub.dead = true;
		pthread_mutex_unlock(&g_stub.lock);
		return -EIO;
	}

	if (g_stub.mode == UP_HOLD) {
		pthread_mutex_unlock(&g_stub.lock);
		return -EAGAIN;
	}

	got = stub_step_locked();
	pthread_mutex_unlock(&g_stub.lock);

	/* 返回值只表达「这次读有没有进展」，池不看内容（内容由回调写进流）。 */
	return got ? 64 : -EAGAIN;
}

int kdg_upstream_flush(struct kdg_upstream *u)
{
	(void)u;
	return 0;
}

void kdg_upstream_reset_stream(struct kdg_upstream *u, int32_t stream_id)
{
	struct stub_stream *s;

	(void)u;

	pthread_mutex_lock(&g_stub.lock);
	s = stub_find(stream_id);
	if (s) {
		/* 真实现里 RST 之后 nghttp2 会调 on_stream_close —— 替身照做。
		 * **不碰 st->err**：调用方（池）已经写好了取消原因，替身再去写
		 * 就把那个原因冲掉了，测试也就失去了它要验的东西。 */
		s->st->done = true;
		s->st->in_flight = false;
		s->closed = true;
	}
	pthread_mutex_unlock(&g_stub.lock);
	atomic_fetch_add(&g_stub.resets, 1);
}

bool kdg_upstream_dead(const struct kdg_upstream *u)
{
	(void)u;
	return g_stub.dead;
}

int kdg_upstream_err(const struct kdg_upstream *u)
{
	(void)u;
	return -ECONNRESET;
}

u32 kdg_upstream_stream_limit(const struct kdg_upstream *u)
{
	(void)u;
	return g_stub.stream_limit;
}

/* ── 测试脚手架 ──────────────────────────────────────────────────────── */

static long test_now_ms(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (long)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

static void cfg_init(struct kdg_doh_cfg *cfg, u32 deadline_ms)
{
	memset(cfg, 0, sizeof(*cfg));
	snprintf(cfg->hostname, sizeof(cfg->hostname), "doh.test");
	snprintf(cfg->path, sizeof(cfg->path), "/dns-query");
	cfg->ip_be = 0x01020304;
	cfg->port_be = 0x01BB;	/* 443 */
	cfg->deadline_ms = deadline_ms;
}

struct worker_arg {
	const struct kdg_doh_cfg *cfg;
	unsigned int	n;
	int		results[4];
	size_t		lens[4];
};

/* 屏障：让所有线程**真的同时**进池，而不是被 pthread_create 的顺序排成一队。
 * 没有它，「并发」这个前提就不成立，测出来的是顺序执行。 */
static pthread_barrier_t g_barrier;
static bool	       g_use_barrier;

/* 进度看门狗：并发测试最坏的失败模式是「挂住」，而挂住的进程什么都
 * 不告诉你 —— 外层 timeout 一杀，连接口印都留不下。这里让一个看门狗
 * 线程在超时后报出「启动了几个、完成了几个」，把挂死变成一个可复现的
 * 坐标。它只在测试进程里活着，不影响被测代码。 */
static atomic_int g_workers_started;
static atomic_int g_workers_done;

static void *watchdog_thread(void *p)
{
	int secs = *(int *)p;

	sleep((unsigned int)secs);
	fprintf(stderr, "!! 看门狗：%d 秒未结束（工作线程 启动=%d 完成=%d）\n",
		secs, atomic_load(&g_workers_started),
		atomic_load(&g_workers_done));
	_exit(9);
}

static void *worker(void *p)
{
	struct worker_arg *a = p;
	unsigned int i;

	atomic_fetch_add(&g_workers_started, 1);
	if (g_use_barrier)
		pthread_barrier_wait(&g_barrier);

	for (i = 0; i < a->n && i < ARRAY_SIZE(a->results); i++) {
		/* 每个查询用**独立**缓冲：被测的正是「池把响应放进调用方
		 * 各自的缓冲」，共用缓冲会让串台与不串台看起来一模一样。 */
		u8 buf[KDG_MAX_WIRE_MSG];
		size_t len = sizeof(buf);

		memset(buf, 0, sizeof(buf));
		a->results[i] = kdg_pool_query(a->cfg, buf, 12, buf, &len);
		a->lens[i] = (len == 4 && buf[0] == 0xAA) ? len : 0;
	}
	atomic_fetch_add(&g_workers_done, 1);
	return NULL;
}

static void barrier_start(pthread_t *th, struct worker_arg *args, unsigned int n)
{
	unsigned int i;

	g_use_barrier = true;
	/* 计数按**本次**批量归零：它是跨用例累加的，不归零的话断言会拿
	 * 「历史上所有用例的完成数」去比「本用例的线程数」。 */
	atomic_store(&g_workers_started, 0);
	atomic_store(&g_workers_done, 0);
	assert(pthread_barrier_init(&g_barrier, NULL, n) == 0);
	for (i = 0; i < n; i++)
		assert(pthread_create(&th[i], NULL, worker, &args[i]) == 0);
}

static void barrier_join(pthread_t *th, unsigned int n)
{
	unsigned int i;

	for (i = 0; i < n; i++)
		assert(pthread_join(th[i], NULL) == 0);
	pthread_barrier_destroy(&g_barrier);
	g_use_barrier = false;
}

static void check_clean(const char *where)
{
	struct kdg_pool_stats s;

	kdg_pool_get_stats(&s);
	CHECK_EQ(s.slots_used, 0);
	CHECK_EQ(s.inflight, 0);
	CHECK_EQ(s.queued, 0);
	CHECK_EQ(host_warn_count, 0);
	/* 最要紧的一条：没有任何槽位在「协议栈还持有它」的时候被复用 */
	CHECK_EQ(g_stub.reuse_while_live, 0);
	if (host_warn_count)
		printf("  （%s：出现 %lu 次 WARN_ON_ONCE）\n", where, host_warn_count);
}

/* ── 用例 ────────────────────────────────────────────────────────────── */

static void test_single_roundtrip(void)
{
	struct kdg_doh_cfg cfg;
	ALIGNED_BUF(buf);
	struct kdg_pool_stats s;
	size_t len = sizeof(buf);

	TEST("单次往返");
	stub_reset();
	cfg_init(&cfg, 3000);

	CHECK_EQ(kdg_pool_query(&cfg, buf, 12, buf, &len), 0);
	CHECK_EQ(len, 4);
	CHECK_EQ(buf[0], 0xAA);
	kdg_pool_get_stats(&s);
	CHECK_EQ(s.connects, 1);
	CHECK_EQ(s.reused, 0);	/* 第一条连接是新建的，不算复用 */
	CHECK_EQ(s.queries, 1);
	check_clean("单次往返");
}

/* 池化的全部意义所在：N 条并发查询共用**一条**连接。
 * 修复前（每查询一条连接）这里的 connects 会等于 N。 */
static void test_reuse_many_sequential(void)
{
	struct kdg_doh_cfg cfg;
	struct kdg_pool_stats s;
	unsigned int i;

	TEST("顺序 200 次查询只建一条连接");
	stub_reset();
	cfg_init(&cfg, 3000);

	for (i = 0; i < 200; i++) {
		ALIGNED_BUF(buf);
		size_t len = sizeof(buf);

		CHECK_EQ(kdg_pool_query(&cfg, buf, 12, buf, &len), 0);
	}
	kdg_pool_get_stats(&s);
	CHECK_EQ(s.connects, 1);
	CHECK_EQ(s.queries, 200);
	CHECK_EQ(s.reused, 199);
	check_clean("顺序复用");
}

static void test_concurrent(void)
{
	enum { N = 64 };
	struct kdg_doh_cfg cfg;
	struct worker_arg args[N];
	struct kdg_pool_stats s;
	pthread_t th[N];
	unsigned int i;

	TEST("并发 64：一条连接、64 条流、各自拿到自己的响应");
	stub_reset();
	cfg_init(&cfg, 5000);

	for (i = 0; i < N; i++)
		args[i] = (struct worker_arg){ .cfg = &cfg, .n = 1 };
	barrier_start(th, args, N);
	barrier_join(th, N);

	for (i = 0; i < N; i++) {
		CHECK_EQ(args[i].results[0], 0);
		CHECK_EQ(args[i].lens[0], 4);
	}

	kdg_pool_get_stats(&s);
	CHECK_EQ(s.connects, 1);	/* 这是要证的那件事 */
	CHECK_EQ(s.queries, N);
	CHECK(s.stream_limit >= KDG_UPSTREAM_STREAMS_INIT,
	      "stream_limit=%u", s.stream_limit);
	check_clean("并发复用");
}

static void test_deadline_cancel(void)
{
	struct kdg_doh_cfg cfg;
	ALIGNED_BUF(buf);
	struct kdg_pool_stats s;
	size_t len = sizeof(buf);
	long t0;
	int ret;

	TEST("上游不响应：池按 deadline 自己取消，而不是让调用方干等");
	stub_reset();
	g_stub.mode = UP_HOLD;
	cfg_init(&cfg, 400);

	t0 = test_now_ms();
	ret = kdg_pool_query(&cfg, buf, 12, buf, &len);
	CHECK_EQ(ret, -ETIMEDOUT);

	/*
	 * **耗时是这条用例真正要验的东西**，比返回值有信息量得多：
	 * 调用方自己的等待上限是 deadline + 2000 ms，「返回 -ETIMEDOUT」在
	 * 两种情况下都成立 —— 池取消得及时，或者调用方自己等崩了。只有
	 * 耗时能把它们分开：池在 deadline 附近取消（+ 一个滴答），
	 * 而等崩了要到 deadline + 余量。少了这条断言，「驱动线程忘了唤醒
	 * 调用方」这种缺陷注入进去仍然全绿。
	 */
	CHECK(test_now_ms() - t0 < 1200, "耗时 %ld ms（应当≈400ms，而不是 2400ms）",
	      test_now_ms() - t0);

	kdg_pool_get_stats(&s);
	CHECK(s.upstream_timeouts >= 1, "upstream_timeouts=%llu",
	      (unsigned long long)s.upstream_timeouts);
	CHECK(s.stream_resets_sent >= 1, "resets=%llu",
	      (unsigned long long)s.stream_resets_sent);
	/* 关键：取消必须是**池**做的。若它是靠调用方自己等到上限才返回，
	 * 那这条路径就退化成「deadline 只是个建议」，而 wait_timeouts 会 >0。 */
	CHECK_EQ(s.wait_timeouts, 0);
	/* 关键：调用方超时之后槽位必须回到池里，不能靠「反正进程要退出了」 */
	check_clean("超期取消");
}

static void test_wait_timeout_abandon(void)
{
	struct kdg_doh_cfg cfg;
	ALIGNED_BUF(buf);
	struct kdg_pool_stats s;
	size_t len = sizeof(buf);
	int ret;

	TEST("调用方放弃：槽位交由驱动线程收尾（不得泄漏、不得双重释放）");
	stub_reset();
	/* read 阻塞得比「deadline + 余量」还久 —— 驱动线程来不及扫超期，
	 * 调用方会先撞上自己的等待上限。这是唯一能把放弃路径走出来的办法，
	 * 也正是它要防的那种「池实现出错」的场景。 */
	g_stub.mode = UP_HOLD;
	g_stub.read_block_ms = 2600;	/* > deadline(200) + 余量(2000) */
	cfg_init(&cfg, 200);

	ret = kdg_pool_query(&cfg, buf, 12, buf, &len);
	CHECK_EQ(ret, -ETIMEDOUT);

	kdg_pool_get_stats(&s);
	CHECK_EQ(s.wait_timeouts, 1);

	/* 驱动线程应当在不晚于下一个滴答把槽位收掉 */
	{
		int i;

		for (i = 0; i < 200; i++) {
			test_sleep_ms(50);
			kdg_pool_get_stats(&s);
			if (s.slots_used == 0)
				break;
		}
	}
	check_clean("调用方放弃");
}

static void test_conn_failure_fails_all(void)
{
	enum { N = 16 };
	struct kdg_doh_cfg cfg;
	struct worker_arg args[N];
	struct kdg_pool_stats s;
	pthread_t th[N];
	unsigned int i;

	TEST("连接级失败：在途流全部失败，不留下吊死的等待者");
	stub_reset();
	g_stub.mode = UP_DIE;
	g_stub.die_after = 2;	/* 交付 2 条之后就断 */
	g_stub.stream_limit = 8;
	cfg_init(&cfg, 3000);

	for (i = 0; i < N; i++)
		args[i] = (struct worker_arg){ .cfg = &cfg, .n = 1 };
	barrier_start(th, args, N);
	barrier_join(th, N);

	for (i = 0; i < N; i++)
		CHECK(args[i].results[0] == 0 || args[i].results[0] == -EIO,
		      "结果=%d", args[i].results[0]);

	kdg_pool_get_stats(&s);
	CHECK(s.conn_errors >= 1, "conn_errors=%llu",
	      (unsigned long long)s.conn_errors);
	check_clean("连接级失败");
}

static void test_h1_fallback_suppressed(void)
{
	struct kdg_doh_cfg cfg;
	struct kdg_pool_stats s;
	unsigned int i;

	TEST("对端不支持 h2：回落 H1，且不每次查询都白建一次连接");
	stub_reset();
	g_stub.open_result = -EPROTONOSUPPORT;
	cfg_init(&cfg, 1000);

	for (i = 0; i < 5; i++) {
		ALIGNED_BUF(buf);
		size_t len = sizeof(buf);

		CHECK_EQ(kdg_pool_query(&cfg, buf, 12, buf, &len),
			 -EPROTONOSUPPORT);
	}
	kdg_pool_get_stats(&s);
	CHECK_EQ(s.connects, 0);
	CHECK_EQ(s.h1_fallbacks, 5);
	CHECK_EQ(atomic_load(&g_stub.opens), 1);	/* 只探了一次 */
	check_clean("H1 回落");
}

static void test_slot_exhaustion(void)
{
	enum { N = 140 };
	struct kdg_doh_cfg cfg;
	struct worker_arg args[N];
	struct kdg_pool_stats s;
	pthread_t th[N];
	unsigned int i;

	TEST("槽位打满：超出的明确拒绝，不排队、不静默吞掉");
	stub_reset();
	g_stub.mode = UP_HOLD;
	g_stub.stream_limit = 4;
	cfg_init(&cfg, 800);

	for (i = 0; i < N; i++)
		args[i] = (struct worker_arg){ .cfg = &cfg, .n = 1 };
	barrier_start(th, args, N);
	barrier_join(th, N);

	kdg_pool_get_stats(&s);
	CHECK_EQ(s.slots_max, 128);
	CHECK(s.rejected >= 1, "rejected=%llu",
	      (unsigned long long)s.rejected);
	{
		unsigned int n_eagain = 0, n_timeout = 0, n_other = 0;

		for (i = 0; i < N; i++) {
			if (args[i].results[0] == -EAGAIN)
				n_eagain++;
			else if (args[i].results[0] == -ETIMEDOUT)
				n_timeout++;
			else
				n_other++;
		}
		CHECK_EQ(n_other, 0);
		CHECK_EQ(n_eagain, (int)s.rejected);
		CHECK(n_timeout >= 1, "timeout=%u", n_timeout);
	}
	check_clean("槽位打满");
}

/*
 * 上游身份变化**与驱动线程正在读**并发时的行为。
 *
 * 这是「拆连接这件事只能由驱动线程做」那条约束的判据：调用方若自己去
 * `kdg_upstream_close()`，就是在驱动线程脚下的那次阻塞读里把它握着的
 * 连接对象 free 掉 —— 真机上表现为随机 panic，宿主上由 ASan 在
 * `kindg_upstream_read` 解引用已释放对象时当场报出来。
 */
static void test_identity_change_during_read(void)
{
	struct kdg_doh_cfg cfg;
	struct worker_arg a;
	pthread_t th;
	struct kdg_pool_stats s;
	ALIGNED_BUF(buf);
	size_t len = sizeof(buf);

	TEST("换上游时驱动线程正卡在读里：不得拆它脚下的连接");
	stub_reset();
	g_stub.mode = UP_OK;
	g_stub.read_block_ms = 500;	/* 让驱动线程有一次足够长的阻塞读 */
	cfg_init(&cfg, 4000);

	/* 线程 A：把驱动线程推进「读里」，并保持在那边 */
	a = (struct worker_arg){ .cfg = &cfg, .n = 1 };
	g_use_barrier = false;
	assert(pthread_create(&th, NULL, worker, &a) == 0);

	/* 等驱动线程真的进了那次读 */
	test_sleep_ms(200);

	/* 主线程：换上游并发一条新查询 —— 旧实现会在这里把连接拆掉 */
	snprintf(cfg.hostname, sizeof(cfg.hostname), "other.test");
	CHECK_EQ(kdg_pool_query(&cfg, buf, 12, buf, &len), 0);

	assert(pthread_join(th, NULL) == 0);
	/*
	 * A 的结果允许是 -ESTALE：换上游时它还在旧连接上飞，按方案 §8
	 * 「拒绝跨上游身份跳转」，那个响应不能回给调用方。**这条用例要验的
	 * 从来不是 A 的结果**，而是「拆连接没有踩到驱动线程正握着的对象」——
	 * 那由 ASan 判、并在该行当场终止进程；以及连接确实被重建了。
	 * 把 A 的结果写成「必须 0」是错的期望，会把一次正确的保守行为
	 * 报成失败。
	 */
	CHECK(a.results[0] == 0 || a.results[0] == -ESTALE,
	      "A 的结果=%d", a.results[0]);

	kdg_pool_get_stats(&s);
	CHECK_EQ(s.connects, 2);	/* 旧连接被拆、新连接建起来 */
	check_clean("换上游与读并发");
}

static void test_identity_change(void)
{
	struct kdg_doh_cfg cfg;
	struct kdg_pool_stats s;

	TEST("上游身份变化：重建连接");
	stub_reset();
	cfg_init(&cfg, 2000);

	{
		ALIGNED_BUF(buf);
		size_t len = sizeof(buf);

		CHECK_EQ(kdg_pool_query(&cfg, buf, 12, buf, &len), 0);
	}

	snprintf(cfg.hostname, sizeof(cfg.hostname), "other.test");
	{
		ALIGNED_BUF(buf);
		size_t len = sizeof(buf);

		CHECK_EQ(kdg_pool_query(&cfg, buf, 12, buf, &len), 0);
	}

	kdg_pool_get_stats(&s);
	CHECK_EQ(s.connects, 2);
	CHECK_EQ(atomic_load(&g_stub.opens), 2);
	check_clean("身份变化");
}

static void test_idle_close(void)
{
	struct kdg_doh_cfg cfg;
	struct kdg_pool_stats s;
	int i;

	TEST("空闲关闭：连接被主动放掉，之后再来查询会重建");
	stub_reset();
	cfg_init(&cfg, 2000);

	{
		ALIGNED_BUF(buf);
		size_t len = sizeof(buf);

		CHECK_EQ(kdg_pool_query(&cfg, buf, 12, buf, &len), 0);
	}

	for (i = 0; i < 40; i++) {
		test_sleep_ms(50);
		kdg_pool_get_stats(&s);
		if (s.idle_closes >= 1)
			break;
	}
	kdg_pool_get_stats(&s);
	CHECK_EQ(s.idle_closes, 1);
	CHECK_EQ(s.connected, 0);

	{
		ALIGNED_BUF(buf);
		size_t len = sizeof(buf);

		CHECK_EQ(kdg_pool_query(&cfg, buf, 12, buf, &len), 0);
	}
	kdg_pool_get_stats(&s);
	CHECK_EQ(s.connects, 2);
	check_clean("空闲关闭");
}

static void test_shutdown_with_waiters(void)
{
	enum { N = 8 };
	struct kdg_doh_cfg cfg;
	struct worker_arg args[N];
	struct kdg_pool_stats s;
	pthread_t th[N];
	unsigned int i;

	TEST("卸载时仍有人等：全部被唤醒，不留吊死的调用方");
	stub_reset();
	g_stub.mode = UP_HOLD;
	cfg_init(&cfg, 5000);

	for (i = 0; i < N; i++)
		args[i] = (struct worker_arg){ .cfg = &cfg, .n = 1 };
	barrier_start(th, args, N);
	{
		test_sleep_ms(300);
	}
	kdg_pool_get_stats(&s);
	CHECK(s.inflight + s.queued >= 1, "inflight=%u queued=%u",
	      s.inflight, s.queued);

	kdg_pool_shutdown();

	/* shutdown 返回 ⇒ 所有调用方都已离场（active==0 那道理所当然的推论）。
	 * 这条断言把「卸载不许释放别人还在写的槽位表」变成可判定的。 */
	{
		int i;

		for (i = 0; i < 200 && atomic_load(&g_workers_done) < N; i++)
			test_sleep_ms(10);
	}
	CHECK_EQ(atomic_load(&g_workers_done), N);

	barrier_join(th, N);
	for (i = 0; i < N; i++)
		CHECK_EQ(args[i].results[0], -ESHUTDOWN);

	/* 卸载之后进来的查询必须明确被拒，而不是去碰已经放掉的槽位表 */
	{
		ALIGNED_BUF(buf);
		size_t len = sizeof(buf);

		CHECK_EQ(kdg_pool_query(&cfg, buf, 12, buf, &len), -ESHUTDOWN);
	}
}

int main(void)
{
	/* 无缓冲：并发测试一旦挂死会被外层 timeout 杀掉，而块缓冲会连
	 * 「跑到哪一步挂的」一起吞掉 —— 那正是最需要的信息。 */
	setvbuf(stdout, NULL, _IONBF, 0);
	{
		static int wd_secs = 45;
		pthread_t wd;

		atomic_init(&g_workers_started, 0);
		atomic_init(&g_workers_done, 0);
		assert(pthread_create(&wd, NULL, watchdog_thread, &wd_secs) == 0);
		pthread_detach(wd);
	}

	printf("=== 连接池宿主测试（ASan/UBSan + pthread）===\n");

	test_single_roundtrip();
	test_reuse_many_sequential();
	test_concurrent();
	test_deadline_cancel();
	test_wait_timeout_abandon();
	test_conn_failure_fails_all();
	test_h1_fallback_suppressed();
	test_slot_exhaustion();
	test_identity_change_during_read();
	test_identity_change();
	test_idle_close();
	test_shutdown_with_waiters();

	printf("=== %d 项检查，%d 项失败 ===\n", g_checks, g_failures);
	return g_failures ? 1 : 0;
}
