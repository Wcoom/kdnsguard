/* SPDX-License-Identifier: GPL-2.0 */
/*
 * kdg_tls.c —— 内核态 TLS 客户端会话实现。设计与约束见 kdg_tls.h。
 */
#define pr_fmt(fmt)	KBUILD_MODNAME ": " fmt

#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/mutex.h>
#include <linux/string.h>
#include <linux/errno.h>

#include "kdg.h"
#include "kdg_tls.h"
/* mbedtls_debug_set_threshold 在 debug.h，ssl.h 不转发它。 */
#include <mbedtls/debug.h>
#include <psa/crypto.h>

/* ── 模块级共享状态 ──────────────────────────────────────────────────── */

/*
 * ⚠️ **两把锁，不是一个。** 各自保护一件独立的共享状态：
 *
 *  - `kdg_tls_mutex`：信任锚链，以及「一次握手与一次信任锚加载不得并行」。
 *    它在**整段握手期间**被持有（见 kdg_doh.c / kdg_upstream.c）。
 *  - `kdg_rng_mutex`：CTR_DRBG。只在一次取随机数期间被持有。
 *
 * 为什么不合成一把：`mbedtls_ssl_handshake()` 内部会调 `f_rng`，也就是
 * `kdg_tls_rng()`。如果它取的是调用方**已经持有**的那把锁，第一次握手就会
 * 自死锁 —— 症状是「第一次查询永久挂住、日志里什么都没有」，从现象完全
 * 看不出是锁的粒度问题。两把锁之间不存在反向获取（持 rng 锁时绝不进 SSL
 * 层），因此不会成环。
 */
static DEFINE_MUTEX(kdg_tls_mutex);
static DEFINE_MUTEX(kdg_rng_mutex);

static mbedtls_entropy_context	kdg_entropy;
static mbedtls_ctr_drbg_context	kdg_ctr_drbg;
static mbedtls_x509_crt		kdg_ca;
static bool			kdg_ca_created;
static bool			kdg_tls_ready;
static unsigned int		kdg_ca_count;

void kdg_tls_lock(void)
{
	mutex_lock(&kdg_tls_mutex);
}

void kdg_tls_unlock(void)
{
	mutex_unlock(&kdg_tls_mutex);
}

/*
 * 取随机数的包装。
 *
 * 为什么需要它（这是 P6 之后新增的一层）：旧的实现靠 `kdg_tls_lock()` 把
 * **整条查询**串行化，副作用是 DRBG 天然不会被并发访问。而持久连接池让
 * 连接长期存在、多个连接可能同时发记录，那把粗锁就不能再罩住整条查询了
 * （罩住就等于放弃池化的并发性）。于是把锁的粒度收到这里 —— 只罩住
 * DRBG 本身，正是 kdg_tls.h 里早就写下的话：「P2 引入请求队列后，锁的粒度
 * 可以收细到 RNG 与共享 CA，但语义不变」。
 *
 * MBEDTLS_THREADING_C 在内核态里是关闭的（不适合让库自己加锁），所以这层
 * 必须由我们提供。成本是一次未被争用的互斥锁加锁/解锁，与一次 SHA-256
 * 相比可以忽略。
 */
static int kdg_tls_rng(void *ctx, unsigned char *out, size_t len)
{
	int ret;

	/* ctx 是本模块内部的 DRBG 句柄；传 NULL 时退回唯一那个全局实例。
	 * ⚠️ 不能让 NULL 落到 mbedtls_ctr_drbg_random 里 —— 那是一次空指针
	 * 解引用，在设备上表现为 kdg_pool 线程 panic 重启（2026-10-05 真机
	 * 取证的正是这条：kdg_tls_rng_export → mbedtls_ctr_drbg_random）。 */
	mutex_lock(&kdg_rng_mutex);
	ret = mbedtls_ctr_drbg_random(ctx ? ctx : &kdg_ctr_drbg, out, len);
	mutex_unlock(&kdg_rng_mutex);
	return ret;
}

/* ── BIO 回调：把 mbedTLS 的 I/O 接到内核 socket 上 ─────────────────── */

/*
 * 返回值的约定（mbedTLS 3.x）：
 *   正数 = 实际收发的字节数
 *   0    = 对 recv 而言表示「暂时无数据」，mbedTLS 会当作 WANT_READ 重试；
 *          对 send 而言是错误（我们不可能「发出 0 字节」却成功）
 *   负数 = MBEDTLS_ERR_NET_* 之一
 *
 * ⚠️ 这里**不能**返 0 表示连接关闭：那会被 mbedTLS 理解为「还没数据、等会儿再试」，
 * 于是一个已经 FIN 的对端会让握手空转到超时，而不是立刻报错。
 * 读到 0 字节必须翻译成 MBEDTLS_ERR_NET_CONN_RESET。
 *
 * 另一处同样容易被忽略的约定：**超时不是错误，是 WANT_READ**。持久连接上
 * 接收超时被用作「扫描滴答」（见 kdg_pool.c 的 KDG_POOL_TICK_MS），一个
 * 250 ms 的滴答如果报成 RECV_FAILED，就会把一条完全健康的连接当成坏了拆掉。
 */
static int kdg_tls_bio_send(void *ctx, const unsigned char *buf, size_t len)
{
	struct kdg_tls *t = ctx;
	int ret;

	ret = kdg_sock_send_all(t->sock, buf, len);
	if (ret) {
		t->last_net_errno = ret;
		return MBEDTLS_ERR_NET_SEND_FAILED;
	}
	if (len == 0)
		return MBEDTLS_ERR_NET_SEND_FAILED;
	return (int)len;
}

static int kdg_tls_bio_recv(void *ctx, unsigned char *buf, size_t len)
{
	struct kdg_tls *t = ctx;
	int ret;

	ret = kdg_sock_recv_some(t->sock, buf, len);
	if (ret < 0) {
		t->last_net_errno = ret;
		if (ret == -ETIMEDOUT)
			return MBEDTLS_ERR_SSL_WANT_READ;
		return MBEDTLS_ERR_NET_RECV_FAILED;
	}
	if (ret == 0) {
		t->last_net_errno = -ECONNRESET;
		return MBEDTLS_ERR_NET_CONN_RESET;
	}
	return ret;
}

/* ── 模块级生命周期 ──────────────────────────────────────────────────── */

int kdg_tls_global_init(void)
{
	static const char pers[] = "kdnsguard-tls";
	int ret;

	mbedtls_entropy_init(&kdg_entropy);
	mbedtls_ctr_drbg_init(&kdg_ctr_drbg);
	mbedtls_x509_crt_init(&kdg_ca);
	kdg_ca_created = true;

	/* 熵源是内核 CRNG（见 kdg_mbedtls.c 的 mbedtls_hardware_poll）。 */
	ret = mbedtls_ctr_drbg_seed(&kdg_ctr_drbg, mbedtls_entropy_func,
				    &kdg_entropy,
				    (const unsigned char *)pers,
				    sizeof(pers) - 1);
	if (ret) {
		pr_err("CTR_DRBG 播种失败: %s (-0x%04x)\n",
		       kdg_tls_strerror(ret), -ret);
		mbedtls_x509_crt_free(&kdg_ca);
		mbedtls_ctr_drbg_free(&kdg_ctr_drbg);
		mbedtls_entropy_free(&kdg_entropy);
		kdg_ca_created = false;
		return -EIO;
	}

	kdg_tls_ready = true;
	pr_info("TLS 子系统就绪（CTR_DRBG 已播种，信任锚 %u 张）\n",
		kdg_tls_ca_count());
	return 0;
}

void kdg_tls_global_exit(void)
{
	if (!kdg_ca_created)
		return;

	mbedtls_x509_crt_free(&kdg_ca);
	mbedtls_ctr_drbg_free(&kdg_ctr_drbg);
	mbedtls_entropy_free(&kdg_entropy);
	kdg_ca_created = false;
	kdg_tls_ready = false;
	WRITE_ONCE(kdg_ca_count, 0);
}

/* ── 信任锚 ──────────────────────────────────────────────────────────── */

static unsigned int kdg_tls_ca_count_locked(void)
{
	unsigned int n = 0;
	const mbedtls_x509_crt *c;

	for (c = &kdg_ca; c != NULL; c = c->next) {
		if (c->raw.len > 0)
			n++;
	}
	return n;
}

static void kdg_tls_clear_ca_locked(void);

int kdg_tls_add_ca(const u8 *data, size_t len)
{
	unsigned int before, after;
	u8 *buf;
	int ret;

	if (!data || len == 0)
		return -EINVAL;
	if (!kdg_ca_created)
		return -EAGAIN;

	/*
	 * ⚠️ 必须补 NUL 并补进长度。
	 *
	 * mbedTLS 判定 PEM 的前提是**缓冲区最后一个字节为 '\0'**：
	 *   x509_crt.c: `buf[buflen - 1] == '\0' && strstr(buf, "-----BEGIN ...")`
	 *   pem.c:      `strstr()` 定位首尾标记
	 * 否则它按 DER 解析。而 netlink 属性载荷是按长度传递的**非 NUL 结尾
	 * 二进制**，直接传进去会被当成 DER → MBEDTLS_ERR_X509_INVALID_FORMAT。
	 *
	 * 长度传 len + 1（而不是 len）：要让 buf[buflen-1] 恰好是那个 NUL。
	 */
	buf = kmalloc(len + 1, GFP_KERNEL);
	if (!buf)
		return -ENOMEM;
	memcpy(buf, data, len);
	buf[len] = '\0';

	/* mbedtls_x509_crt_parse 会把 PEM 里**所有**证书追加进链，返回 0
	 * 表示全部成功；返回正数表示有 N 张解析失败但仍追加了其余部分 ——
	 * 后者必须当成失败处理：带着残缺的信任锚去握手，等于把安全性
	 * 建立在「恰好没被解析到的那张不是关键」这个没有根据的假设上。 */
	kdg_tls_lock();
	before = kdg_tls_ca_count_locked();
	ret = mbedtls_x509_crt_parse(&kdg_ca, buf, len + 1);
	after = kdg_tls_ca_count_locked();
	kfree(buf);

	if (ret != 0) {
		pr_err("信任锚解析有失败项（%d 张），拒绝本次加载\n",
		       ret);
		/* 已追加的部分无法单张摘除，只能整体作废，避免留下未知状态。 */
		kdg_tls_clear_ca_locked();
		kdg_tls_unlock();
		return -EINVAL;
	}
	kdg_tls_unlock();
	if (after == before)
		return -EINVAL;
	WRITE_ONCE(kdg_ca_count, after);
	return (int)(after - before);
}

unsigned int kdg_tls_ca_count(void)
{
	return READ_ONCE(kdg_ca_count);
}

/*
 * 清空信任锚。**调用方必须已持有 kdg_tls_mutex** ——
 * kdg_tls_add_ca() 的失败路径就是这么调它的，而在那里再取一次锁会自死锁。
 * 名字里的 _locked 就是这条约定本身；对外的 kdg_tls_clear_ca() 是薄包装。
 */
static void kdg_tls_clear_ca_locked(void)
{
	if (!kdg_ca_created)
		return;

	mbedtls_x509_crt_free(&kdg_ca);
	mbedtls_x509_crt_init(&kdg_ca);
	WRITE_ONCE(kdg_ca_count, 0);
}

/*
 * 给 QUIC/TLS1.3 引擎的随机数入口。
 *
 * ⚠️ **不要把它当成「带上下文的回调」**：本模块只有一个 DRBG，调用方传进来
 * 的 ctx 没有任何意义。第一版原样转手给 mbedtls_ctr_drbg_random，而
 * kdg_h3_init 传的是 NULL —— 真机上每次 H3 建连都会在 kdg_pool 线程里空指针
 * 解引用（minidump: lr = kdg_tls_rng_export+0x48 → mbedtls_ctr_drbg_random）。
 * 现在固定使用全局实例，这个类别的问题从构造上消失。
 */
int kdg_tls_rng_export(void *ctx, unsigned char *out, size_t len)
{
	(void)ctx;
	return kdg_tls_rng(&kdg_ctr_drbg, out, len);
}

const struct mbedtls_x509_crt *kdg_tls_ca_chain(void)
{
	return kdg_ca_count ? &kdg_ca : NULL;
}

void kdg_tls_clear_ca(void)
{
	if (!kdg_ca_created)
		return;

	kdg_tls_lock();
	kdg_tls_clear_ca_locked();
	kdg_tls_unlock();
}

/*
 * mbedTLS 调试回调。仅在 kdg_debug=1 时挂上。
 *
 * mbedTLS 的调试文本会包含握手消息摘要，但不含完整 URI 或查询域名，
 * 且默认关闭 —— 符合方案 §14.1 的输出纪律。
 */
static void kdg_tls_debug(void *ctx, int level, const char *file, int line,
			  const char *str)
{
	(void)ctx;
	pr_info("mbedtls[%d] %s:%d: %s", level, file, line, str);
}

/* ── 会话 ────────────────────────────────────────────────────────────── */

/*
 * ALPN 列表。**h2 在前** —— 列表有序，服务端按自己的偏好从中挑。
 *
 * 早先刻意只提供 http/1.1：那时 H2 客户端还没移植，宣告 h2 会让服务端选中
 * 它、而我们构造不出合法的 HTTP/2 帧，得到的是一条「看似连上、实则不可用」
 * 的连接。现在 nghttp2 已编入模块，可以如实宣告。
 * 方案 §6.3 说 H2 是主线目标、§6.4 说 H1 是兼容路径，两者并存，
 * 由协商结果决定实际走哪条（见 kdg_doh.c 的传输选择）。
 *
 * mbedTLS 只保存指针，故必须是静态生存期。
 */
/* 类型必须是 `const char *[]`：mbedtls_ssl_conf_alpn_protocols() 的形参是
 * `const char **`，写成 `const char *const[]` 会因丢弃顶层 const 而编译失败。 */
static const char *kdg_alpn_protos[] = {
	"h2",
	"http/1.1",
	NULL,
};

int kdg_tls_session_open(struct kdg_tls *t, struct kdg_sock *sock,
			 const char *hostname)
{
	int ret;

	if (!t || !sock || !hostname)
		return -EINVAL;
	if (!kdg_tls_ready)
		return -EAGAIN;

	memset(t, 0, sizeof(*t));
	t->sock = sock;

	mbedtls_ssl_init(&t->ssl);
	mbedtls_ssl_config_init(&t->conf);

	ret = mbedtls_ssl_config_defaults(&t->conf,
					  MBEDTLS_SSL_IS_CLIENT,
					  MBEDTLS_SSL_TRANSPORT_STREAM,
					  MBEDTLS_SSL_PRESET_DEFAULT);
	if (ret) {
		pr_err("ssl_config_defaults 失败: %s\n", kdg_tls_strerror(ret));
		goto fail;
	}

	/* 证书验证绝不关闭（方案 §6.2 的硬性要求）。 */
	mbedtls_ssl_conf_authmode(&t->conf, MBEDTLS_SSL_VERIFY_REQUIRED);

	/* TLS 1.3 优先，保留 TLS 1.2 作为互操作路径（方案 §6.2）。
	 * 曾一度被迫限制到 1.2，根因是 shim 里 UINT_MAX 写成 (~0U) 导致
	 * mbedtls_mpi_bitlen() 错误、P-256 全链路失败；已修复，见
	 * third_party/mbedtls-kernel/shim/_kdg_common.h 的详细记录。 */
	mbedtls_ssl_conf_min_tls_version(&t->conf, MBEDTLS_SSL_VERSION_TLS1_2);

	if (READ_ONCE(kdg_debug)) {
		mbedtls_debug_set_threshold(4);
		mbedtls_ssl_conf_dbg(&t->conf, kdg_tls_debug, NULL);
	}

	mbedtls_ssl_conf_rng(&t->conf, kdg_tls_rng, &kdg_ctr_drbg);
	mbedtls_ssl_conf_ca_chain(&t->conf, &kdg_ca, NULL);
	mbedtls_ssl_conf_alpn_protocols(&t->conf, kdg_alpn_protos);

	/* 会话票据：本项目不做持久化票据存储（§6.2「连接恢复票据有界存储」），
	 * 且 0-RTT 首期禁用 —— mbedTLS 默认不启用 early data，无需额外操作。 */
	mbedtls_ssl_conf_session_tickets(&t->conf, MBEDTLS_SSL_SESSION_TICKETS_DISABLED);

	ret = mbedtls_ssl_setup(&t->ssl, &t->conf);
	if (ret) {
		pr_err("ssl_setup 失败: %s\n", kdg_tls_strerror(ret));
		goto fail;
	}

	/* SNI 与主机名校验。必须在握手前设置；直连 IP 也不例外
	 * （方案 §6.2：「不因直连 IP 而遗漏 SNI」）。 */
	ret = mbedtls_ssl_set_hostname(&t->ssl, hostname);
	if (ret) {
		pr_err("set_hostname 失败: %s\n", kdg_tls_strerror(ret));
		goto fail;
	}

	/* 第三个回调留 NULL：DTLS 才需要 recv_timeout，而我们未启用 DTLS；
	 * 超时由 kdg_sock 的 sk_rcvtimeo 承担。 */
	mbedtls_ssl_set_bio(&t->ssl, t, kdg_tls_bio_send, kdg_tls_bio_recv, NULL);
	return 0;

fail:
	mbedtls_ssl_config_free(&t->conf);
	mbedtls_ssl_free(&t->ssl);
	t->sock = NULL;
	return -EIO;
}

int kdg_tls_handshake(struct kdg_tls *t)
{
	int ret;

	if (!t || !t->sock)
		return -EINVAL;

	ret = mbedtls_ssl_handshake(&t->ssl);
	if (ret != 0) {
		/* WANT_READ/WANT_WRITE 在这里只可能来自**接收超时**（我们自备的
		 * socket 层是阻塞的，唯一会返回 WANT_READ 的地方就是
		 * kdg_tls_bio_recv 的超时分支）。因此它是「握手没能在超时内
		 * 完成」，而不是「握手协议出错」—— 两者的可诊断性差很多，
		 * 分不开就会让人对着一个 -EIO 去查证书问题。 */
		if (ret == MBEDTLS_ERR_SSL_WANT_READ ||
		    ret == MBEDTLS_ERR_SSL_WANT_WRITE) {
			pr_warn("TLS 握手超时（对端在 deadline 内未完成握手）\n");
			return -ETIMEDOUT;
		}
		/* 握手失败时，证书类错误往往同时体现在 verify result 里。
		 * 把它记下来，便于上层给出「是证书问题还是网络问题」的区分。 */
		t->verify_flags = mbedtls_ssl_get_verify_result(&t->ssl);
		pr_warn("TLS 握手失败: %s (-0x%04x) verify_flags=0x%08x\n",
			kdg_tls_strerror(ret), -ret, t->verify_flags);
		return -EIO;
	}

	/* 双保险：即使 mbedTLS 放行，也显式复查一次验证结果。
	 * VERIFY_REQUIRED 下正常不会走到这里，但显式复查能让「验证被意外
	 * 关闭」这类配置错误变成显式失败而不是静默通过。 */
	t->verify_flags = mbedtls_ssl_get_verify_result(&t->ssl);
	if (t->verify_flags != 0) {
		pr_err("证书验证未通过: flags=0x%08x\n", t->verify_flags);
		return -EACCES;
	}

	t->handshaken = true;
	pr_info("TLS 握手完成（协议 %s，密码套件 %s，ALPN %s）\n",
		mbedtls_ssl_get_version(&t->ssl),
		mbedtls_ssl_get_ciphersuite(&t->ssl),
		kdg_tls_alpn(t) ? kdg_tls_alpn(t) : "(未协商)");
	return 0;
}

int kdg_tls_write(struct kdg_tls *t, const void *buf, size_t len)
{
	size_t off = 0;
	const u8 *p = buf;

	if (!t || !t->handshaken)
		return -EINVAL;

	while (off < len) {
		int ret = mbedtls_ssl_write(&t->ssl, p + off, len - off);

		if (ret < 0) {
			pr_warn("TLS 写入失败: %s\n", kdg_tls_strerror(ret));
			return -EIO;
		}
		if (ret == 0)
			return -EPIPE;
		off += (size_t)ret;
	}
	return 0;
}

int kdg_tls_read(struct kdg_tls *t, void *buf, size_t len)
{
	int ret;

	if (!t || !t->handshaken)
		return -EINVAL;

	ret = mbedtls_ssl_read(&t->ssl, buf, len);
	if (ret == 0)
		return 0;			/* 对端正常关闭 */
	if (ret == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY)
		return 0;
	/*
	 * WANT_READ = 这次接收没在超时内拿到数据。**它是「暂时没有」，不是
	 * 「连接坏了」** —— 持久连接上接收超时被用作扫描滴答，把它当错误会
	 * 让一条健康的空闲连接每 250 ms 被拆一次。
	 *
	 * 注意 mbedTLS 会把跨调用读到的半个记录留在自己的缓冲里，因此这里
	 * 返回 -EAGAIN 不会丢数据：下次读到的仍是一个完整记录。
	 */
	if (ret == MBEDTLS_ERR_SSL_WANT_READ ||
	    ret == MBEDTLS_ERR_SSL_WANT_WRITE)
		return -EAGAIN;
	if (ret < 0) {
		pr_warn("TLS 读取失败: %s\n", kdg_tls_strerror(ret));
		return -EIO;
	}
	return ret;
}

const char *kdg_tls_alpn(const struct kdg_tls *t)
{
	if (!t)
		return NULL;
	return mbedtls_ssl_get_alpn_protocol(&t->ssl);
}

void kdg_tls_session_close(struct kdg_tls *t)
{
	if (!t)
		return;

	if (t->handshaken) {
		/* 尽力发 close_notify，但**不因它失败而改变结果**：
		 * 对端可能已经走了，此时关连接仍然应当成功。 */
		mbedtls_ssl_close_notify(&t->ssl);
		t->handshaken = false;
	}

	mbedtls_ssl_free(&t->ssl);
	mbedtls_ssl_config_free(&t->conf);
	t->sock = NULL;
}

const char *kdg_tls_strerror(int err)
{
	static char buf[96];

	mbedtls_strerror(err, buf, sizeof(buf));
	if (buf[0] == '\0')
		scnprintf(buf, sizeof(buf), "未知 mbedTLS 错误 -0x%04x", -err);
	return buf;
}
