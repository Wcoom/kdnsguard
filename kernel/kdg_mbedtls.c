/* SPDX-License-Identifier: GPL-2.0 */
/*
 * kdg_mbedtls.c —— mbedTLS 的内核态平台适配层。
 *
 * 本文件 include shim/stdio.h 以取得与 mbedTLS 完全一致的 FILE 类型
 * （mbedtls_fprintf 的函数指针签名必须逐字匹配）。该 shim 刻意不含任何
 * snprintf/vsnprintf 宏，故本文件内对内核 vsnprintf 的调用不会被改名。
 *
 * 适配点共 5 个，对应 mbedTLS 的 5 个注入契约：
 *   1. 内存分配   mbedtls_platform_set_calloc_free   → kcalloc/kfree
 *   2. 格式化     mbedtls_platform_set_{v,}snprintf   → 内核 vsnprintf
 *   3. 时间       mbedtls_platform_set_time          → ktime_get_real_seconds
 *   4. 熵源       mbedtls_hardware_poll              → get_random_bytes
 *   5. 诊断输出   编译期宏 MBEDTLS_PLATFORM_{,F}PRINTF_MACRO → printk
 */
#define pr_fmt(fmt)	KBUILD_MODNAME ": " fmt

#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/random.h>
#include <linux/timekeeping.h>
#include <linux/string.h>
#include <linux/compiler.h>	/* barrier_data() */
#include <linux/stdarg.h>
#include <linux/errno.h>

#include <mbedtls/build_info.h>
#include <mbedtls/platform.h>
#include <mbedtls/platform_time.h>
/* mbedtls_hardware_poll 的约定返回值 MBEDTLS_ERR_ENTROPY_SOURCE_FAILED 在
 * entropy.h，不在 platform.h。 */
#include <mbedtls/entropy.h>

/* FILE 类型与四个入口的声明的唯一真源，与 mbedTLS 侧必须一致。 */
#include "stdio.h"

/* ── 1. 内存 ──────────────────────────────────────────────────────────── */

void *kdg_mbedtls_calloc(size_t n, size_t size)
{
	/*
	 * 用 GFP_KERNEL：mbedTLS 的每一次分配都必须发生在**可睡眠上下文**。
	 * 这是方案 §6.2 的硬性要求——握手、证书解析、网络等待不得发生于
	 * Netfilter hook、spinlock、RCU 读侧临界区或关中断区。
	 * 若将来有人在原子上下文调用到 TLS 路径，这里会给出明确的
	 * "sleeping function called from invalid context" 而不是静默错乱。
	 *
	 * kcalloc 自带 n*size 溢出检查（对应 C99 calloc 的语义）。
	 */
	return kcalloc(n, size, GFP_KERNEL);
}

void kdg_mbedtls_free(void *ptr)
{
	kfree(ptr);
}

/* ── 2. 格式化 ────────────────────────────────────────────────────────── */

int kdg_mbedtls_vsnprintf(char *s, size_t n, const char *fmt, va_list ap)
{
	/* 内核 vsnprintf 的返回语义与 C99 一致（返回「本该写入」的长度），
	 * 正是 mbedTLS 依赖的语义。 */
	return vsnprintf(s, n, fmt, ap);
}

int kdg_mbedtls_snprintf(char *s, size_t n, const char *fmt, ...)
{
	va_list ap;
	int ret;

	va_start(ap, fmt);
	ret = vsnprintf(s, n, fmt, ap);
	va_end(ap);
	return ret;
}

/*
 * 诊断输出。mbedTLS 的 debug 回调最终会走到这里。
 *
 * 方案 §14.1 的输出纪律要求「stats 和普通日志不输出完整 URI/查询域名」——
 * 这条纪律的落点就在此处：本函数只是通道，**调用方决定打印什么**。
 * 传输层只允许把 mbedTLS 的握手/证书错误（不含主机名）交给它。
 *
 * 长度截到 512 以适配 printk 的单条上限，超出部分丢弃而不是分片刷屏。
 */
#define KDG_MBEDTLS_LOG_MAX	512

int kdg_mbedtls_printf(const char *fmt, ...)
{
	char buf[KDG_MBEDTLS_LOG_MAX];
	va_list ap;
	int ret;

	va_start(ap, fmt);
	ret = vsnprintf(buf, sizeof(buf), fmt, ap);
	va_end(ap);
	if (ret > 0)
		pr_info("%s", buf);
	return ret;
}

int kdg_mbedtls_fprintf(FILE *stream, const char *fmt, ...)
{
	char buf[KDG_MBEDTLS_LOG_MAX];
	va_list ap;
	int ret;

	/* stream 在内核态无意义（它不是真正的 FILE），刻意忽略——但仍然
	 * 接住这个参数，因为 mbedTLS 的调用点会传它。 */
	(void)stream;

	va_start(ap, fmt);
	ret = vsnprintf(buf, sizeof(buf), fmt, ap);
	va_end(ap);
	if (ret > 0)
		pr_info("%s", buf);
	return ret;
}

/* ── 3. 时间 ──────────────────────────────────────────────────────────── */

static mbedtls_time_t kdg_mbedtls_time(mbedtls_time_t *t)
{
	/*
	 * 用 CLOCK_REALTIME（ktime_get_real_seconds）而不是单调时钟：
	 * 证书有效期检查要求的是「墙上时间」。
	 *
	 * 方案 §9.3 要求「TTL 计算使用可明确处理休眠流逝的时间源，避免设备睡了
	 * 一小时却仍把旧缓存当作刚写入」。注意这里的分工：**证书有效期**必须用
	 * realtime；而 DNS 记录的 TTL 递减属于另一条路径，那个用单调时钟更合适
	 * （设备休眠时单调时钟不前进，缓存不会被无端判过期）。两者不可混用。
	 */
	mbedtls_time_t now = (mbedtls_time_t)ktime_get_real_seconds();

	if (t)
		*t = now;
	return now;
}

/*
 * mbedTLS 的单调毫秒时钟（MBEDTLS_PLATFORM_MS_TIME_ALT）。
 *
 * 上游在 Linux 用户态用的是 clock_gettime(CLOCK_BOOTTIME)，其内核等价物正是
 * ktime_get_boottime_ns()。选它而不是 ktime_get_ns()（CLOCK_MONOTONIC）是因为
 * BOOTTIME 把设备休眠期间的时间也算进去 —— 与用户态基线行为一致，
 * 也符合方案 §9.3「用可明确处理休眠流逝的时间源」的要求。
 */
mbedtls_ms_time_t mbedtls_ms_time(void)
{
	return (mbedtls_ms_time_t)(ktime_get_boottime_ns() / NSEC_PER_MSEC);
}

/* ── 3b. 安全清零（MBEDTLS_PLATFORM_ZEROIZE_ALT）────────────────────────
 *
 * 存在理由见 kdnsguard_mbedtls_config.h 第 5 节：上游用 volatile 函数指针
 * 调 memset，在内核里 = 对没有 kCFI 类型哈希的汇编 memset 做间接调用 = panic。
 *
 * 这里用**直接调用 + 编译器屏障**复刻内核 memzero_explicit() 的手法。
 * 为什么直接调用同样安全：mbedtls_platform_zeroize 是一个非内联的导出函数，
 * 编译期无法证明调用方之后不再使用该缓冲区，因此这次 memset 不可能是死存储，
 * 不会被优化掉；barrier_data() 是额外的显式保证。
 */
void mbedtls_platform_zeroize(void *buf, size_t len)
{
	if (len > 0) {
		memset(buf, 0, len);
		barrier_data(buf);
	}
}

/* ── 4. 熵源 ──────────────────────────────────────────────────────────── */

/*
 * MBEDTLS_ENTROPY_HARDWARE_ALT 要求的入口。内核 CRNG 已经过充分初始化
 * （模块加载必然发生在其之后），直接取即可，不需要再套一层 DRBG。
 */
int mbedtls_hardware_poll(void *data, unsigned char *output, size_t len,
			  size_t *olen)
{
	(void)data;
	if (!output || !olen)
		return MBEDTLS_ERR_ENTROPY_SOURCE_FAILED;

	get_random_bytes(output, len);
	*olen = len;
	return 0;
}

/* ── 初始化 ───────────────────────────────────────────────────────────── */

/*
 * 必须在任何 mbedTLS 调用之前执行。当前实现是幂等的（重复设置同样的
 * 函数指针无副作用），但调用点应保证只执行一次。
 *
 * 为什么不能依赖编译期默认值：MBEDTLS_PLATFORM_NO_STD_FUNCTIONS 下
 * 这几个指针初值为 NULL，未初始化就调用 = 空指针解引用。
 */
int kdg_mbedtls_init(void)
{
	int ret;

	ret = mbedtls_platform_set_calloc_free(kdg_mbedtls_calloc,
					       kdg_mbedtls_free);
	if (ret)
		return ret;

	ret = mbedtls_platform_set_snprintf(kdg_mbedtls_snprintf);
	if (ret)
		return ret;

	ret = mbedtls_platform_set_vsnprintf(kdg_mbedtls_vsnprintf);
	if (ret)
		return ret;

	ret = mbedtls_platform_set_time(kdg_mbedtls_time);
	if (ret)
		return ret;

	ret = mbedtls_platform_set_printf(kdg_mbedtls_printf);
	if (ret)
		return ret;

	ret = mbedtls_platform_set_fprintf(kdg_mbedtls_fprintf);
	if (ret)
		return ret;

	pr_info("mbedTLS 平台层就绪（mem/printf/time/entropy 均已注入）\n");
	return 0;
}
