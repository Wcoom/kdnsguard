/* SPDX-License-Identifier: GPL-2.0 */
/*
 * kdnsguard 的 mbedTLS 配置——**叠加式**（overlay）。
 *
 * 设计取向：先 `#include` 上游默认配置（已知可用、覆盖完整），再逐项 `#undef`
 * 掉内核里根本不存在的东西。相比从零写一份两百项的清单，这种写法的好处是
 * 「我们改动了什么」= 本文件全文，一眼可审；上游升级时只需复核被 undef 的项
 * 是否有了新名字。
 *
 * ⚠️ 不要修改 third_party/mbedtls/ 下的任何文件 —— 那是上游原件，
 * 保持逐字节一致才能可靠升级。所有适配都在本文件与 ../mbedtls-kernel/ 里。
 *
 * 用法：-DMBEDTLS_CONFIG_FILE='"kdnsguard_mbedtls_config.h"'
 *       且 -I 指向本目录。
 */
#ifndef KDNSGUARD_MBEDTLS_CONFIG_H
#define KDNSGUARD_MBEDTLS_CONFIG_H

/* ── 1. 上游默认配置作为基线 ──────────────────────────────────────────── */
#include "mbedtls/mbedtls_config.h"

/* ── 2. 内核里不存在的操作系统设施，全部关闭 ───────────────────────────── */

/* BSD socket 封装。内核态没有 socket()/connect()/getaddrinfo()；
 * 我们用 mbedtls_ssl_set_bio() 把 send/recv 回调接到 kernel_sendmsg/recvmsg。 */
#undef MBEDTLS_NET_C

/* signal/setitimer 实现的定时器。内核态不可用，且我们不需要 DTLS 重传定时器。 */
#undef MBEDTLS_TIMING_C

/* 文件 I/O。内核态没有 fopen/fread。 */
#undef MBEDTLS_FS_IO

/* PSA 的持久化键存储与 ITS（文件后端）。内核模块不做持久密钥存储；
 * 本项目连会话票据持久化都刻意保持有界且仅内存（方案 §6.2）。 */
#undef MBEDTLS_PSA_CRYPTO_STORAGE_C
#undef MBEDTLS_PSA_ITS_FILE_C

/* 熵源的 NV seed 需要读写种子文件。我们改用内核 CRNG，见 MBEDTLS_ENTROPY_HARDWARE_ALT。 */
#undef MBEDTLS_ENTROPY_NV_SEED

/* ── 3. 本项目不需要的协议与功能面 ───────────────────────────────────── */

/* 只要客户端。服务端代码占相当体积且永远不会被调用。 */
#undef MBEDTLS_SSL_SRV_C

/* DTLS（UDP 版 TLS）。DoQ 不在本阶段范围内，且 DTLS 需要 TIMING_C。 */
#undef MBEDTLS_SSL_PROTO_DTLS
#undef MBEDTLS_SSL_DTLS_ANTI_REPLAY
#undef MBEDTLS_SSL_DTLS_HELLO_VERIFY
#undef MBEDTLS_SSL_DTLS_CLIENT_PORT_REUSE
#undef MBEDTLS_SSL_DTLS_CONNECTION_ID
#undef MBEDTLS_SSL_DTLS_SRTP

/* 证书与 CSR 的**生成/写入**。我们只解析与校验，从不签发。 */
#undef MBEDTLS_X509_CREATE_C
#undef MBEDTLS_X509_CRT_WRITE_C
#undef MBEDTLS_X509_CSR_WRITE_C
#undef MBEDTLS_X509_CSR_PARSE_C
#undef MBEDTLS_PK_WRITE_C
#undef MBEDTLS_PK_PARSE_EC_EXTENDED

/* 内存调试分配器与线程抽象：前者仅供测试，后者本项目按「单一执行者驱动
 * 一个 TLS 对象」设计（方案 §6.2），不需要 mbedTLS 自己加锁。 */
#undef MBEDTLS_MEMORY_BUFFER_ALLOC_C
#undef MBEDTLS_THREADING_C

/* 此开关控制整条证书链的有效期验证，不能关闭。UTC 转换由内核提供。 */
#define MBEDTLS_HAVE_TIME_DATE
#define MBEDTLS_PLATFORM_GMTIME_R_ALT
#define MBEDTLS_SSL_DTLS_CONNECTION_ID_COMPAT 0

/* PSK 与静态 DH：本项目只用证书握手。 */
#undef MBEDTLS_KEY_EXCHANGE_PSK_ENABLED
#undef MBEDTLS_KEY_EXCHANGE_DHE_PSK_ENABLED
#undef MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED
#undef MBEDTLS_KEY_EXCHANGE_RSA_PSK_ENABLED
#undef MBEDTLS_KEY_EXCHANGE_RSA_ENABLED
#undef MBEDTLS_KEY_EXCHANGE_DHE_RSA_ENABLED

/* TLS 1.2 与 TLS 1.3 都保留：方案 §6.2 要求「先验证 TLS 1.3，可保留符合策略的
 * TLS 1.2 互操作路径」。若日后要收紧到 TLS 1.3-only，undef MBEDTLS_SSL_PROTO_TLS1_2
 * 并同步清掉上面之外的 1.2 专属项即可。 */

/* 库自检（self-test）：面向宿主开发的正确性验证，内核模块里既无意义又
 * 会拉进 rand()/printf 等宿主设施（实测 rsa.c:2955 就在该块内）。
 * 正确性验证由 tests/ 下的宿主侧语料测试承担。 */
#undef MBEDTLS_SELF_TEST

/* 注：曾实验性关闭 MBEDTLS_ECP_NIST_OPTIM / MBEDTLS_ECP_FIXED_POINT_OPTIM，
 * 用以判断 P-256 失败是否源于优化路径的预计算表 —— **实测结果完全不变**，
 * 故已撤销该偏离。失败在更下层（群参数校验），见 docs/P1-ecp-blocker.md。 */

/* ── 4. 内核态必需的平台抽象 ──────────────────────────────────────────── */

/* PLATFORM_C 是这一整套注入机制的总开关。 */
#define MBEDTLS_PLATFORM_C

/* 让 calloc/free 走我们注入的函数（kmalloc/kfree 封装）。 */
#define MBEDTLS_PLATFORM_MEMORY

/* 关掉对 stdlib/stdio/time 的直接依赖，强制走注入点。
 * 没有这一项，mbedTLS 会直接引用 libc 符号，内核态链接必然失败。 */
#define MBEDTLS_PLATFORM_NO_STD_FUNCTIONS

/* 格式化输出走注入点。mbedTLS 在错误字符串与调试里用 snprintf/vsnprintf。 */
#define MBEDTLS_PLATFORM_SNPRINTF_ALT
#define MBEDTLS_PLATFORM_VSNPRINTF_ALT

/* mbedtls_time() 走注入点，接内核 ktime_get_real_seconds()。
 * 证书有效期检查依赖它，且方案 §9.3 要求「用可明确处理休眠流逝的时间源」——
 * CLOCK_REALTIME（ktime_get_real_seconds）符合这一要求。 */
#define MBEDTLS_PLATFORM_TIME_ALT

/* mbedTLS 还需要一个**单调毫秒**时钟（mbedtls_ms_time），用于 DTLS 重传计时等。
 * 默认实现靠 clock_gettime/POSIX，内核态没有；置 ALT 由我们提供。
 * 实测不置它会在 platform_util.c:256 撞上 `#error "No mbedtls_ms_time available"`。 */
#define MBEDTLS_PLATFORM_MS_TIME_ALT

/* 熵源：由我们提供 MBEDTLS_ENTROPY_HARDWARE_ALT 指向的实现，
 * 内部用内核 CRNG（get_random_bytes）。 */
#define MBEDTLS_ENTROPY_HARDWARE_ALT

/* 内核态没有 /dev/urandom 这种平台熵源。 */
#define MBEDTLS_NO_PLATFORM_ENTROPY

/* ⚠️ 这里**不能**用 MBEDTLS_PLATFORM_TIME_TYPE_MACRO 来定义 mbedtls_time_t：
 * check_config.h:530 明令它与 MBEDTLS_PLATFORM_TIME_ALT 互斥。我们必须要
 * TIME_ALT（把时间接到内核时钟上），所以 mbedtls_time_t 只能由 time_t 推出，
 * 而 time_t 由 shim/time.h 提供。 */

/* printf/fprintf 改走 **ALT 函数指针**，而不是 *_MACRO 宏替换。
 *
 * 这是一个实测踩出来的选择：*_MACRO 只是把名字替换掉，不产生任何声明，
 * 于是 mbedTLS 各文件里（如 aes.c 的 AESNI 调试路径）就出现
 * "call to undeclared function 'kdg_mbedtls_printf'"。ALT 方式下
 * mbedTLS 自己在 platform.h 里声明函数指针与 setter，我们只需在初始化时
 * 调 mbedtls_platform_set_printf()/set_fprintf() 装上实现。
 *
 * FPRINTF_ALT 的声明需要 FILE，由 shim/stdio.h 提供。 */
#define MBEDTLS_PLATFORM_PRINTF_ALT
#define MBEDTLS_PLATFORM_FPRINTF_ALT

/* ── 5. 安全清零走平台实现 ──────────────────────────────────────────────
 *
 * 🔴 这一项不是可选项，不定义它模块**一加载就 panic**。
 *
 * 上游 platform_util.c:91 是这么写的：
 *     static void *(*const volatile memset_func)(void *, int, size_t) = memset;
 *     ... memset_func(buf, 0, len);
 * 那个 volatile 函数指针是**刻意的反优化手法**，保证安全清零不被编译器删掉。
 * 但在内核里它构成一次**间接调用**，而 kCFI（CONFIG_CFI_CLANG=y）会检查
 * 目标函数前的类型哈希 —— 内核的 memset 是 arch/arm64/lib/memset.S 的汇编
 * 实现（memset 只是 __memset 的弱别名），**没有 kCFI 类型哈希**，于是：
 *     CFI failure at mbedtls_platform_zeroize+0x3c (target: __memset;
 *                 expected type: 0x8827a475)
 *     Internal error: Oops - CFI → Kernel panic
 *
 * 换成平台实现后是一次**直接调用**，kCFI 不管直接调用；安全性由
 * barrier_data() 的编译器屏障保证（内核自己的 memzero_explicit() 用的
 * 正是这一手法，但它未导出，故在 kdg_mbedtls.c 里等价复刻）。 */
#define MBEDTLS_PLATFORM_ZEROIZE_ALT

/* ── 6. 调试（开发期开启，便于首次联调看握手细节）─────────────────────
 * 关闭可省体积；排障时打开并配合 -DMBEDTLS_DEBUG_LEVEL。 */
#define MBEDTLS_DEBUG_C

#endif /* KDNSGUARD_MBEDTLS_CONFIG_H */
