/* SPDX-License-Identifier: GPL-2.0 */
/*
 * kdg_h3.h —— 精简 HTTP/3 客户端（RFC 9114），只服务 DoH。
 *
 * 实现范围：控制流 + SETTINGS、请求流的 HEADERS/DATA、响应侧的
 * HEADERS/DATA/GOAWAY 解析。不做：推送（服务端推送一律 CANCEL_PUSH 之外
 * 直接忽略）、CONNECT、扩展 CONNECT、WebTransport、优先级（不接收
 * PRIORITY_UPDATE）。
 *
 * 与 QUIC 层的分工：本层只处理「流上的字节」——流的建立/收发/重传由
 * kdg_quic_conn 负责。socket 与线程同样不在此层出现，故宿主可测。
 */
#ifndef _KDG_H3_H
#define _KDG_H3_H

#include "kdg_quic_conn.h"
#include "kdg_qpack.h"

/* 帧类型（RFC 9114 §7.2），常量名后带 H3_ 以免与 QUIC 帧混淆 */
#define H3F_DATA	0x00
#define H3F_HEADERS	0x01
#define H3F_CANCEL_PUSH	0x03
#define H3F_SETTINGS	0x04
#define H3F_PUSH_PROMISE 0x05
#define H3F_GOAWAY	0x07
#define H3F_MAX_PUSH_ID	0x0d

/* 流类型（§6） */
#define H3S_CONTROL	0x00
#define H3S_PUSH	0x01
#define H3S_QPACK_ENC	0x02
#define H3S_QPACK_DEC	0x03

/* 设置标识（§7.2.4.1） */
#define H3_SET_QPACK_MAX_TABLE_CAPACITY	0x01
#define H3_SET_MAX_FIELD_SECTION_SIZE	0x06
#define H3_SET_QPACK_BLOCKED_STREAMS	0x07

/* 错误码（§8.1） */
#define H3E_NO_ERROR		0x0100
#define H3E_GENERAL_PROTOCOL	0x0101
#define H3E_INTERNAL		0x0102
#define H3E_STREAM_CREATION	0x0103
#define H3E_CLOSED_CRITICAL	0x0104
#define H3E_FRAME_UNEXPECTED	0x0105
#define H3E_FRAME_ERROR		0x0106
#define H3E_EXCESSIVE_LOAD	0x0107
#define H3E_ID_ERROR		0x0108
#define H3E_SETTINGS_ERROR	0x0109
#define H3E_MISSING_SETTINGS	0x010a
#define H3E_REQUEST_REJECTED	0x010b
#define H3E_REQUEST_CANCELLED	0x010c
#define H3E_REQUEST_INCOMPLETE	0x010d
#define H3E_MESSAGE_ERROR	0x010e
#define H3E_CONNECT_ERROR	0x010f
#define H3E_VERSION_FALLBACK	0x0110
/* QPACK 解压失败（RFC 9204 §8.3） */
#define H3E_QPACK_DECOMPRESSION_FAILED	0x0200

#define KDG_H3_BODY_MAX	(64 * 1024)	/* DoH 响应上限（DNS 报文本身 ≤64 KiB） */
#define KDG_H3_RSTATES	4		/* 并发请求流上限 */

enum kdg_h3_req_state {
	H3R_IDLE = 0,
	H3R_OPEN,		/* 已发 HEADERS，等响应 */
	H3R_DONE,		/* 收到完整响应 */
	H3R_FAILED,
};

#define KDG_H3_HDR_MAX	8192	/* HEADERS 载荷上限（对端声明的字段段上限 8 KB） */

/* 一条请求流上的增量帧解析状态。
 * ⚠️ 必须能跨多次 feed：一次 TCP/QUIC 交付只给出帧的一部分是常态。 */
struct kdg_h3_req {
	enum kdg_h3_req_state state;
	u64 sid;
	bool fin;
	/* 帧头解析：varint 分两段（类型、长度），字节可能拆在两次 feed 里 */
	u8 stage;		/* 0=读类型 1=读长度 2=读载荷 3=跳过载荷 */
	u8 vbuf[8];		/* 正在拼的 varint */
	u8 vlen, vneed;
	u64 ftype, frem;
	bool is_control;	/* 这个解析状态属于对端控制流（帧类型集不同） */
	/* HEADERS/GOAWAY 载荷需要完整拿到才能处理 */
	u8 hbuf[KDG_H3_HDR_MAX];
	size_t hlen;
	/* 响应 */
	bool got_headers;
	int status;
	u8 body[KDG_H3_BODY_MAX];
	size_t body_len;
	int err;		/* 失败原因（负 errno 或 H3E_* 错误码） */
};

#define KDG_H3_UNI_MAX	3	/* 控制流 + QPACK 编/解码流 */

/* 对端单向流：首段是流类型 varint，其后才是帧。 */
struct kdg_h3_uni {
	u64 id;
	bool type_known;
	u64 type;
	u8 tbuf[8];
	u8 tlen, tneed;
	struct kdg_h3_req fr;		/* 复用请求流的帧解析状态机 */
};

struct kdg_h3 {
	struct kdg_qc qc;		/* 内嵌：一条 H3 连接就是一条 QUIC 连接 */
	bool control_open, settings_sent;
	bool goaway_seen;
	u64 goaway_id;
	struct kdg_h3_req req[KDG_H3_RSTATES];
	struct kdg_h3_uni uni[KDG_H3_UNI_MAX];
	struct kdg_qpack_dec dec;
	u8 decbuf[4096];		/* QPACK 解码出的字符串池 */
	struct kdg_qpack_field fields[KDG_QPACK_MAX_FIELDS];
	char authority[256];
};

int kdg_h3_init(struct kdg_h3 *h, const char *host, const char *alpn,
		const struct kdg_qtp *tp, const mbedtls_x509_crt *ca,
		kdg_rng_fn rng, void *rng_ctx, u64 now);
void kdg_h3_fini(struct kdg_h3 *h);

/* 开一条请求流，发一个 DoH POST（HEADERS + DATA + FIN）。返回槽位或负 errno。 */
int kdg_h3_post(struct kdg_h3 *h, const char *path, const u8 *body,
		size_t body_len);

/* 数据报进出（与 kdg_qc_* 同形）：上层 socket 循环直接转发。 */
size_t kdg_h3_send(struct kdg_h3 *h, u8 *out, size_t cap, u64 now);
int kdg_h3_recv(struct kdg_h3 *h, u8 *dgram, size_t len, u64 now);
void kdg_h3_timeout(struct kdg_h3 *h, u64 now);
u64 kdg_h3_next_timer(const struct kdg_h3 *h);

/* 取第 i 个请求槽位；未使用返回 NULL。 */
struct kdg_h3_req *kdg_h3_req_at(struct kdg_h3 *h, size_t i);

/* 连接是否可再发请求（握手完成且未收到 GOAWAY） */
bool kdg_h3_ready(const struct kdg_h3 *h);

/* 内部：把流上的字节喂给 H3 帧解析（测试直接调用它，跳过 QUIC 层）。 */
int kdg_h3_feed(struct kdg_h3 *h, struct kdg_h3_req *r, const u8 *data,
		size_t len, bool fin);

#endif