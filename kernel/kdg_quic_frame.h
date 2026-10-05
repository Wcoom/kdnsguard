/* SPDX-License-Identifier: GPL-2.0 */
/*
 * kdg_quic_frame.h —— QUIC varint、帧与传输参数编解码（RFC 9000 §16/§19/§18）。
 * 纯计算、双态可编译。所有对端输入经有界读取，越界即 FRAME_ENCODING_ERROR。
 */
#ifndef _KDG_QUIC_FRAME_H
#define _KDG_QUIC_FRAME_H

#include "kdg_base.h"

#define KDG_QV_MAX	((1ULL << 62) - 1)

/* 帧类型（只列客户端会收发的） */
#define QF_PADDING		0x00
#define QF_PING			0x01
#define QF_ACK			0x02
#define QF_ACK_ECN		0x03
#define QF_RESET_STREAM		0x04
#define QF_STOP_SENDING		0x05
#define QF_CRYPTO		0x06
#define QF_NEW_TOKEN		0x07
#define QF_STREAM		0x08	/* 0x08..0x0f，低 3 位 OFF/LEN/FIN */
#define QF_MAX_DATA		0x10
#define QF_MAX_STREAM_DATA	0x11
#define QF_MAX_STREAMS_BIDI	0x12
#define QF_MAX_STREAMS_UNI	0x13
#define QF_DATA_BLOCKED		0x14
#define QF_STREAM_DATA_BLOCKED	0x15
#define QF_STREAMS_BLOCKED_BIDI	0x16
#define QF_STREAMS_BLOCKED_UNI	0x17
#define QF_NEW_CONNECTION_ID	0x18
#define QF_RETIRE_CONNECTION_ID	0x19
#define QF_PATH_CHALLENGE	0x1a
#define QF_PATH_RESPONSE	0x1b
#define QF_CONN_CLOSE		0x1c
#define QF_CONN_CLOSE_APP	0x1d
#define QF_HANDSHAKE_DONE	0x1e

/* 传输错误码（§20.1） */
#define QE_NO_ERROR		0x0
#define QE_INTERNAL		0x1
#define QE_FLOW_CONTROL		0x3
#define QE_STREAM_LIMIT		0x4
#define QE_STREAM_STATE		0x5
#define QE_FINAL_SIZE		0x6
#define QE_FRAME_ENCODING	0x7
#define QE_TRANSPORT_PARAM	0x8
#define QE_PROTOCOL_VIOLATION	0xa
#define QE_CRYPTO_BASE		0x100

/* 有界读取器（与 kdg_tls13.c 的 rd 同纪律：越界置 bad，后续读返回 0） */
struct kdg_qrd {
	const u8 *p;
	size_t n;
	bool bad;
};

u64 kdg_qv_get(struct kdg_qrd *r);
const u8 *kdg_qrd_take(struct kdg_qrd *r, size_t len);
size_t kdg_qv_len(u64 v);
/* 写 varint，返回写入字节数；cap 不足或 v 越界返回 0 */
size_t kdg_qv_put(u8 *p, size_t cap, u64 v);
/* 固定 2 字节写法（长头 Length 字段先占位后回填用） */
void kdg_qv_put2(u8 *p, u64 v);

/* 一个解析出的帧。指针指向原包内，生命期同包缓冲。 */
struct kdg_qframe {
	u64 type;
	union {
		struct { u64 largest, delay, first_range, range_count;
			 const u8 *ranges; size_t ranges_len; } ack;
		struct { u64 off; const u8 *data; size_t len; } crypto;
		struct { u64 id, off; const u8 *data; size_t len; bool fin; } stream;
		struct { u64 id, err, final_size; } reset;	/* RESET_STREAM/STOP_SENDING */
		struct { u64 id, max; } max;			/* MAX_* / *_BLOCKED */
		struct { u64 seq, retire_prior; u8 cid_len; const u8 *cid;
			 const u8 *token; } ncid;
		struct { u64 err, frame_type; const u8 *reason; size_t rlen; } close;
		struct { const u8 *data; } path;		/* 8 字节 */
		struct { const u8 *tok; size_t len; } token;
	} u;
};

/* 解析下一帧。返回 0 成功、-EAGAIN 已无更多帧、其余负值为编码错误。 */
int kdg_qframe_next(struct kdg_qrd *r, struct kdg_qframe *f);

/* ACK 帧里的附加区间迭代：每次给出一个 [lo, hi] 包号闭区间 */
struct kdg_qack_it {
	struct kdg_qrd r;
	u64 next_hi;
	u64 left;
	bool first;
	u64 first_range;
};
void kdg_qack_begin(struct kdg_qack_it *it, const struct kdg_qframe *f);
int kdg_qack_next(struct kdg_qack_it *it, u64 *lo, u64 *hi);

/* 传输参数（§18.2，只取客户端关心的） */
struct kdg_qtp {
	u64 max_idle_timeout;		/* ms */
	u64 max_udp_payload;
	u64 initial_max_data;
	u64 initial_max_stream_data_bidi_local;
	u64 initial_max_stream_data_bidi_remote;
	u64 initial_max_stream_data_uni;
	u64 initial_max_streams_bidi;
	u64 initial_max_streams_uni;
	u64 ack_delay_exponent;
	u64 max_ack_delay;
	u64 active_cid_limit;
	u8 orig_dcid[20], orig_dcid_len;
	u8 init_scid[20], init_scid_len;
	bool has_orig_dcid, has_init_scid, has_retry_scid;
};

void kdg_qtp_defaults(struct kdg_qtp *tp);
int kdg_qtp_parse(const u8 *p, size_t n, struct kdg_qtp *tp);
/* 编码客户端传输参数，返回长度，失败返回负值 */
int kdg_qtp_encode_client(const struct kdg_qtp *tp, const u8 *scid,
			  size_t scid_len, u8 *out, size_t cap);

#endif
