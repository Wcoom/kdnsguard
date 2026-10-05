/* SPDX-License-Identifier: GPL-2.0 */
/*
 * kdg_quic_conn.h —— QUIC v1 客户端连接状态机（RFC 9000 / 9002）。
 *
 * 只处理数据报，不碰 socket、不读时钟：
 *   kdg_qc_recv(dgram, now)      交付一个收到的 UDP 载荷
 *   kdg_qc_send(buf, now) → len  取一个要发的 UDP 载荷（0 表示暂无）
 *   kdg_qc_timeout(now)          计时器到期（丢包探测 / 空闲超时）
 *   kdg_qc_next_timer()          下一次需要调用 timeout 的时刻
 * socket 与线程由上层（kdg_upstream 的 H3 驱动）负责。纯计算 ⇒ 宿主可测。
 *
 * 面向 DoH 的有意取舍（都是「有界」而不是「通用」）：
 *   - 只建客户端双向流（请求）与 HTTP/3 必需的三条单向流；
 *   - 每条流的收发缓冲定长，超限即重置该流（DNS 报文 ≤ 64 KiB）；
 *   - 不迁移、不发 NEW_CONNECTION_ID 以外的路径帧、不支持 0-RTT；
 *   - 拥塞控制用 RFC 9002 NewReno 的最小子集（cwnd/ssthresh/恢复期）；
 *   - 丢包判据：包号阈值 3 与时间阈值 9/8·RTT（RFC 9002 §6.1），加 PTO。
 */
#ifndef _KDG_QUIC_CONN_H
#define _KDG_QUIC_CONN_H

#include "kdg_quic_crypto.h"
#include "kdg_quic_frame.h"
#include "kdg_tls13.h"

#define KDG_QC_MAX_STREAMS	72	/* 64 请求 + 3 本端单向 + 余量 */
#define KDG_QC_STREAM_BUF	(64 * 1024 + 64)	/* 单流收/发缓冲上限 */
#define KDG_QC_SENT_MAX		256	/* 每个包号空间在途包记录数 */
#define KDG_QC_CRYPTO_BUF	(KDG_T13_TXBUF * 2)
#define KDG_QC_RX_RANGES	16	/* 记住的已收包号区间（生成 ACK 用） */
#define KDG_QC_MTU		1200	/* 不做 PMTU 探测：1200 处处可达 */

enum kdg_qc_space { QS_INITIAL = 0, QS_HANDSHAKE, QS_APP, QS_COUNT };

enum kdg_qc_state {
	QC_IDLE = 0,
	QC_HANDSHAKING,
	QC_ESTABLISHED,		/* 1-RTT 可用（握手已完成，可能仍待 HANDSHAKE_DONE） */
	QC_CLOSING,		/* 已发 CONNECTION_CLOSE */
	QC_DRAINING,		/* 已收 CONNECTION_CLOSE */
	QC_CLOSED,
};

/* 一条流。id 按 RFC 9000 §2.1 编码；buf 按需分配。 */
struct kdg_qc_stream {
	u64 id;
	bool used;
	/* 发送 */
	u8 *sbuf;
	size_t slen;		/* 已写入的总字节 */
	u64 s_sent;		/* 已首次发出到的偏移 */
	u64 s_acked;		/* 连续已确认到的偏移（简化：只追踪前缀） */
	u64 s_max;		/* 对端给的流级发送上限 */
	bool s_fin;		/* 应用已结束写入 */
	bool s_fin_sent, s_fin_acked;
	/* 需要重传的区间（丢包后置位；最多一段，按最小未确认偏移重发） */
	bool s_lost;
	u64 s_lost_off;
	/* 接收 */
	u8 *rbuf;
	size_t rcap;
	u64 r_contig;		/* 连续可读到的偏移 */
	u64 r_final;		/* 对端 FIN 给出的最终长度，未知为 ~0 */
	u64 r_max;		/* 本端给对端的接收上限 */
	u64 r_read;		/* 应用已读走 */
	u8 *rmap;		/* 收到位图（按字节；DNS 量级可承受） */
	bool r_reset;
	u64 r_err;
};

/* 一个已发出的包的记录（丢包重传依据）。 */
struct kdg_qc_sent {
	u64 pn;
	u64 t_ms;
	u16 bytes;
	bool in_use, ack_eliciting, in_flight;
	/* 本包携带的可重传内容 */
	u32 crypto_off, crypto_len;
	bool has_crypto;
	u8 nstreams;
	struct { u16 slot; u32 off, len; bool fin; } st[4];
	bool has_max_data;	/* 携带过 MAX_DATA/MAX_STREAM_DATA，丢了要重发 */
};

/* 一个包号空间。 */
struct kdg_qc_pnspace {
	struct kdg_quic_keys tx, rx;
	bool discarded;
	u64 next_pn;
	s64 largest_rx;			/* -1 表示尚未收到 */
	u64 largest_rx_t;		/* 收到 largest_rx 的时刻（ACK delay 用） */
	s64 largest_acked;		/* 对端确认过的最大本端包号，-1 为无 */
	struct { u64 lo, hi; } rx_ranges[KDG_QC_RX_RANGES];	/* 降序 */
	u8 n_rx_ranges;
	bool ack_pending;		/* 收到 ack-eliciting 包后需回 ACK */
	/* CRYPTO 发送：握手字节保留至确认，丢包后从 c_lost 起重发 */
	u8 cbuf[KDG_QC_CRYPTO_BUF];
	u32 c_len, c_sent;
	bool c_lost;
	u32 c_lost_off;
	/* CRYPTO 接收：乱序到达时只接受落在 [c_rx, c_rx+窗口) 的数据 */
	u8 crx[KDG_T13_RXBUF];
	u8 crx_map[KDG_T13_RXBUF];		/* 逐字节已收标记，便于整体平移 */
	u64 c_rx;			/* 已按序交给 TLS 的偏移 */
	/* 在途包 */
	struct kdg_qc_sent sent[KDG_QC_SENT_MAX];
	u64 loss_time;			/* 时间阈值丢包判定时刻，0 为无 */
	u64 last_ack_eliciting_t;
};

struct kdg_qc {
	enum kdg_qc_state state;
	u64 err;			/* 关闭原因（传输错误码或 0x100+alert） */
	bool err_app;			/* err 是应用层错误码（H3） */
	bool peer_closed;

	/* 连接 ID */
	u8 scid[8];
	u8 dcid[KDG_QUIC_MAX_CID], dcid_len;	/* 当前对端 CID */
	u8 odcid[KDG_QUIC_MAX_CID], odcid_len;	/* 客户端首个 DCID（Initial 密钥种子） */
	bool dcid_from_server;			/* 已采纳服务器首个 SCID */
	u8 token[256];				/* Retry token */
	u16 token_len;
	bool retried;

	struct kdg_tls13 tls;
	struct kdg_qc_pnspace sp[QS_COUNT];
	struct kdg_qtp local;			/* 本端传输参数（原样保存） */
	struct kdg_qtp peer;
	bool peer_tp_ok;
	bool hs_confirmed;			/* 收到 HANDSHAKE_DONE */

	/* 流控 */
	u64 max_data_tx;			/* 对端允许本端发送的总量 */
	u64 data_sent;
	u64 max_data_rx;			/* 本端允许对端发送的总量 */
	u64 data_rx;
	bool send_max_data;
	u64 max_bidi_tx;			/* 对端允许本端开的双向流数 */
	u64 next_bidi;				/* 下一个本端双向流序号 */
	u64 next_uni;
	u64 peer_uni_seen;			/* 对端已开的单向流数（限 max_uni_rx） */

	struct kdg_qc_stream st[KDG_QC_MAX_STREAMS];

	/* 恢复与拥塞（RFC 9002，毫秒） */
	u64 srtt, rttvar, min_rtt, latest_rtt;
	bool have_rtt;
	u32 pto_count;
	u64 cwnd, ssthresh, bytes_in_flight, recovery_start;
	u64 idle_deadline;
	u64 close_deadline;
	u64 pto_deadline;			/* PTO 到期时刻 */
	u64 now;				/* 最近一次调用传入的时刻 */

	/* 待发的一次性帧 */
	bool send_close;
	bool send_path_resp;
	u8 path_resp[8];
	bool send_ping;
	u64 retire_cid_seq;
	bool send_retire;
};

/* tp：本端传输参数（调用方填 initial_* 等）；ca 可为 NULL（宿主测试用自签） */
int kdg_qc_init(struct kdg_qc *c, const char *host, const char *alpn,
		const struct kdg_qtp *tp, const mbedtls_x509_crt *ca,
		kdg_rng_fn rng, void *rng_ctx, u64 now);
void kdg_qc_fini(struct kdg_qc *c);

int kdg_qc_recv(struct kdg_qc *c, u8 *dgram, size_t len, u64 now);
size_t kdg_qc_send(struct kdg_qc *c, u8 *out, size_t cap, u64 now);
void kdg_qc_timeout(struct kdg_qc *c, u64 now);
u64 kdg_qc_next_timer(const struct kdg_qc *c);

/* 流接口。open 返回流 id（≥0）或负 errno；uni=true 开本端单向流。 */
s64 kdg_qc_stream_open(struct kdg_qc *c, bool uni);
int kdg_qc_stream_write(struct kdg_qc *c, u64 id, const u8 *data, size_t len,
			bool fin);
/* 读出可读数据。*fin 为真表示已读到流尾。返回读到的字节数或负 errno。 */
s64 kdg_qc_stream_read(struct kdg_qc *c, u64 id, u8 *out, size_t cap,
			   bool *fin);
/* 遍历有可读数据（或已结束/被重置）的对端流与本端双向流 */
int kdg_qc_stream_next_readable(struct kdg_qc *c, u64 *id, u32 *iter);
void kdg_qc_stream_free(struct kdg_qc *c, u64 id);

void kdg_qc_close(struct kdg_qc *c, u64 err, bool app);

#endif