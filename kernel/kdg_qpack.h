/* SPDX-License-Identifier: GPL-2.0 */
/*
 * kdg_qpack.h —— QPACK 的一小片（RFC 9204）：只够 DoH 请求/响应用。
 *
 * 有意不实现的：动态表、Post-Base 索引、被阻塞的流、字段段指令编码。
 * 我们在 SETTINGS 里申报 QPACK_MAX_TABLE_CAPACITY=0 且
 * QPACK_BLOCKED_STREAMS=0，因此对端**不得**用动态表引用；一旦用了就按
 * §4.5.1.1 判为解压失败，连接关掉（不做静默降级）。
 *
 * 静态表（RFC 9204 附录 A，99 项）是本文件的表。⚠️ 如实说明验证范围：
 * 只有解码响应时真正会依赖的那几项（:status 200=25、content-type
 * application/dns-message=44、以及作名引用用的 :authority=0、:path=1）
 * 由真机/真服务器对打验证过；其余项是照抄，尚未被任何真实服务器触发过。
 * 表项错位只会让那一行解错名值，不会破坏字段段的结构解析；而我们的逻辑
 * 只看 :status 与 content-type，故风险可控。
 */
#ifndef _KDG_QPACK_H
#define _KDG_QPACK_H

#include "kdg_base.h"

#define KDG_QPACK_STATIC_N	99
#define KDG_QPACK_MAX_FIELDS	32

struct kdg_qpack_field {
	const u8 *name;
	size_t name_len;
	const u8 *val;
	size_t val_len;
};

/* 解码器：解码出的字符串放在调用方给的工作缓冲里（避免每次分配）。 */
struct kdg_qpack_dec {
	u8 *buf;
	size_t cap;
	size_t used;
	size_t nfields;
};

void kdg_qpack_dec_init(struct kdg_qpack_dec *d, u8 *buf, size_t cap);
/* 解一个字段段（HEADERS 帧的载荷）。返回 0 或负 errno。 */
int kdg_qpack_decode(struct kdg_qpack_dec *d, const u8 *in, size_t inlen,
		     struct kdg_qpack_field *out, size_t max_fields);
/* 取已解出的字段；越界返回 NULL。 */
const struct kdg_qpack_field *kdg_qpack_dec_at(const struct kdg_qpack_dec *d,
					       const struct kdg_qpack_field *f,
					       size_t i);
/* 按名字查字段（区分大小写，HTTP/3 字段名一律小写）。 */
const struct kdg_qpack_field *kdg_qpack_find(const struct kdg_qpack_field *f,
					     size_t n, const char *name);

/* 静态表：index 越界返回 NULL。 */
const char *kdg_qpack_static_name(size_t idx);
const char *kdg_qpack_static_value(size_t idx);

/*
 * 编码一个 DoH POST 请求的字段段（:method POST + content-type
 * application/dns-message）。报文本身随后放在 DATA 帧里 —— 与既有 H2 路径
 * 同一形式，也省掉 base64url 编码。只用静态索引与名引用，不发 Huffman。
 */
int kdg_qpack_encode_post(u8 *out, size_t cap, const char *authority,
			  const char *path);

/* RFC 7541 §5.2 的 Huffman 表（与 H2/nghttp2 同一张），解码用生成表。 */
int kdg_qpack_huff_decode(const u8 *in, size_t inlen, u8 *out, size_t outcap,
			  size_t *outlen);

#endif
