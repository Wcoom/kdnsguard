/* SPDX-License-Identifier: GPL-2.0 */
/*
 * kdg_http.c —— 有界 HTTP/1.1 响应解析。设计与约束见 kdg_http.h。
 *
 * 纪律：本文件必须保持双态可编译，只用 kdg_base.h 提供的原语。
 */
#include "kdg_http.h"

/* ── 小工具 ──────────────────────────────────────────────────────────── */

static inline u8 lower(u8 c)
{
	return (c >= 'A' && c <= 'Z') ? (u8)(c + 32) : c;
}

/* 大小写不敏感比较：n 为待比较长度，字面量以 NUL 结尾。 */
static bool ci_eq(const u8 *a, size_t alen, const char *b)
{
	size_t i;

	for (i = 0; i < alen; i++) {
		if (b[i] == '\0')
			return false;
		if (lower(a[i]) != lower((u8)b[i]))
			return false;
	}
	return b[alen] == '\0';
}

static bool is_digit(u8 c)
{
	return c >= '0' && c <= '9';
}

static bool is_ows(u8 c)
{
	return c == ' ' || c == '\t';
}

/* 定位头部结束（\r\n\r\n 之后的首字节）。返回 0 表示尚未收全。
 * 只认 \r\n\r\n：裸 \n\n 不是合法 HTTP 分帧，接受它等于放宽了协议。 */
static size_t find_head_end(const u8 *buf, size_t len)
{
	size_t i;

	if (len < 4)
		return 0;

	for (i = 0; i + 3 < len; i++) {
		if (buf[i] == '\r' && buf[i + 1] == '\n' &&
		    buf[i + 2] == '\r' && buf[i + 3] == '\n')
			return i + 4;
	}
	return 0;
}

/* 头部内一行的边界：返回该行内容结束（不含 CRLF）的偏移，失败返回 0。 */
static size_t line_end(const u8 *buf, size_t start, size_t head_end,
		       size_t *next)
{
	size_t i = start;

	while (i + 1 < head_end) {
		if (buf[i] == '\r' && buf[i + 1] == '\n') {
			*next = i + 2;
			return i;
		}
		i++;
	}
	return 0;
}

/* ── 响应头解析 ──────────────────────────────────────────────────────── */

int kdg_http_parse_response_head(const u8 *buf, size_t len,
				 struct kdg_http_response *out)
{
	size_t head_end;
	size_t pos, line_stop, next;
	size_t status_off;
	u16 count = 0;

	if (!buf || !out)
		return KDG_H_EFORMAT;

	memset(out, 0, sizeof(*out));
	out->status = -1;

	head_end = find_head_end(buf, len);
	if (head_end == 0) {
		/* 还没收全 vs 已经太长：后者必须尽早拒绝，否则头部洪泛
		 * 会把接收缓冲填满。 */
		if (len >= KDG_HTTP_MAX_HEAD)
			return KDG_H_ETOOLONG;
		return KDG_H_NEED_MORE;
	}
	if (head_end > KDG_HTTP_MAX_HEAD)
		return KDG_H_ETOOLONG;
	if (head_end > 0xffffu)
		return KDG_H_ETOOLONG;

	/* ── 状态行：HTTP/1.x SP 3DIGIT [SP reason] CRLF ──
	 * 只接受 1.x。0.9 没有状态行、2/3 是二进制帧，都不能当文本解析。 */
	line_stop = line_end(buf, 0, head_end, &next);
	if (line_stop == 0)
		return KDG_H_EFORMAT;
	if (line_stop > KDG_HTTP_MAX_LINE)
		return KDG_H_ETOOLONG;
	if (line_stop < 12)
		return KDG_H_EVERSION;
	if (memcmp(buf, "HTTP/1.", 7) != 0)
		return KDG_H_EVERSION;
	if (buf[7] != '0' && buf[7] != '1')
		return KDG_H_EVERSION;
	out->http11 = (buf[7] == '1');
	if (buf[8] != ' ')
		return KDG_H_EVERSION;

	status_off = 9;
	if (status_off + 3 > line_stop)
		return KDG_H_ESTATUS;
	if (!is_digit(buf[status_off]) || !is_digit(buf[status_off + 1]) ||
	    !is_digit(buf[status_off + 2]))
		return KDG_H_ESTATUS;
	/* 第 4 个字符必须是分隔或行尾，否则 "2000" 会被误读成 200。 */
	if (status_off + 3 < line_stop && buf[status_off + 3] != ' ')
		return KDG_H_ESTATUS;

	out->status = (buf[status_off] - '0') * 100 +
		      (buf[status_off + 1] - '0') * 10 +
		      (buf[status_off + 2] - '0');

	/* ── 逐行扫头部 ── */
	pos = next;
	while (pos < head_end) {
		size_t colon = (size_t)-1;
		size_t i;
		size_t name_len, val_start, val_end;

		line_stop = line_end(buf, pos, head_end, &next);
		if (line_stop == 0)
			return KDG_H_EFORMAT;
		if (line_stop - pos > KDG_HTTP_MAX_LINE)
			return KDG_H_ETOOLONG;

		/* 空行即头部结束（find_head_end 已保证它就在末尾）。 */
		if (line_stop == pos)
			break;

		for (i = pos; i < line_stop; i++) {
			if (buf[i] == ':') {
				colon = i;
				break;
			}
			/* 遵循 RFC 9110：字段名是 token，且冒号前不得有空白。
			 * 容忍空白会造成「Content-Length : 5」这类走私手法。 */
			if (is_ows(buf[i]))
				return KDG_H_EFORMAT;
		}
		if (colon == (size_t)-1)
			return KDG_H_EFORMAT;

		name_len = colon - pos;
		if (name_len == 0)
			return KDG_H_EFORMAT;

		val_start = colon + 1;
		while (val_start < line_stop && is_ows(buf[val_start]))
			val_start++;
		val_end = line_stop;
		while (val_end > val_start && is_ows(buf[val_end - 1]))
			val_end--;

		count++;

		if (ci_eq(buf + pos, name_len, "content-length")) {
			u32 v = 0;
			size_t k;
			bool ok = true;

			if (val_end == val_start || val_end - val_start > 10)
				return KDG_H_EFORMAT;
			for (k = val_start; k < val_end; k++) {
				if (!is_digit(buf[k])) {
					ok = false;
					break;
				}
				v = v * 10 + (u32)(buf[k] - '0');
			}
			if (!ok)
				return KDG_H_EFORMAT;
			out->has_content_length = true;
			out->content_length = v;
		} else if (ci_eq(buf + pos, name_len, "transfer-encoding")) {
			/* 只支持纯 chunked。任何其它取值（含 gzip 之外的
			 * 扩展、或多个编码串联）一律拒绝——不做「尽力而为」。 */
			if (!ci_eq(buf + val_start, val_end - val_start, "chunked"))
				return KDG_H_EFORMAT;
			out->chunked = true;
		} else if (ci_eq(buf + pos, name_len, "content-type")) {
			size_t vlen = val_end - val_start;

			out->content_type_off = (u16)val_start;
			out->content_type_len = (u16)vlen;
			/* 允许带参数（如 "; charset=..."），只比主类型。 */
			if (vlen >= 23 &&
			    ci_eq(buf + val_start, 23, "application/dns-message"))
				out->ctype_is_dns = true;
		} else if (ci_eq(buf + pos, name_len, "connection")) {
			if (ci_eq(buf + val_start, val_end - val_start, "close"))
				out->connection_close = true;
		}

		pos = next;
	}

	out->hdr_end = (u16)head_end;
	out->nheaders = count;
	return KDG_H_OK;
}

int kdg_http_header_get(const u8 *buf, u16 hdr_end, const char *name,
			const u8 **val, size_t *vlen)
{
	size_t pos, line_stop, next;
	size_t first_stop;

	if (!buf || !name || !val || !vlen)
		return KDG_H_EFORMAT;

	/* 跳过状态行 */
	first_stop = line_end(buf, 0, hdr_end, &next);
	if (first_stop == 0)
		return KDG_H_EFORMAT;
	pos = next;

	while (pos < hdr_end) {
		size_t colon = (size_t)-1;
		size_t i, name_len, vs, ve;

		line_stop = line_end(buf, pos, hdr_end, &next);
		if (line_stop == 0 || line_stop == pos)
			break;

		for (i = pos; i < line_stop; i++) {
			if (buf[i] == ':') {
				colon = i;
				break;
			}
		}
		if (colon == (size_t)-1)
			break;

		name_len = colon - pos;
		if (ci_eq(buf + pos, name_len, name)) {
			vs = colon + 1;
			while (vs < line_stop && is_ows(buf[vs]))
				vs++;
			ve = line_stop;
			while (ve > vs && is_ows(buf[ve - 1]))
				ve--;
			*val = buf + vs;
			*vlen = ve - vs;
			return KDG_H_OK;
		}
		pos = next;
	}

	return KDG_H_ENOENT;
}

unsigned int kdg_http_count_header(const u8 *buf, u16 hdr_end,
				   const char *name)
{
	size_t pos, line_stop, next;
	size_t first_stop;
	unsigned int n = 0;

	if (!buf || !name)
		return 0;

	first_stop = line_end(buf, 0, hdr_end, &next);
	if (first_stop == 0)
		return 0;
	pos = next;

	while (pos < hdr_end) {
		size_t colon = (size_t)-1;
		size_t i;

		line_stop = line_end(buf, pos, hdr_end, &next);
		if (line_stop == 0 || line_stop == pos)
			break;

		for (i = pos; i < line_stop; i++) {
			if (buf[i] == ':') {
				colon = i;
				break;
			}
		}
		if (colon == (size_t)-1)
			break;

		if (ci_eq(buf + pos, colon - pos, name))
			n++;

		pos = next;
	}
	return n;
}

/* ── chunked 解码 ────────────────────────────────────────────────────── */

int kdg_http_chunk_decode(const u8 *in, size_t inlen,
			  u8 *out, size_t outcap, size_t *outlen)
{
	size_t ip = 0, op = 0;

	if (!in || !out || !outlen)
		return KDG_H_EFORMAT;

	*outlen = 0;

	for (;;) {
		u32 chunk = 0;
		size_t digits = 0;
		bool any = false;

		/* chunk-size [;ext] CRLF */
		for (;;) {
			u8 c;

			if (ip >= inlen)
				return KDG_H_NEED_MORE;
			c = in[ip];

			if (c == '\r') {
				if (ip + 1 >= inlen)
					return KDG_H_NEED_MORE;
				if (in[ip + 1] != '\n')
					return KDG_H_EFORMAT;
				ip += 2;
				break;
			}
			if (c == ';') {
				/* 丢弃 chunk-ext 直到行尾 */
				while (ip < inlen && in[ip] != '\r')
					ip++;
				if (ip >= inlen)
					return KDG_H_NEED_MORE;
				continue;
			}
			if (!any && c == ' ') {
				/* 允许前导空白（防守性；严格实现不该发） */
				ip++;
				continue;
			}
			if (c >= '0' && c <= '9') {
				chunk = chunk * 16 + (u32)(c - '0');
			} else if (c >= 'a' && c <= 'f') {
				chunk = chunk * 16 + (u32)(c - 'a' + 10);
			} else if (c >= 'A' && c <= 'F') {
				chunk = chunk * 16 + (u32)(c - 'A' + 10);
			} else {
				return KDG_H_EFORMAT;
			}
			any = true;
			if (++digits > 8)
				return KDG_H_ETOOLONG;
			ip++;
		}
		if (!any)
			return KDG_H_EFORMAT;

		if (chunk == 0) {
			/* 末尾块之后：trailer 段 + 空行。整体丢弃 trailer，
			 * 但必须把分帧走完，否则会把 trailer 当正文。 */
			for (;;) {
				size_t ls = 0, nx = 0;
				{
					size_t i = ip;
					bool found = false;

					while (i + 1 < inlen) {
						if (in[i] == '\r' &&
						    in[i + 1] == '\n') {
							ls = i;
							nx = i + 2;
							found = true;
							break;
						}
						i++;
					}
					if (!found)
						return KDG_H_NEED_MORE;
				}
				if (ls == ip) {
					/* 空行：trailer 结束，正文完成 */
					*outlen = op;
					return KDG_H_OK;
				}
				ip = nx;
			}
		}

		if (op + chunk > outcap)
			return KDG_H_ENOSPC;
		if (ip + chunk > inlen)
			return KDG_H_NEED_MORE;

		memcpy(out + op, in + ip, chunk);
		op += chunk;
		ip += chunk;

		if (ip + 1 >= inlen)
			return KDG_H_NEED_MORE;
		if (in[ip] != '\r' || in[ip + 1] != '\n')
			return KDG_H_EFORMAT;
		ip += 2;
	}
}
