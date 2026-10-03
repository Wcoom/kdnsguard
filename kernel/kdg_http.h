/* SPDX-License-Identifier: GPL-2.0 */
/*
 * kdg_http.h —— 有界 HTTP/1.1 响应解析（DoH 用）。
 *
 * 为什么单独一份、而且做成双态可编译：HTTP 报文解析和 DNS wire 解析一样，
 * 是「全部风险都在边界条件上」的代码 —— 缺 \r\n、长度撒谎、chunked 分块
 * 越界、头部大小写、重复头、超长行。这类代码不跑几百条语料等于没验证，
 * 而本内核 CONFIG_KUNIT=m 导致设备构建里跑不了 KUnit 用例（见 kdg_wire.h）。
 *
 * 本阶段只解析**响应头**与正文分帧；不做 HTTP/2、不做请求队列、不做
 * 连接池。方案 §6.4 说 H1 是「先导与兼容路径」，并计划用 llhttp 做增量
 * 解析 —— P2 会用它替换本文件。在那之前，这里是一份**故意写得很保守**的
 * 实现：宁可拒收可疑响应，也不做「尽力而为」的容错。
 *
 * 三条不可让步的性质（与 kdg_wire 一致）：
 *  1. 有界：任何输入长度下读取都不越界，不存在无界循环。
 *  2. 不分配：状态全在调用者的结构体里。
 *  3. 不信任声明：Content-Length 只是「声明值」，实际读取以真实到达的字节
 *     为准并由上层封顶；声称 4 GB 的响应不会被预分配。
 */
#ifndef _KDG_HTTP_H
#define _KDG_HTTP_H

#include "kdg_base.h"

/* 单条响应头部的上限。DoH 响应头通常 < 1 KB；给到 8 KB 是为了容纳
 * 冗长的 Set-Cookie/Server 字段，超出即拒绝（防头部洪泛）。 */
#define KDG_HTTP_MAX_HEAD	8192

/* 单个头的行上限，防一行超长撑爆扫描。 */
#define KDG_HTTP_MAX_LINE	4096

struct kdg_http_response {
	int  status;			/* HTTP 状态码，例如 200 */
	u16  hdr_end;			/* 正文起始偏移（= 头部总长） */
	u16  content_type_off;		/* 便于诊断，不改写 */
	u16  content_type_len;
	bool http11;			/* 状态行是否 HTTP/1.1 */
	bool chunked;			/* Transfer-Encoding: chunked */
	bool has_content_length;
	u32  content_length;		/* 仅在 has_content_length 时有意义 */
	bool connection_close;
	bool ctype_is_dns;		/* Content-Type 是 application/dns-message */
	u16  nheaders;			/* 解析到的头数量（含重复） */
};

/*
 * 解析响应头。要求 buf 中**已经包含完整的头部**（即能找到 \r\n\r\n）。
 * 若尚未收全，返回 KDG_H_NEED_MORE，调用方继续收。
 */
#define KDG_H_OK		0
#define KDG_H_NEED_MORE		1	/* 头部未收全（非错误，继续读） */
#define KDG_H_EFORMAT		(-1)	/* 结构非法 */
#define KDG_H_ETOOLONG		(-2)	/* 头部/行长超限 */
#define KDG_H_EVERSION		(-3)	/* 不是 HTTP/1.x */
#define KDG_H_ESTATUS		(-4)	/* 状态码非法或非 3 位数字 */
#define KDG_H_ENOSPC		(-5)	/* 输出缓冲区不足 */
#define KDG_H_ENOENT		(-6)	/* 指定的头字段不存在 */

int kdg_http_parse_response_head(const u8 *buf, size_t len,
				 struct kdg_http_response *out);

/*
 * 大小写不敏感地取一个头字段的值（不含首尾空白，已 trim）。
 * 重复头取**第一处** —— 对 Content-Length 而言，重复出现本身应按非法处理，
 * 由调用方通过 kdg_http_count_header() 判断。
 * 返回 KDG_H_OK 表示找到，KDG_H_ENOENT 表示没有。
 */
int kdg_http_header_get(const u8 *buf, u16 hdr_end, const char *name,
			const u8 **val, size_t *vlen);

/* 统计某头字段出现次数（用于检测重复的 Content-Length / Transfer-Encoding）。 */
unsigned int kdg_http_count_header(const u8 *buf, u16 hdr_end,
				   const char *name);

/*
 * chunked 正文解码。把 in[0..inlen) 解码进 out（容量 outcap）。
 * 返回 0 或负错误；*outlen 回填实际产出。
 * 若最后一个块尚未到达，返回 KDG_H_NEED_MORE（调用方继续读）。
 * 结尾必须出现 0 长度块；尾部 trailer 一律丢弃（我们不使用任何 trailer）。
 */
int kdg_http_chunk_decode(const u8 *in, size_t inlen,
			  u8 *out, size_t outcap, size_t *outlen);

#endif /* _KDG_HTTP_H */
