/* SPDX-License-Identifier: GPL-2.0 */
/*
 * kdg_resolve.c —— 解析编排实现。设计见 kdg_resolve.h。
 */
#define pr_fmt(fmt)	KBUILD_MODNAME ": resolve: " fmt

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/timekeeping.h>
#include <linux/ktime.h>

#include "kdg.h"
#include "kdg_resolve.h"
#include "kdg_cache.h"
#include "kdg_cache_tab.h"
#include "kdg_wire.h"

static struct kdg_resolve_stats g_stat;

void kdg_resolve_get_stats(struct kdg_resolve_stats *out)
{
	if (out)
		*out = g_stat;
}

/*
 * 单调毫秒时钟，**含设备休眠时间**。
 *
 * 用 CLOCK_BOOTTIME 的等价物 ktime_get_boottime_ns 而不是 CLOCK_MONOTONIC：
 * 方案 §9.3 明确要求「避免设备睡了一小时却仍把旧缓存当作刚写入」。
 * MONOTONIC 在休眠期间不前进，用它会让缓存穿越一次长休眠仍然「新鲜」。
 * （mbedTLS 那边也是同一个选择，见 kdg_mbedtls.c 的 mbedtls_ms_time。）
 */
static inline u64 kdg_now_ms(void)
{
	return div_u64(ktime_get_boottime_ns(), NSEC_PER_MSEC);
}

/* 复制一份查询并把 ID 规范化为 0（方案 §6.3：上游 ID 规范为 0，
 * 用 stream ID / request cookie 关联，不按 16 位 DNS ID 索引）。 */
static u8 *kdg_query_normalized(const u8 *qwire, size_t qlen)
{
	u8 *p = kmemdup(qwire, qlen, GFP_KERNEL);

	if (p) {
		p[0] = 0;
		p[1] = 0;
	}
	return p;
}

/* 不可缓存路径的直通：仍然要走一次上游，但不查缓存、不写缓存。 */
static int kdg_resolve_passthrough(const struct kdg_resolve_req *req,
				   const u8 *qwire, size_t qlen,
				   u8 *rwire, size_t *rlen)
{
	u8 *norm;
	size_t nlen = *rlen;
	int ret;

	norm = kdg_query_normalized(qwire, qlen);
	if (!norm)
		return -ENOMEM;

	ret = kdg_doh_query(req->cfg, norm, qlen, rwire, &nlen);
	kfree(norm);
	if (ret)
		return ret;

	/* 只恢复 ID：这条路径没有模板，不做 TTL 改写（也没必要——
	 * 不缓存的响应 TTL 本来就是原值）。 */
	if (nlen >= 2) {
		rwire[0] = qwire[0];
		rwire[1] = qwire[1];
	}
	*rlen = nlen;
	return 0;
}

int kdg_resolve(const struct kdg_resolve_req *req,
		const u8 *qwire, size_t qlen,
		u8 *rwire, size_t *rlen,
		enum kdg_source *src)
{
	struct kdg_cache_key key;
	struct kdg_cache_tmpl view;
	struct kdg_query q;
	struct kdg_summary summary;
	void *pin = NULL;
	u8 *norm = NULL, *up = NULL;
	u16 offs[KDG_CACHE_MAX_TTL_OFF];
	size_t up_cap, up_len, out_len, caller_cap;
	u64 now;
	bool cacheable;
	u32 ttl_s;
	int n_ttl, ret, mk;

	if (!req || !req->cfg || !qwire || !rwire || !rlen || !src)
		return -EINVAL;

	g_stat.total++;
	caller_cap = *rlen;
	*src = KDG_SRC_UPSTREAM;

	/* ── 1. 有界校验调用方的查询（方案 §8：这是本模块唯一的报文入口）── */
	ret = kdg_wire_parse_query(qwire, qlen, &q);
	if (ret < 0) {
		pr_warn_ratelimited("查询未通过校验: %d\n", ret);
		g_stat.invalid_query++;
		return -EBADMSG;
	}

	/* ── 2. 构造缓存/合并键 ── */
	mk = kdg_cache_key_from_query(&q, req->net_id, req->profile_gen, &key);
	if (mk != KDG_CKE_OK) {
		g_stat.not_cacheable++;
		return kdg_resolve_passthrough(req, qwire, qlen, rwire, rlen);
	}

	/* ── 3. 查缓存 ── */
	now = kdg_now_ms();
	ret = kdg_cache_get(&key, now, &view, &pin);
	if (ret == 0) {
		int r = kdg_cache_repack(&view, now, qwire, qlen,
					 rwire, caller_cap, &out_len);

		kdg_cache_unpin(pin);
		pin = NULL;

		if (r == 0) {
			*rlen = out_len;
			*src = KDG_SRC_CACHE;
			g_stat.from_cache++;
			return 0;
		}
		/* 重封装失败（模板问题区被压缩等）：当作未命中继续走上游，
		 * 而不是把这个结构异常的条目回给调用方。 */
		pr_warn_ratelimited("缓存重封装失败 %d，改走上游\n", r);
	}

	/* ── 4. 上游 ── */
	norm = kdg_query_normalized(qwire, qlen);
	if (!norm)
		return -ENOMEM;

	up_cap = KDG_DOH_RX_MAX;
	up = kmalloc(up_cap, GFP_KERNEL);
	if (!up) {
		kfree(norm);
		return -ENOMEM;
	}

	up_len = up_cap;
	ret = kdg_doh_query(req->cfg, norm, qlen, up, &up_len);
	if (ret) {
		kfree(up);
		kfree(norm);
		return ret;
	}

	/* ── 5. 校验上游响应确实是对**本次规范化查询**的响应 ──
	 * 方案 §8：「拒绝跨上游身份跳转」。ID 已规范为 0，故拿规范化后的
	 * 查询去匹配，而不是调用方那份带自己 ID 的。 */
	ret = kdg_wire_match_response(norm, qlen, up, up_len, &summary);
	if (ret < 0) {
		pr_warn_ratelimited("上游响应未通过匹配校验: %d\n", ret);
		g_stat.invalid_response++;
		kfree(up);
		kfree(norm);
		return -EBADMSG;
	}
	kfree(norm);
	norm = NULL;

	g_stat.from_upstream++;

	/* ── 6. 回填缓存 ──
	 * 可缓存性由 kdg_wire_cacheable_ttl 决定，它已覆盖 §8 的全部规则：
	 * TC 截断、扩展 rcode、非 NOERROR/NXDOMAIN、TTL=0、负缓存上限等。 */
	ttl_s = kdg_wire_cacheable_ttl(&summary, true);
	cacheable = (ttl_s > 0);
	if (cacheable) {
		int pr = kdg_cache_put(&key, up, up_len, now,
				       ttl_s > (U32_MAX / 1000u) ? U32_MAX
							 : ttl_s * 1000u);

		if (pr == 0)
			g_stat.cache_put_ok++;
		else {
			g_stat.cache_put_fail++;
			/* 写不进缓存不是错误：本次照常回包，只是下次还得走上游。 */
		}
	} else {
		g_stat.not_cacheable++;
	}

	/* ── 7. 回包 ──
	 * 无论缓存与否，都要把 ID 与问题区换回调用方的那一份
	 * （方案 §7.2「每个调用方问题区原样保留」）。 */
	n_ttl = kdg_wire_collect_ttl_offs(up, up_len, offs,
					  KDG_CACHE_MAX_TTL_OFF);
	if (n_ttl >= 0) {
		struct kdg_cache_tmpl t;

		memset(&t, 0, sizeof(t));
		t.msg = up;
		t.msg_len = (u16)up_len;
		t.qname_off = KDG_DNS_HDR_LEN;
		t.qname_len = q.qname.len;
		t.ttl_offs = offs;
		t.n_ttl = (u16)n_ttl;
		t.stored_ms = 0;
		t.ttl_ms = U32_MAX;	/* 本次立即使用，不做新鲜度判定 */

		ret = kdg_cache_repack(&t, 0, qwire, qlen, rwire, caller_cap,
				       &out_len);
		if (ret == 0) {
			*rlen = out_len;
			kfree(up);
			return 0;
		}
	}

	/* 退路：上游把问题区压缩了（少见但合法），逐字节替换做不了。
	 * 此时只恢复 ID、原样回传响应 —— 不能让调用方因为服务端的一种
	 * 合法编码而拿不到答案。 */
	if (up_len > caller_cap) {
		kfree(up);
		return -EMSGSIZE;
	}
	memcpy(rwire, up, up_len);
	if (up_len >= 2) {
		rwire[0] = qwire[0];
		rwire[1] = qwire[1];
	}
	*rlen = up_len;
	pr_warn_ratelimited("上游问题区不可逐字节替换，已退化为仅恢复 ID\n");
	kfree(up);
	return 0;
}
