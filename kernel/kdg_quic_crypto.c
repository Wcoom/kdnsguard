// SPDX-License-Identifier: GPL-2.0
/*
 * kdg_quic_crypto.c —— QUIC 包保护（RFC 9001 §5），双态可编译。
 *
 * 对照点：
 *   §5.1  HKDF-Expand-Label 派生 key/iv/hp（标签 "quic key/iv/hp"）
 *   §5.2  Initial secret = HKDF-Extract(initial_salt, DCID)
 *   §5.3  AEAD nonce = iv XOR 左补零的包号
 *   §5.4  头部保护：AES-ECB 或 ChaCha20 对 16 字节样本生成掩码
 */
#include "kdg_quic_crypto.h"

#ifndef __KERNEL__
#include <errno.h>
#endif

#include <mbedtls/hkdf.h>
#include <mbedtls/md.h>
#include <mbedtls/chacha20.h>
#include <mbedtls/platform_util.h>

/* RFC 9001 §5.2 QUIC v1 initial_salt。 */
static const u8 kdg_quic_v1_salt[20] = {
	0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17,
	0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a,
};

int kdg_quic_hkdf_expand_label(const u8 *secret, size_t secret_len,
			       const char *label, const u8 *ctx, size_t ctx_len,
			       u8 *out, size_t out_len)
{
	/* HkdfLabel = u16 length || u8 len || "tls13 " label || u8 len || ctx */
	u8 info[2 + 1 + 6 + 32 + 1 + 64];
	size_t llen = strlen(label), n = 0;

	if (llen > 32 || ctx_len > 64 || out_len > 0xffff)
		return -EINVAL;
	info[n++] = (u8)(out_len >> 8);
	info[n++] = (u8)out_len;
	info[n++] = (u8)(6 + llen);
	memcpy(info + n, "tls13 ", 6);
	n += 6;
	memcpy(info + n, label, llen);
	n += llen;
	info[n++] = (u8)ctx_len;
	if (ctx_len)
		memcpy(info + n, ctx, ctx_len);
	n += ctx_len;

	if (mbedtls_hkdf_expand(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256),
				secret, secret_len, info, n, out, out_len))
		return -EIO;
	return 0;
}

static size_t kdg_quic_key_len(enum kdg_quic_suite s)
{
	return s == KDG_QUIC_AES128GCM ? 16 : 32;
}

int kdg_quic_keys_from_secret(struct kdg_quic_keys *k, enum kdg_quic_suite s,
			      const u8 *secret)
{
	size_t kl = kdg_quic_key_len(s);
	int ret;

	memset(k, 0, sizeof(*k));
	k->suite = s;
	memcpy(k->secret, secret, KDG_QUIC_SECRET_LEN);

	ret = kdg_quic_hkdf_expand_label(secret, KDG_QUIC_SECRET_LEN,
					 "quic key", NULL, 0, k->key, kl);
	if (!ret)
		ret = kdg_quic_hkdf_expand_label(secret, KDG_QUIC_SECRET_LEN,
						 "quic iv", NULL, 0, k->iv,
						 KDG_QUIC_IV_LEN);
	if (!ret)
		ret = kdg_quic_hkdf_expand_label(secret, KDG_QUIC_SECRET_LEN,
						 "quic hp", NULL, 0, k->hp, kl);
	if (ret)
		goto fail;

	if (s == KDG_QUIC_AES128GCM) {
		mbedtls_gcm_init(&k->aead.gcm);
		mbedtls_aes_init(&k->hp_aes);
		if (mbedtls_gcm_setkey(&k->aead.gcm, MBEDTLS_CIPHER_ID_AES,
				       k->key, 128) ||
		    mbedtls_aes_setkey_enc(&k->hp_aes, k->hp, 128)) {
			mbedtls_gcm_free(&k->aead.gcm);
			mbedtls_aes_free(&k->hp_aes);
			ret = -EIO;
			goto fail;
		}
	} else {
		mbedtls_chachapoly_init(&k->aead.cp);
		if (mbedtls_chachapoly_setkey(&k->aead.cp, k->key)) {
			mbedtls_chachapoly_free(&k->aead.cp);
			ret = -EIO;
			goto fail;
		}
	}
	k->ready = true;
	return 0;
fail:
	mbedtls_platform_zeroize(k, sizeof(*k));
	return ret;
}

void kdg_quic_keys_free(struct kdg_quic_keys *k)
{
	if (!k->ready)
		return;
	if (k->suite == KDG_QUIC_AES128GCM) {
		mbedtls_gcm_free(&k->aead.gcm);
		mbedtls_aes_free(&k->hp_aes);
	} else {
		mbedtls_chachapoly_free(&k->aead.cp);
	}
	mbedtls_platform_zeroize(k, sizeof(*k));
}

int kdg_quic_initial_keys(const u8 *dcid, size_t dcid_len,
			  struct kdg_quic_keys *client,
			  struct kdg_quic_keys *server)
{
	u8 initial[KDG_QUIC_SECRET_LEN], cs[KDG_QUIC_SECRET_LEN],
	   ss[KDG_QUIC_SECRET_LEN];
	int ret;

	if (dcid_len > KDG_QUIC_MAX_CID)
		return -EINVAL;
	if (mbedtls_hkdf_extract(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256),
				 kdg_quic_v1_salt, sizeof(kdg_quic_v1_salt),
				 dcid, dcid_len, initial))
		return -EIO;
	ret = kdg_quic_hkdf_expand_label(initial, sizeof(initial), "client in",
					 NULL, 0, cs, sizeof(cs));
	if (!ret)
		ret = kdg_quic_hkdf_expand_label(initial, sizeof(initial),
						 "server in", NULL, 0, ss,
						 sizeof(ss));
	if (!ret)
		ret = kdg_quic_keys_from_secret(client, KDG_QUIC_AES128GCM, cs);
	if (!ret) {
		ret = kdg_quic_keys_from_secret(server, KDG_QUIC_AES128GCM, ss);
		if (ret)
			kdg_quic_keys_free(client);
	}
	mbedtls_platform_zeroize(initial, sizeof(initial));
	mbedtls_platform_zeroize(cs, sizeof(cs));
	mbedtls_platform_zeroize(ss, sizeof(ss));
	return ret;
}

/* §5.3：nonce = iv XOR (包号左补零到 12 字节)。 */
static void kdg_quic_nonce(const struct kdg_quic_keys *k, u64 pn, u8 *nonce)
{
	int i;

	memcpy(nonce, k->iv, KDG_QUIC_IV_LEN);
	for (i = 0; i < 8; i++)
		nonce[KDG_QUIC_IV_LEN - 1 - i] ^= (u8)(pn >> (8 * i));
}

/* §5.4.3 / §5.4.4：由 16 字节样本生成 5 字节掩码。 */
static int kdg_quic_hp_mask(struct kdg_quic_keys *k, const u8 *sample,
			    u8 *mask)
{
	if (k->suite == KDG_QUIC_AES128GCM) {
		u8 out[16];

		if (mbedtls_aes_crypt_ecb(&k->hp_aes, MBEDTLS_AES_ENCRYPT,
					  sample, out))
			return -EIO;
		memcpy(mask, out, 5);
		return 0;
	} else {
		static const u8 zero[5];
		u32 ctr = (u32)sample[0] | (u32)sample[1] << 8 |
			  (u32)sample[2] << 16 | (u32)sample[3] << 24;

		if (mbedtls_chacha20_crypt(k->hp, sample + 4, ctr, 5, zero,
					   mask))
			return -EIO;
		return 0;
	}
}

/* 对首字节与包号字段施加/去除掩码（异或，自逆）。 */
static void kdg_quic_hp_apply(u8 *buf, size_t pn_off, size_t pn_len,
			      const u8 *mask)
{
	size_t i;

	buf[0] ^= mask[0] & ((buf[0] & 0x80) ? 0x0f : 0x1f);
	for (i = 0; i < pn_len; i++)
		buf[pn_off + i] ^= mask[1 + i];
}

int kdg_quic_protect(struct kdg_quic_keys *k, u64 pn, u8 *buf,
		     size_t pn_off, size_t pn_len, size_t hdr_len,
		     size_t pt_len, size_t cap)
{
	u8 nonce[KDG_QUIC_IV_LEN], mask[5];
	size_t total = hdr_len + pt_len + KDG_QUIC_TAG_LEN;
	u8 *p = buf + hdr_len;
	int ret;

	if (!k->ready || pn_len < 1 || pn_len > 4 ||
	    pn_off + pn_len != hdr_len || total > cap)
		return -EINVAL;
	/* 样本取自包号起点后 4 字节（§5.4.2），必须完全落在密文+标签里；
	 * 载荷过短时由调用方补 PADDING 帧。 */
	if (pn_off + 4 + KDG_QUIC_HP_SAMPLE > total)
		return -EINVAL;

	kdg_quic_nonce(k, pn, nonce);
	if (k->suite == KDG_QUIC_AES128GCM)
		ret = mbedtls_gcm_crypt_and_tag(&k->aead.gcm, MBEDTLS_GCM_ENCRYPT,
						pt_len, nonce, sizeof(nonce),
						buf, hdr_len, p, p,
						KDG_QUIC_TAG_LEN, p + pt_len);
	else
		ret = mbedtls_chachapoly_encrypt_and_tag(&k->aead.cp, pt_len,
							 nonce, buf, hdr_len,
							 p, p, p + pt_len);
	if (ret)
		return -EIO;

	ret = kdg_quic_hp_mask(k, buf + pn_off + 4, mask);
	if (ret)
		return ret;
	kdg_quic_hp_apply(buf, pn_off, pn_len, mask);
	return (int)total;
}

/* RFC 9000 附录 A.3：由截断包号与已收最大包号恢复完整包号。 */
static u64 kdg_quic_decode_pn(s64 largest, u64 truncated, size_t pn_len)
{
	s64 expected = largest + 1;
	s64 win = (s64)1 << (pn_len * 8);
	s64 hwin = win / 2;
	s64 cand = (expected & ~(win - 1)) | (s64)truncated;

	if (cand <= expected - hwin && cand < ((s64)1 << 62) - win)
		return (u64)(cand + win);
	if (cand > expected + hwin && cand >= win)
		return (u64)(cand - win);
	return (u64)cand;
}

int kdg_quic_unprotect(struct kdg_quic_keys *k, u8 *buf, size_t pn_off,
		       size_t pkt_len, s64 largest_pn, u64 *pn,
		       size_t *hdr_len)
{
	u8 nonce[KDG_QUIC_IV_LEN], mask[5];
	size_t pn_len, hl, ct_len, i;
	u64 trunc = 0;
	u8 *p;
	int ret;

	if (!k->ready || pn_off + 4 + KDG_QUIC_HP_SAMPLE > pkt_len)
		return -EINVAL;
	ret = kdg_quic_hp_mask(k, buf + pn_off + 4, mask);
	if (ret)
		return ret;

	buf[0] ^= mask[0] & ((buf[0] & 0x80) ? 0x0f : 0x1f);
	pn_len = (buf[0] & 0x03) + 1;
	for (i = 0; i < pn_len; i++) {
		buf[pn_off + i] ^= mask[1 + i];
		trunc = trunc << 8 | buf[pn_off + i];
	}
	hl = pn_off + pn_len;
	if (hl + KDG_QUIC_TAG_LEN > pkt_len) {
		ret = -EBADMSG;
		goto fail;
	}
	ct_len = pkt_len - hl - KDG_QUIC_TAG_LEN;
	*pn = kdg_quic_decode_pn(largest_pn, trunc, pn_len);

	kdg_quic_nonce(k, *pn, nonce);
	p = buf + hl;
	if (k->suite == KDG_QUIC_AES128GCM)
		ret = mbedtls_gcm_auth_decrypt(&k->aead.gcm, ct_len, nonce,
					       sizeof(nonce), buf, hl,
					       p + ct_len, KDG_QUIC_TAG_LEN,
					       p, p);
	else
		ret = mbedtls_chachapoly_auth_decrypt(&k->aead.cp, ct_len,
						      nonce, buf, hl,
						      p + ct_len, p, p);
	if (ret) {
		ret = -EBADMSG;
		goto fail;
	}
	*hdr_len = hl;
	return (int)ct_len;

fail:
	/*
	 * 失败后缓冲区内容**未定义**，调用方只能丢弃或用事先拷贝的副本重试。
	 * 曾经承诺「失败时还原头部」，宿主测试证伪了它：错误密钥会解出错误的
	 * pn_len ⇒ 明文起点 hl 跟着错 ⇒ mbedtls 的 auth_decrypt 在标签不符时
	 * 把 [hl, hl+ct_len) 清零，这段会盖住真实的包号字段。
	 */
	return ret;
}