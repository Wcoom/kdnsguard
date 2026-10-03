/* SPDX-License-Identifier: GPL-2.0 */
/*
 * kdg_psa_probe.c —— PSA 密码学子系统的直探针（**排障用，问题定位后可整体删除**）。
 *
 * 单独成文件的理由：本文件只做诊断、不参与功能，隔离出来便于随手删掉，
 * 也避免用脚本改主文件时误伤（此前正因为在 kdg_tls.c 里做区间替换而删掉了
 * 三个函数）。
 *
 * 它解决什么问题：TLS 1.3 的 ECDHE 走 PSA，而 mbedTLS 把 PSA 的原始状态码
 * **翻译**成自己的错误码后才上报（psa_util.c 的 psa_to_ssl_errors[]），
 * 内核日志里只剩一个笼统的 -0x7100，看不出 PSA 那边到底怎么了。
 * 这里绕过翻译层，逐项打印**原始** PSA 状态码。
 */
#define pr_fmt(fmt)	KBUILD_MODNAME ": PSA 探针: " fmt

/*
 * ⚠️ include 顺序有意为之：**内核头必须全部拉完，再拉 PSA**。
 *
 * psa/crypto.h 会 include libc 风格的 <stddef.h>/<stdint.h>，而这两个名字
 * 在我们的 shim 里被映射成内核头 + 冲突清理。清理里有一条 `#undef current`
 * （为了 mbedTLS 的 constant_time.c 能用 current 当局部变量名）。
 * 若在那之后再拉 include/linux/mm.h，它的内联函数就找不到 current 了。
 * include guard 保证先拉的内核头不会被二次处理，故顺序一换即可。
 */
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/slab.h>

#include "kdg.h"

/*
 * ⚠️ 仅本文件定义 MBEDTLS_ALLOW_PRIVATE_ACCESS。
 *
 * 它只影响 MBEDTLS_PRIVATE(x) 展开成 x 还是 private_##x —— **结构体布局完全相同**，
 * C 不把成员名编进 ABI，因此本翻译单元与库的其它翻译单元混用是安全的。
 * 但它绝不该定义在库或主代码里，故只出现在这个排障文件中。
 */
#define MBEDTLS_ALLOW_PRIVATE_ACCESS

#include <psa/crypto.h>
#include <mbedtls/ecp.h>

/* 用公开 PSA API 做 ECP 的 RNG 回调：mbedtls_psa_get_random 在库私有头里，
 * 而本文件不该去依赖库内部符号。 */
static int probe_rng(void *ctx, unsigned char *out, size_t len)
{
	(void)ctx;
	return psa_generate_random(out, len) == PSA_SUCCESS ? 0 : -1;
}

static const char *psa_str(psa_status_t st)
{
	switch (st) {
	case PSA_SUCCESS:                    return "SUCCESS";
	case PSA_ERROR_GENERIC_ERROR:        return "GENERIC_ERROR";
	case PSA_ERROR_NOT_SUPPORTED:        return "NOT_SUPPORTED";
	case PSA_ERROR_INVALID_ARGUMENT:     return "INVALID_ARGUMENT";
	case PSA_ERROR_INVALID_HANDLE:       return "INVALID_HANDLE";
	case PSA_ERROR_BAD_STATE:            return "BAD_STATE";
	case PSA_ERROR_BUFFER_TOO_SMALL:     return "BUFFER_TOO_SMALL";
	case PSA_ERROR_ALREADY_EXISTS:       return "ALREADY_EXISTS";
	case PSA_ERROR_DOES_NOT_EXIST:       return "DOES_NOT_EXIST";
	case PSA_ERROR_NOT_PERMITTED:        return "NOT_PERMITTED";
	default:                             return "?";
	}
}

/*
 * 单变量对照：曲线固定 X25519，**只改 usage 标志**。
 * 上一轮同时改了曲线与标志，无法归因。
 * 结果若两格一致，说明 usage 不是变量；若不一致，说明问题就在策略判定。
 */
static void probe_usage_variants(void)
{
	psa_key_attributes_t attr;
	mbedtls_svc_key_id_t key;
	u8 pub[128];
	size_t publen;
	psa_status_t st;
	int i;

	for (i = 0; i < 2; i++) {
		psa_key_usage_t usage = i ? (PSA_KEY_USAGE_DERIVE |
					     PSA_KEY_USAGE_EXPORT)
					  : PSA_KEY_USAGE_DERIVE;

		key = MBEDTLS_SVC_KEY_ID_INIT;
		attr = psa_key_attributes_init();
		psa_set_key_usage_flags(&attr, usage);
		psa_set_key_algorithm(&attr, PSA_ALG_ECDH);
		psa_set_key_type(&attr,
				 PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_MONTGOMERY));
		psa_set_key_bits(&attr, 255);

		st = psa_generate_key(&attr, &key);
		pr_info("usage=0x%x generate=%d(%s)\n", (unsigned)usage,
			(int)st, psa_str(st));
		if (st != PSA_SUCCESS)
			continue;

		/* 同一个密钥上连调两次：区分「首次调用有状态问题」与
		 * 「该密钥/该标志本身不可导出」。 */
		publen = 0;
		st = psa_export_public_key(key, pub, sizeof(pub), &publen);
		pr_info("usage=0x%x export_public #1=%d(%s) len=%u\n",
			(unsigned)usage, (int)st, psa_str(st), (unsigned)publen);

		publen = 0;
		st = psa_export_public_key(key, pub, sizeof(pub), &publen);
		pr_info("usage=0x%x export_public #2=%d(%s) len=%u\n",
			(unsigned)usage, (int)st, psa_str(st), (unsigned)publen);

		psa_destroy_key(key);
	}
}

/* 曲线对照：usage 固定，只改曲线。 */
static void probe_curve_variants(void)
{
	static const struct {
		psa_ecc_family_t fam;
		size_t bits;
		const char *name;
	} curves[] = {
		{ PSA_ECC_FAMILY_MONTGOMERY, 255, "X25519" },
		{ PSA_ECC_FAMILY_SECP_R1,    256, "P-256"  },
		{ PSA_ECC_FAMILY_SECP_R1,    384, "P-384"  },
	};
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(curves); i++) {
		psa_key_attributes_t attr = psa_key_attributes_init();
		mbedtls_svc_key_id_t key = MBEDTLS_SVC_KEY_ID_INIT;
		u8 pub[128];
		size_t publen = 0;
		psa_status_t st;

		psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_DERIVE);
		psa_set_key_algorithm(&attr, PSA_ALG_ECDH);
		psa_set_key_type(&attr,
				 PSA_KEY_TYPE_ECC_KEY_PAIR(curves[i].fam));
		psa_set_key_bits(&attr, curves[i].bits);

		st = psa_generate_key(&attr, &key);
		if (st != PSA_SUCCESS) {
			pr_info("%s generate=%d(%s)\n", curves[i].name,
				(int)st, psa_str(st));
			continue;
		}
		st = psa_export_public_key(key, pub, sizeof(pub), &publen);
		pr_info("%s export_public=%d(%s) len=%u\n", curves[i].name,
			(int)st, psa_str(st), (unsigned)publen);
		psa_destroy_key(key);
	}
}

/*
 * 绕过 PSA，直接测 ECP 的每一步。
 *
 * 已知：PSA 的 export_public_key 在 P-256/X25519 上返回 -135，而 P-384 正常；
 * 证书解析也在 P-256 上返回 MBEDTLS_ERR_ECP_BAD_INPUT_DATA。
 * PSA 把底层 mbedTLS 错误码翻译掉了，这里逐步骤打印**原始**返回值，
 * 定位到底卡在 group_load / gen_privkey / ecp_mul / check_pubkey 哪一步。
 *
 * 用堆分配 mbedtls_ecp_keypair：它内嵌 mbedtls_ecp_group，含预计算表，
 * 体积可观，不该放在本就只有 16 KiB 的内核栈上。
 */
static void probe_ecp_direct(void)
{
	static const struct {
		mbedtls_ecp_group_id id;
		const char *name;
	} groups[] = {
		{ MBEDTLS_ECP_DP_SECP256R1, "P-256"  },
		{ MBEDTLS_ECP_DP_SECP384R1, "P-384"  },
		{ MBEDTLS_ECP_DP_CURVE25519, "X25519" },
	};
	unsigned int i;

	/*
	 * 只用公开 API。mbedTLS 3.x 把 ecp_keypair 的字段经 MBEDTLS_PRIVATE 改名为
	 * private_xxx，直接访问 grp/d/Q 编不过；更不该为此定义
	 * MBEDTLS_ALLOW_PRIVATE_ACCESS —— 那会让本翻译单元看到的字段名与其它
	 * 翻译单元不一致（布局虽同、名字不同，但仍是不必要的风险）。
	 *
	 * mbedtls_ecp_gen_key() 内部就是 group_load + gen_privkey + ecp_mul，
	 * 正是 PSA 那条失败路径的等价物，返回码足够定位。
	 */
	for (i = 0; i < ARRAY_SIZE(groups); i++) {
		mbedtls_ecp_group *grp;
		mbedtls_ecp_keypair *kp;
		int ret_g, ret_k;

		grp = kzalloc(sizeof(*grp), GFP_KERNEL);
		if (!grp)
			return;
		mbedtls_ecp_group_init(grp);
		ret_g = mbedtls_ecp_group_load(grp, groups[i].id);
		mbedtls_ecp_group_free(grp);
		kfree(grp);

		kp = kzalloc(sizeof(*kp), GFP_KERNEL);
		if (!kp)
			return;
		mbedtls_ecp_keypair_init(kp);
		ret_k = mbedtls_ecp_gen_key(groups[i].id, kp, probe_rng, NULL);
		mbedtls_ecp_keypair_free(kp);
		kfree(kp);

		pr_info("ECP %s: group_load=%d gen_key=%d\n",
			groups[i].name, ret_g, ret_k);
	}
}

/*
 * 确证实验：用**已知正确的生成元编码**去校验群参数。
 *
 * mbedtls_ecp_gen_key 的失败点在 mbedtls_ecp_mul 内部对 G 调用的
 * mbedtls_ecp_check_pubkey()，即验算 Y² == X³+AX+B (mod P)。
 * 若这里的 check_pubkey 也失败，就确证「P/A/B 这三个群常数在运行时是错的」，
 * 而不是加载流程或算法的问题 —— 无需访问任何 MBEDTLS_PRIVATE 字段。
 */
static void probe_known_generator(void)
{
	/* P-256 生成元，SEC1 未压缩编码（0x04 || X || Y），标准值。 */
	static const unsigned char p256_g[65] = {
		0x04,
		0x6b, 0x17, 0xd1, 0xf2, 0xe1, 0x2c, 0x42, 0x47,
		0xf8, 0xbc, 0xe6, 0xe5, 0x63, 0xa4, 0x40, 0xf2,
		0x77, 0x03, 0x7d, 0x81, 0x2d, 0xeb, 0x33, 0xa0,
		0xf4, 0xa1, 0x39, 0x45, 0xd8, 0x98, 0xc2, 0x96,
		0x4f, 0xe3, 0x42, 0xe2, 0xfe, 0x1a, 0x7f, 0x9b,
		0x8e, 0xe7, 0xeb, 0x4a, 0x7c, 0x0f, 0x9e, 0x16,
		0x2b, 0xce, 0x33, 0x57, 0x6b, 0x31, 0x5e, 0xce,
		0xcb, 0xb6, 0x40, 0x68, 0x37, 0xbf, 0x51, 0xf5
	};
	/* P-384 生成元，同格式。 */
	static const unsigned char p384_g[97] = {
		0x04,
		0xaa, 0x87, 0xca, 0x22, 0xbe, 0x8b, 0x05, 0x37,
		0x8e, 0xb1, 0xc7, 0x1e, 0xf3, 0x20, 0xad, 0x74,
		0xe1, 0x8e, 0xf6, 0x9b, 0x35, 0xdf, 0x5c, 0xea,
		0x44, 0x4b, 0x4d, 0xd3, 0x8e, 0x1a, 0x4b, 0x4e,
		0x2d, 0x6c, 0x9c, 0x2e, 0xf6, 0xb8, 0x8b, 0x5a,
		0xc7, 0x5f, 0x30, 0x6c, 0x68, 0xd2, 0xd6, 0x5b,
		0x38, 0x9b, 0x1c, 0x80, 0x1c, 0xcd, 0xea, 0x8e,
		0xaa, 0x1c, 0xd9, 0xea, 0x48, 0x1c, 0x79, 0xb4,
		0xdf, 0x30, 0x62, 0x98, 0xf7, 0xb2, 0xd7, 0xc6,
		0x23, 0xe1, 0xff, 0x75, 0xa3, 0x81, 0x93, 0x7f,
		0x43, 0x1b, 0x19, 0x12, 0xaa, 0x20, 0x9b, 0x84,
		0x0a, 0x75, 0xe0, 0x87, 0x74, 0xbf, 0x7d, 0x1f,
		0x57
	};
	struct {
		mbedtls_ecp_group_id id;
		const unsigned char *g;
		size_t glen;
		const char *name;
	} cases[] = {
		{ MBEDTLS_ECP_DP_SECP256R1, p256_g, sizeof(p256_g), "P-256" },
		{ MBEDTLS_ECP_DP_SECP384R1, p384_g, sizeof(p384_g), "P-384" },
	};
	unsigned int i;

	pr_info("sizeof(mbedtls_mpi_uint)=%u MBEDTLS_ECP_MAX_BITS=%d\n",
		(unsigned)sizeof(mbedtls_mpi_uint), (int)MBEDTLS_ECP_MAX_BITS);

	for (i = 0; i < ARRAY_SIZE(cases); i++) {
		mbedtls_ecp_group *grp;
		mbedtls_ecp_point P;
		int r1, r2, r3;

		grp = kzalloc(sizeof(*grp), GFP_KERNEL);
		if (!grp)
			return;
		mbedtls_ecp_group_init(grp);
		mbedtls_ecp_point_init(&P);

		r1 = mbedtls_ecp_group_load(grp, cases[i].id);

		/*
		 * 群类型是理解 read_binary 为何拒绝的关键：
		 * mbedtls_ecp_point_read_binary 按类型分支，WEIERSTRASS 期望
		 * 1 + 2*size(P) 字节，而 MONTGOMERY 只期望 size(P) 字节。
		 * 类型又由 grp->G.Y.p 是否为 NULL 决定（ecp.c:488）。
		 */
		pr_info("群类型 %s = %d (0=NONE 1=WEIERSTRASS 2=MONTGOMERY)\n",
			cases[i].name, (int)mbedtls_ecp_get_type(grp));

		/*
		 * 把加载出来的 P 一行打完。不要分多行 pr_info —— dmesg 的环形
		 * 缓冲会被撑爆，先打的内容反而被挤掉（踩过一次）。
		 */
		{
			char buf[256];
			int off = 0;
			unsigned int k;

			for (k = 0; k < grp->P.n && k < 8 && off < 200; k++)
				off += scnprintf(buf + off, sizeof(buf) - off,
						 " %016llx",
						 (unsigned long long)grp->P.p[k]);
			pr_info("%s: P.n=%u bitlen=%u size=%u pbits=%u nbits=%u G.Y=%s limbs:%s\n",
				cases[i].name, (unsigned)grp->P.n,
				(unsigned)mbedtls_mpi_bitlen(&grp->P),
				(unsigned)mbedtls_mpi_size(&grp->P),
				(unsigned)grp->pbits, (unsigned)grp->nbits,
				grp->G.Y.p ? "set" : "NULL", buf);
		}

		r2 = mbedtls_ecp_point_read_binary(grp, &P, cases[i].g,
						   cases[i].glen);
		r3 = mbedtls_ecp_check_pubkey(grp, &P);

		/* 再试「当作蒙哥马利」的长度（只给 X，32 字节） */
		{
			mbedtls_ecp_point P2;
			int r4;

			mbedtls_ecp_point_init(&P2);
			r4 = mbedtls_ecp_point_read_binary(grp, &P2,
					cases[i].g + 1, (cases[i].glen - 1) / 2);
			mbedtls_ecp_point_free(&P2);
			pr_info("已知生成元 %s: group_load=%d 全长度读=%d 半长度读=%d check_pubkey=%d\n",
				cases[i].name, r1, r2, r4, r3);
		}

		mbedtls_ecp_point_free(&P);
		mbedtls_ecp_group_free(grp);
		kfree(grp);
	}
}

void kdg_psa_probe(void)
{
	psa_status_t st = psa_crypto_init();

	pr_info("psa_crypto_init=%d(%s)\n", (int)st, psa_str(st));
	probe_known_generator();
	probe_ecp_direct();
	probe_usage_variants();
	probe_curve_variants();
}
