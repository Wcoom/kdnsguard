/* SPDX-License-Identifier: GPL-2.0 */
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <mbedtls/platform.h>
#include <mbedtls/x509_crt.h>

static mbedtls_time_t test_time;
static mbedtls_time_t clock_(mbedtls_time_t *out)
{
	if (out) *out = test_time;
	return test_time;
}

static int load(const char *path, mbedtls_x509_crt *crt)
{
	unsigned char buf[8192];
	FILE *f = fopen(path, "rb");
	size_t n;
	if (!f) return -1;
	n = fread(buf, 1, sizeof(buf) - 1, f);
	fclose(f);
	buf[n] = 0;
	return mbedtls_x509_crt_parse(crt, buf, n + 1);
}

int main(int argc, char **argv)
{
	mbedtls_x509_crt ca, leaf;
	uint32_t flags;
	int ret;
	assert(argc == 3);
	mbedtls_x509_crt_init(&ca);
	mbedtls_x509_crt_init(&leaf);
	assert(mbedtls_platform_set_calloc_free(calloc, free) == 0);
	assert(mbedtls_platform_set_time(clock_) == 0);
	assert(load(argv[1], &ca) == 0);
	assert(load(argv[2], &leaf) == 0);
	/* 固定夹具窗口中点，不修改宿主或设备时钟。 */
	test_time = 1893456000; /* 2030-01-01 UTC */
	ret = mbedtls_x509_crt_verify(&leaf, &ca, NULL, "kdg-test.invalid", &flags, NULL, NULL);
	assert(ret == 0 && flags == 0);
	ret = mbedtls_x509_crt_verify(&leaf, &ca, NULL, "wrong.invalid", &flags, NULL, NULL);
	assert(ret != 0 && (flags & MBEDTLS_X509_BADCERT_CN_MISMATCH));
	test_time = 2208988800; /* 2040-01-01：过期 */
	ret = mbedtls_x509_crt_verify(&leaf, &ca, NULL, "kdg-test.invalid", &flags, NULL, NULL);
	assert(ret != 0 && (flags & MBEDTLS_X509_BADCERT_EXPIRED));
	test_time = 946684800; /* 2000-01-01：尚未生效 */
	ret = mbedtls_x509_crt_verify(&leaf, &ca, NULL, "kdg-test.invalid", &flags, NULL, NULL);
	assert(ret != 0 && (flags & MBEDTLS_X509_BADCERT_FUTURE));
	mbedtls_x509_crt_free(&leaf);
	mbedtls_x509_crt_free(&ca);
	puts("tls_verify: 正常链 / 主机名错误 / 过期 / 尚未生效全部通过");
	return 0;
}
