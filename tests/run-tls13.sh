#!/usr/bin/env bash
# kdg_tls13 与 OpenSSL 3.5 QUIC-TLS 服务端的进程内互通测试。
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DIR="$ROOT/tests/build/tls13"
Q="$ROOT/tests/build/quic"
mkdir -p "$DIR"
"$ROOT/tests/run-quic-crypto.sh" >/dev/null	# 顺带产出 libmbed.a 与 kdg_quic_crypto.o
cd "$DIR"
gen() {	# $1=前缀
	openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
		-subj "/CN=$1 root" -days 3650 -keyout "$1-ca.key" -out "$1-ca.pem" >/dev/null 2>&1
}
gen good; gen wrong
openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
	-subj '/CN=kdg-test.invalid' -addext 'subjectAltName=DNS:kdg-test.invalid' \
	-keyout leaf.key -out leaf.csr >/dev/null 2>&1
openssl x509 -req -in leaf.csr -CA good-ca.pem -CAkey good-ca.key -set_serial 7 \
	-copy_extensions copy -days 3650 -out leaf.pem >/dev/null 2>&1
CF=(-std=gnu11 -O1 -g -Wall -Wextra -Werror -fsanitize=address,undefined
    -fno-omit-frame-pointer -fno-sanitize-recover=all
    -DMBEDTLS_CONFIG_FILE='"tls_host_config.h"' -I"$ROOT/tests" -I"$ROOT/include"
    -I"$ROOT/kernel" -I"$ROOT/third_party/mbedtls-kernel" -I"$ROOT/third_party/mbedtls/include")
gcc "${CF[@]}" -c "$ROOT/kernel/kdg_tls13.c" -o kdg_tls13.o
# 测试文件同时包含 OpenSSL 与 mbedTLS 头：两者命名空间不冲突
gcc "${CF[@]}" -c "$ROOT/tests/test_tls13.c" -o test_tls13.o
gcc -fsanitize=address,undefined test_tls13.o kdg_tls13.o "$Q/kdg_quic_crypto.o" \
	"$Q/libmbed.a" -lssl -lcrypto -o test_tls13
./test_tls13 good-ca.pem leaf.pem leaf.key wrong-ca.pem
