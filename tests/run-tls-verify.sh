#!/bin/bash
# 本地证书夹具只存在 tests/build，不用于设备信任材料。
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DIR="$ROOT/tests/build/tls"
mkdir -p "$DIR"
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
    -subj '/CN=KDG test root' -days 7300 -keyout "$DIR/ca.key" -out "$DIR/ca.pem" \
    >/dev/null 2>&1
openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
    -subj '/CN=kdg-test.invalid' -addext 'subjectAltName=DNS:kdg-test.invalid' \
    -keyout "$DIR/leaf.key" -out "$DIR/leaf.csr" >/dev/null 2>&1
openssl x509 -req -in "$DIR/leaf.csr" -CA "$DIR/ca.pem" -CAkey "$DIR/ca.key" \
    -set_serial 2 -copy_extensions copy -not_before 20200101000000Z \
    -not_after 20350101000000Z -out "$DIR/leaf.pem" >/dev/null 2>&1
CC="${CC:-gcc}"
"$CC" -O1 -g -fsanitize=address,undefined -fno-omit-frame-pointer \
    -DMBEDTLS_CONFIG_FILE='"tls_host_config.h"' \
    -I"$ROOT/tests" -I"$ROOT/third_party/mbedtls-kernel" \
    -I"$ROOT/third_party/mbedtls/include" \
    "$ROOT/tests/test_tls_verify.c" "$ROOT"/third_party/mbedtls/library/*.c \
    -o "$DIR/test_tls_verify"
"$DIR/test_tls_verify" "$DIR/ca.pem" "$DIR/leaf.pem"
