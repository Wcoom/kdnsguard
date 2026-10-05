#!/usr/bin/env bash
# QUIC 包保护的宿主测试：直接链接 mbedTLS 源码（与 run-tls-verify.sh 同配置）。
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DIR="$ROOT/tests/build/quic"
mkdir -p "$DIR"
"${CC:-gcc}" -std=gnu11 -O1 -g -Wall -Wextra -Werror \
    -fsanitize=address,undefined -fno-omit-frame-pointer -fno-sanitize-recover=all \
    -DMBEDTLS_CONFIG_FILE='"tls_host_config.h"' \
    -I"$ROOT/tests" -I"$ROOT/include" -I"$ROOT/kernel" \
    -I"$ROOT/third_party/mbedtls-kernel" -I"$ROOT/third_party/mbedtls/include" \
    -c "$ROOT/kernel/kdg_quic_crypto.c" -o "$DIR/kdg_quic_crypto.o"
"${CC:-gcc}" -std=gnu11 -O1 -g -Wall -Wextra -Werror \
    -fsanitize=address,undefined -fno-omit-frame-pointer -fno-sanitize-recover=all \
    -DMBEDTLS_CONFIG_FILE='"tls_host_config.h"' \
    -I"$ROOT/tests" -I"$ROOT/include" -I"$ROOT/kernel" \
    -I"$ROOT/third_party/mbedtls-kernel" -I"$ROOT/third_party/mbedtls/include" \
    -c "$ROOT/tests/test_quic_crypto.c" -o "$DIR/test_quic_crypto.o"
[ -f "$DIR/libmbed.a" ] || {
    (cd "$DIR" && for f in "$ROOT"/third_party/mbedtls/library/*.c; do
        "${CC:-gcc}" -O1 -g -fsanitize=address,undefined -fno-omit-frame-pointer \
            -DMBEDTLS_CONFIG_FILE='"tls_host_config.h"' -I"$ROOT/tests" \
            -I"$ROOT/third_party/mbedtls-kernel" -I"$ROOT/third_party/mbedtls/include" \
            -c "$f" -o "$(basename "$f" .c).mo" & done; wait; ar rcs libmbed.a *.mo)
}
"${CC:-gcc}" -fsanitize=address,undefined "$DIR/test_quic_crypto.o" "$DIR/kdg_quic_crypto.o" \
    "$DIR/libmbed.a" -o "$DIR/test_quic_crypto"
"$DIR/test_quic_crypto"
