本仓库**自身**的代码（`kernel/`、`include/`、`clients/`、`tools/`、`deploy/`、`tests/`）
按 GPL-2.0 发布（见 `LICENSE`），与它要编进的目标内核（GPL-2.0-only）相容。

仓库里**不包含**任何第三方源码：`third_party/mbedtls`、`third_party/nghttp2` 由
`tools/build.sh` 从 `third_party/` 同步而来并已 gitignore。各依赖的许可证、锁定
commit 与审计结论见 `third_party/third_party.lock`：

| 依赖 | 许可 | 用途 |
|---|---|---|
| mbedTLS | Apache-2.0 OR GPL-2.0-or-later | 内核 TLS 1.3 客户端与 X.509 |
| nghttp2 | MIT | HTTP/2 会话与 HPACK |
| wolfSSL | GPLv3（例外清单不含 Linux 内核） | **已拒绝**，记录在案 |
| lxin/quic | GPL-2.0+ | H3 数据层评估，握手在用户态，未采用 |
