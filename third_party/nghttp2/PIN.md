# nghttp2 依赖锁定

| 项 | 值 |
|---|---|
| 仓库 | https://github.com/nghttp2/nghttp2 |
| commit | `19d06e62185d93d2398d85241cdbb460349bfe44` |
| 版本 | 1.71.0-DEV（取自该 commit 的 configure.ac） |
| 许可证 | MIT（见同目录 LICENSE） |
| 取用范围 | 仅 `lib/`（库核心）与 `lib/includes/nghttp2/nghttp2.h` |
| 手工生成 | `includes/nghttp2/nghttp2ver.h`（上游由 autoconf/CMake 从 `.in` 生成） |

## 未取用的部分（方案 §6.3 划定的移植边界）

不移植 `nghttpx`/`nghttpd`/`h2load`/`nghttp`、不移植 libevent 与 TLS 封装、
不移植命令行与测试。只要客户端库核心。

## 不修改上游

`third_party/nghttp2/` 下的文件保持与上游逐字节一致（除手工生成的
`nghttp2ver.h`）。所有内核适配都在：

- `third_party/mbedtls-kernel/shim/`（libc 名称遮蔽与内核宏清理）
- `kernel/kdg_h2.c`（会话驱动、回调、内存分配器接入）

这样升级时只需复核 shim 与适配层，不必比对被改过的上游源码。

## 与内核的接口约束

- **自定义分配器**：nghttp2 的 `nghttp2_mem` 是为此设计的。内核侧通过
  自己实现的 `nghttp2_mem` 把分配导向 kmalloc/krealloc/kfree
  （`nghttp2_mem.c` 的四个 default_* 走 shim 提供的同名函数）。
- **不需要 config.h**：上游只在 `HAVE_CONFIG_H` 被定义时才 include 它；
  我们不定义，即走它的默认分支。
- **assert 与 abort 的处置不同**：见 `shim/stdlib.h` 的说明。
