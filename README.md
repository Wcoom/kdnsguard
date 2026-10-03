# kdnsguard

便携设备（OnePlus 13 / PJZ110）的**全局 DNS 内核化**工程：把 DNS 接管、缓存、
同名合并、DoH 上游连接与响应回送全部放在 Linux 内核里，用户空间只调用接口，
不承担解析、握手或上游请求。

本仓库是《便携设备全局 DNS 内核架构与实施方案》的**实现**。
方案是设计与验收目标的来源；本仓库只记录**实测到的偏离**，不复述方案。

---

## 当前状态：P0 完成，P1 达成

| 阶段 | 状态 |
|---|---|
| **P0** 环境锁定 / 依赖锁定 / 授权核对 | ✅ 完成，见 [`docs/P0-findings.md`](docs/P0-findings.md) |
| **内核骨架** 生命周期 / NAT 注册 / DNS 校验器 / UAPI | ✅ 完成并真机验证 |
| **P1** 内核 TLS + H1 DoH 原型 | ✅ **达成方案 §19 的第一个可验收成果** |
| **P2** 解析核心：缓存 / 同名合并 / 每调用方配额 | ✅ 完成并真机验证 |
| P2 剩余：nghttp2 移植（H2 上游） | ⬜ 未开始 |
| P3 全局接管 | ⬜ 未开始 |
| P4–P7 | ⬜ 未开始 |

### P1 验收：不改全局网络、通过 API 完成经证书验证的 DoH 查询

真机实测（OnePlus 13，内核 `6.6.118-…-abogki20260727-4k`）：

```
kdnsguard: TLS 握手完成（协议 TLSv1.3，密码套件 TLS1-3-CHACHA20-POLY1305-SHA256，ALPN http/1.1）

$ kdgctl query github.com
响应: status=0 errno=0 resp_len=…      DNS: rcode=0
  A 140.82.121.4
```

| 域名 | 解析结果 |
|---|---|
| example.com | 104.20.23.154, 172.66.147.243 |
| www.baidu.com | 182.61.200.108, 182.61.200.110 |
| github.com | 140.82.121.4 |
| one.one.one.one | 1.1.1.1, 1.0.0.1 |

健康计数 `DOH_QUERIES=8 / DOH_OK=8 / LAST_STATUS=200 / LAST_RTT=150ms`，
连续多轮稳定；DNS 接管仍**默认关闭**，对系统零行为影响。

链路全程在内核：内核 TCP socket → 内核 TLS（mbedTLS 3.6.7，证书链 + 主机名校验，
`VERIFY_REQUIRED` 不可关闭）→ 内核 HTTP/1.1 解析 → DoH POST。
用户空间只通过 `/dev/kdnsguard` 提交 wire 报文。

### P2 验收：缓存 / 同名合并 / 配额

| 项 | 真机实测 |
|---|---|
| 缓存 | 同域名第二次查询 **270 ms → 10 ms**；大小写不同的同一域名命中同一缓存项 |
| 同名合并 | **100 个并发 → 1 次上游 + 99 个 waiter**（方案 §7.3 逐字口径）|
| 每调用方配额 | 突发上限设为 10 时，连发 20 次 → 精确 10 成功 / 10 明确 `KDG_ST_EAGAIN` |

缓存参数取自方案 §7.4 的初值：4096 槽位、CLOCK 淘汰、4 MiB 目标 / 8 MiB 上限
（槽位结构本身的 1.4 MiB 已预扣进预算）。

⚠️ **一个值得记住的缺陷已在 P1 定位并修复**：shim 里把 `UINT_MAX` 写成 `(~0U)`，
而 C 预处理器按 `intmax_t` 运算，`(~0U)` 在 `#if` 里是 **64 位全 1**，
导致 mbedTLS 把 64 位肢体误判为 32 位、选中 `__builtin_clz`。
复盘见 [`docs/P1-ecp-rootcause.md`](docs/P1-ecp-rootcause.md)。

### ⚠️ 两条必须先知道的事实

1. **原方案的核心依赖 wolfSSL 不可用。** 它是 GPLv3，其 GPLv2 例外清单为封闭
   集合且**不含 Linux 内核**，无免费许可路径。已按方案 §3.1 自设的规则换选
   **mbedTLS**（`Apache-2.0 OR GPL-2.0-or-later`）。详见
   [`third_party/third_party.lock`](third_party/third_party.lock)。
2. **方案 §2.1 的 `CONFIG_NF_TABLES is not set` 是错的**，真值为 `=y`。
   误判源于读了不会更新的 `/proc/config.gz`。核配置只认 `out/.config`
   与 `/proc/kallsyms`。

---

## 目录结构

```
kdnsguard/
  include/
    kdg_base.h            双态构建基座（内核态 / 宿主态）
    uapi/kdnsguard.h      UAPI v1：Generic Netlink + 字符设备
  kernel/
    kdg.h                 模块内部共享定义
    kdg_main.c            生命周期、per-netns 状态、模块参数
    kdg_nat.c             Netfilter/NAT 接管点（方案 §5.2）
    kdg_genl.c            管理面 Generic Netlink 族
    kdg_wire.{h,c}        有界 DNS wire 校验器（方案 §8）
    kdg_transport.h       上游 DoH 传输层接口（实现留待 P1/P2）
  tests/                  宿主侧语料测试（ASan/UBSan）
  tools/
    build.sh              构建 kdnsguard.ko
    build-kdgctl.sh       构建 freestanding aarch64 诊断客户端
    kdgctl.c
    manifest.sh           生成 kernel_build_manifest（方案 §15）
  third_party/            依赖锁定与授权审计
  docs/                   P0 结论等
```

---

## 设计上的几个关键取舍

### DNS wire 校验器双态可编译

`kernel/kdg_wire.c` 既能编进内核，也能被**宿主 gcc** 直接编译并跑语料测试。
这不是花活：本内核 `CONFIG_KUNIT=m`，而 KUnit 的 Kconfig 要求 `KUNIT=y`
才会编入用例，**设备构建里 KUnit 用例根本不会被编译**。DNS 解析的安全性完全
取决于对畸形输入（压缩指针自环、标签长度溢出、计数不一致、报文截断）的处置，
不跑几百条语料就等于没验证。同一份源文件两种编译形态，保证「设备上跑的」
与「测过的」是同一份代码——不复制源码，不建镜像副本。

### 压缩指针强制严格回指

RFC 1035 §4.1.4 要求指针指向 "a prior occurrence"。据此强制 `target < p`，
于是所有指针链沿地址严格递减 ⇒ **环在构造上不可能存在**，不依赖「跳转次数
上限」兜底（上限只是第二道闸）。这是合规的收紧，不是额外限制。

### 骨架阶段默认不改写任何流量

`intercept_enabled` 默认 0，且启用还需要模块以 `allow_intercept=1` 加载。
原因是本阶段**还没有**本地 DNS 监听者，一旦启用接管，53 端口流量会被改写到
`127.0.0.1:1054` 而无人应答——等于把手机的 DNS 打断。这是「分阶段推进、
每步都有退出条件」的落地。

### NAT 接管必须走 NAT hook provider 机制

方案 §5.2 明确禁止「在任意普通 hook 里调一次 `nf_nat_setup_info()`」。
正确做法是经 `nf_nat_ipv4_register_fn()` 把 ops 插进 **nat 核心自己的 hook**，
由 nat 核心完成改写并借 conntrack 建立反向转换。见 `kernel/kdg_nat.c` 头注。

---

## 构建与测试

```bash
# 宿主侧单元测试（需要 gcc；带 ASan/UBSan）
cd tests && make run

# 内核模块（需先构建过 oplus13/android_kernel_common_oneplus_sm8750/out）
bash tools/build.sh

# 诊断客户端（freestanding aarch64，不依赖 NDK 或设备 libc）
bash tools/build-kdgctl.sh

# 构建清单
bash tools/manifest.sh third_party/manifest.txt
```

真机：

```bash
adb push kernel/kdnsguard.ko tools/kdgctl /data/local/tmp/
adb shell su -c 'insmod /data/local/tmp/kdnsguard.ko'
adb shell su -c '/data/local/tmp/kdgctl'
adb shell su -c 'rmmod kdnsguard'
```

`kdgctl` 会打印 Generic Netlink 族、能力位与健康计数。其中
`hook_calls`（hook 被调用总次数）与 `seen`（判定为 DNS 的次数）分开计数，
是区分「hook 没挂上」与「挂上了但谓词错」的关键诊断量——本次开发正是靠它
定位到一个真实的缺陷。

---

## 与工作区的关系

本仓库是独立 git 仓库。内核源码在
`/home/wcoom/桌面/oplus13/android_kernel_common_oneplus_sm8750`，
模块以**树外**方式（`M=...`）针对其 `out/` 构建，避免 ddl_guard 那种
「源码在内核树、符号链接进模块目录」的双份布局隐患。
将来若需常驻设备（AnyKernel3 只换内核段、不装模块），再改为内建集成。
