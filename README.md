# kdnsguard

便携设备（OnePlus 13 / PJZ110）的**全局 DNS 内核化**工程：把 DNS 接管、缓存、
同名合并、DoH 上游连接与响应回送全部放在 Linux 内核里，用户空间只调用接口，
不承担解析、握手或上游请求。

本仓库是《便携设备全局 DNS 内核架构与实施方案》的**实现**。
方案是设计与验收目标的来源；本仓库只记录**实测到的偏离**，不复述方案。

---

## 当前状态：P0–P4 完成，P5 常驻已落地（设备当前处于接管态）

| 阶段 | 状态 |
|---|---|
| **P0** 环境锁定 / 依赖锁定 / 授权核对 | ✅ 完成，见 [`docs/P0-findings.md`](docs/P0-findings.md) |
| **内核骨架** 生命周期 / NAT 注册 / DNS 校验器 / UAPI | ✅ 完成并真机验证 |
| **P1** 内核 TLS + H1 DoH 原型 | ✅ **达成方案 §19 的第一个可验收成果** |
| **P2** 解析核心：缓存 / 同名合并 / 每调用方配额 / **H2 上游（nghttp2）** | ✅ 完成并真机验证 |
| **P2 补齐：方案 §6.3 的 H2 持久连接池** | ✅ 已实现并**真机验证**（[`docs/P2-connection-pool.md`](docs/P2-connection-pool.md)、[`docs/P6-round2.md`](docs/P6-round2.md)） |
| **P3** 全局接管（双栈 NAT / 代理所有权交接 / 泄漏与失败策略） | ✅ **已在受控窗口内真机接管并验证**，见 [`docs/P3-takeover.md`](docs/P3-takeover.md) |
| **P4** 核心 DNS 移交 | ✅ **Path A 真机接管已验证**（[`docs/P4-final.md`](docs/P4-final.md)） |
| **P5** 常驻交付 | ✅ LKM + `service.d`（[`docs/P5-persist.md`](docs/P5-persist.md)、[`deploy/`](deploy/)）。**设备当前处于接管态**。FakeIP 改为 `redir-host`（内核返回真实 IP）。ueventd / 多网络 isolation 未做 |
| **P6** 功耗定型 | 🟡 测量完成；**能耗不可测**（无功率仪 + 手机在充电），不宣传更低能耗 |
| P7 全内核 H3 | ⛔ **按方案 §6.5 停在 H2**：mbedTLS 无 QUIC API；wolfSSL 已拒；本树无 in-tree QUIC；`lxin/quic` 握手在用户态 |

**常驻后接管默认打开**（`/data/adb/kdnsguard/enabled` 存在且开机脚本跑过）。
模块仍须 `allow_intercept=1`。卸载：`sh /data/adb/kdnsguard/disable.sh`。
私人 DNS 必须保持 `off`。上游是 H2 DoH，不是 H3。

### P3 真机验证摘要（2026-10-05，详见 `docs/P3-takeover.md`）

所有权交接不靠改 eBPF 源码：mihomo 已有 `listeners[].dns-mode: off`，置 off 后
53 在 socket 层直接放行到 Netfilter。实测 `getpeername()` 从 `127.x:33507` 变为
真实的 `223.5.5.5:53`。

| 验收项（方案 §16 P3 行） | 实测 |
|---|---|
| UDP / TCP 双栈接管 | LOCAL_OUT IPv4/IPv6 的 UDP/TCP/sendto 全部由内核应答 |
| conntrack 回包 | 反向映射实证：IPv4 → `127.0.0.1:1054`，IPv6 → `[::1]:1054` |
| **热点 / 共享网络** | 笔记本（10.56.139.42）查手机 rndis0:53 → 反向映射为 `10.56.139.93:1054`，2 ms 命中缓存 |
| 客户端入口生命周期 | dummy 接口实测：建/改/删地址与删接口都正确绑定/重绑/释放 |
| 严格模式零回落 | 注入上游故障后查询**失败而非回落**；1.0 s 返回 SERVFAIL |
| 退出 | `DISABLE` 后 listener 全消失、DNS 立即回到原链路；`rmmod` 干净、0 告警 |

**本轮修掉两个真实缺陷**（真机上暴露的）：

1. **IPv4 地址添加不产生 netdev 事件**——`inet_insert_ifa()` 发的是
   `inetaddr_chain` 而非 `netdev_chain`。只挂 netdev 链会导致「接口先 up、地址后配」
   （即用户后开热点的真实时序）永远不被接管，且日志上看不出异常。已补挂
   `register_inetaddr_notifier()` / `register_inet6addr_notifier()`。
2. **上游失败时静默丢包**——客户端只能等到自己的超时（实测 3.05 s），违反方案 §18
   「返回 SERVFAIL/API 错误」。已新增 `kdg_wire_make_error_response()`。

**提交前独立审核又发现 5 条真机测不出来的问题**（IPv6 绑定地址与
`nf_nat_redirect_ipv6` 的选择规则不一致、持锁做上游探测会拖住 rtnl、
`stop()` 与并发 PREPARE 的时序、`stop()` 与通知链回调无互斥、未区分
子网命名空间），已全部修掉并重新真机回归。明细与「哪条修法被审核本身否决」
见 `docs/P3-takeover.md` §5。

**明确未覆盖**：真实 Wi-Fi↔蜂窝切换未做（当前手机是本机唯一出口，切换会切断验证
通路）；netId/fwmark 多网络隔离未实现；上游仍是 IPv4 bootstrap。理由与细节见
`docs/P3-takeover.md` §6。

### P6 第一轮：性能与机制量测量（2026-10-05，详见 `docs/P6-measurements.md`）

**先说测不了的**：本装置**无法测能耗** —— 没有外部功率仪，且手机正在 USB 充电
（也是 adb 通路，断开就失去控制通道），净电流被充电电流淹没。按方案 §17.4 的
红线，**不宣传"更低能耗"**。

测出来的是机制量，用同轨迹、同上游、同网络对比内核路径（`/dev/kdnsguard`）与
用户态基线（mihomo `127.0.0.1:1053`），轨迹见 `clients/rust/traces/`：

| | 内核 vs 基线 |
|---|---|
| **缓存命中 p50** | **15–28 µs vs 576–2602 µs（快 20–90×）** ✅ |
| **同名爆发** | 100 并发同名 → **上游 1 次**（方案 §17.3 逐字达标）✅ |
| 冷查询 p50（并发 64） | **14161 ms vs 101 ms（慢 140×）**，且**开始超时失败** 🔴 |
| 冷查询 wall（并发 64） | **77 s vs 0.28 s（长 275×）** 🔴 |
| 随机 1000（缓存无效）CPU | **22615 ms vs 32 ms（707×）** 🔴 |

> ⚠️ 这张表里 A（基线）的 c16/c64 数字**有口径问题**：第一轮对 C 逐档重载模块、
> 对 A 只重启了一次，所以 C 是冷的而 A 是热的。修正后的 A 冷 p50 是 63–120 ms
> 而不是 101 ms，比值因此被夸大。C 那一列是对的。见
> [`docs/P6-measurements.md`](docs/P6-measurements.md) 开头的说明。

**最刺眼的一条：并发对内核是负作用。** 基线 c1→c16→c64 的 wall 是
15.2 s → 2.15 s → 0.28 s（快 54 倍）；内核是 29.7 s → 33.3 s → **77 s**（慢 2.6 倍）。

根因是**每次查询新建 TCP+TLS 会话 + 一把共享 TLS 锁**：方案 §6.3 要求的
「H2 每网络一条按需连接、32 个活跃流」**尚未实现**，README 此前只承认
「尚未完成持久连接多流」，没有数字说明那意味着什么。P6 给出了数字，并把
它列为最高优先级的下一步。

**该缺陷已修复并在真机上复测**（2026-10-05，
[`docs/P2-connection-pool.md`](docs/P2-connection-pool.md) /
[`docs/P6-round2.md`](docs/P6-round2.md)）：建连/握手/收发搬进一个驱动线程，
调用方只入队并等自己的完成；H2 会话常驻、多流并行。

| | 第一轮 | 第二轮 |
|---|---|---|
| 冷查询并发 64 wall | **77.0 s** | **0.459 s（短 168×）** |
| 冷查询并发 64 p50 | **14161 ms** | **86.8 ms（快 163×）** |
| 随机 1000 wall | 207 s | **6.82 s（短 30×）** |
| 随机 1000 调用方 CPU | 22615 ms | **133 ms（低 170×）** |
| **`pool_connects : doh_queries`** | 1 : 1 | **1 : 1000** |
| 并发方向 | c64 比 c1 **慢 2.6×** | c64 比 c1 **快 31.5×** |

方案 §6.3 的三条也在真机上逐字达标：并发流上限 32（对端 SETTINGS 前）→ 64
（之后）；空闲 95 秒后连接被主动关闭、再查一次重建；零告警、`rmmod` 干净、
驱动线程数归 0。

⚠️ **没有变成零差距**：内核的 wall 仍是 mihomo 基线的 1.45–2.25×、p50 高约
40 ms。成因未定位，如实记在 `docs/P6-round2.md` §3。

### P4 第一步：IP ↔ 域名 关联表（2026-10-05，详见 `docs/P4-mapping.md`）

DNS 挪进内核后代理就失去了它原先由 DNS 应答触发的域名/IP 映射，方案 §12.2
要求内核提供这份有界关联。已落地内核侧：512 槽 / 316 KiB、按
`net_id + profile_gen + 地址` 索引、**一个 IP 保留一组域名**（歧义不丢）、
TTL 夹取、惰性过期、零定时器，`KDG_OP_MAP_LOOKUP` 反查接口。真机验证：
条目数与答案区 A 记录逐条对上、TTL 递减、`mem_bytes` 与算术精确一致、
`rmmod` 干净、0 告警。

> ⚠️ **这一步先撞了一次内核 panic（手机重启），复盘在 `docs/P4-mapping.md` §3。**
> 一句话：`buckets`/`slots` 是 `kvcalloc` 来的，我却用 `kfree` 释放 —— 316 KiB
> 必然落在 vmalloc 区，`kfree` 打 vmalloc 地址直接 panic。**宿主 ASan 抓不到
> 这一类**（host shim 把 `kfree`/`kvfree` 都映射成 `free`），故补了一道
> **构建期分配/释放配对门禁**。那道门禁的第一版还是**空闸**：它只查「同文件有
> 没有正确的 `kvfree`」，而改错其中一处时另一处仍在，照样放行 —— 靠**反向注入
> 测试**才发现，现已改成同时检查「有没有错误的释放」。



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

链路全程在内核：内核 TCP socket → 内核 TLS（mbedTLS 3.6.7，证书链、SAN/主机名和有效期校验，
`VERIFY_REQUIRED` 不可关闭）→ 内核 HTTP/2 或 HTTP/1.1 → DoH POST。
用户空间只通过 `/dev/kdnsguard` 提交 wire 报文。

### P2 验收：缓存 / 同名合并 / 配额

| 项 | 真机实测 |
|---|---|
| 缓存 | 同域名第二次查询 **270 ms → 10 ms**；大小写不同的同一域名命中同一缓存项 |
| 同名合并 | **100 个并发 → 1 次上游 + 99 个 waiter**（方案 §7.3 逐字口径）|
| 每调用方配额 | 突发上限设为 10 时，连发 20 次 → 精确 10 成功 / 10 明确 `KDG_ST_EAGAIN` |
| H2/H1 | ALPN 选择 H2，服务端不支持时回落 H1。**该行的「每次建连」描述已过期**，见下方连接池 |

H2/H1 实测：真实上游协商 `h2`，DoH 请求经内核 nghttp2 发出，4 个域名成功。
（这条验收是在**每查询一条连接**时期的记录，保留作为「H2 链路本身能通」的
证据；连接复用与并发多流是后来补的，见
[`docs/P2-connection-pool.md`](docs/P2-connection-pool.md)。）

**H2/H1 按 ALPN 协商结果自动选择**（方案 §6.3/§6.4）：服务端支持 h2 时走
nghttp2 的 HTTP/2 客户端，否则回落到内核自写的 HTTP/1.1 路径。

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
    kdg_listener.c        loopback + 客户端入口 listener、ownership 事务的执行体
    kdg_map.{h,c}         IP ↔ 域名 有界关联表（方案 §12.2，双态可编译）
    kdg_genl.c            管理面 Generic Netlink 族
    kdg_wire.{h,c}        有界 DNS wire 校验器（方案 §8）
    kdg_sock/tls/http/doh.c
                          内核 socket / TLS 会话 / H1 兼容路径 / 传输选择
    kdg_h2stream.h        一条 H2 流的收集状态（只依赖 kdg_base.h）
    kdg_h2.{h,c}          H2 **会话**：建会话、提交多条流、喂字节、刷帧
    kdg_upstream.{h,c}    一条上游连接（TCP+TLS+ALPN+H2）的不透明句柄
    kdg_pool.{h,c}        持久连接池：槽位、排队、超期取消、空闲关闭
    kdg_resolve/cache*/sflight/quota/chardev…
                          解析编排与缓存、同名合并、配额、字符设备
  clients/
    rust/kdg-client/      Rust 用户空间客户端库（零依赖，含 UAPI 布局交叉验证）
  tests/                  宿主侧语料测试（ASan/UBSan）
    test_pool.c           连接池并发测试（真 pthread + ASan，跑 kdg_pool.c 原文）
    hostlinux/            让 kdg_pool.c 在宿主上编译的一组 <linux/*.h> 替身
    inject_pool_defects.py 反向注入审计：证明上面那些用例抓得住对应缺陷（不是空闸）
  tools/
    build.sh              构建 kdnsguard.ko（含 kCFI / 未定义符号 / 分配释放配对三道门禁）
    build-kdgctl.sh       构建 freestanding aarch64 诊断客户端
    build-netprobe.sh     构建 DNS 路径探针（判「谁抢到了 53」）
    kdgctl.c / netprobe.c
    manifest.sh           生成 kernel_build_manifest（方案 §15）
  third_party/            依赖锁定与授权审计
  clients/rust/traces/    P6 查询轨迹（确定性生成、脱敏）
  docs/                   P0 结论、P3 接管验证、P4 映射表与 panic 复盘、P4 代理适配器、
                          P2 连接池、P5 范围、P6 两轮测量
  docs/evidence/          真机验证的原始输出与当时用的脚本（可复现）
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

### 接管默认关闭，启用必须走 ownership 事务

`intercept_enabled` 默认 0，且启用还需要模块以 `allow_intercept=1` 加载，
并且要经过 `PREPARE`（建 listener、探测上游、要求信任锚已加载）→ `COMMIT`
（校验 transaction/generation/readiness）。`DISABLE` 停 listener 并把所有权
还给原链路。这是「分阶段推进、每步都有退出条件」的落地，也让真机验证可以在
一个可随时收回的窗口里做。

### 两条路径的 listener **不能**共用同一个绑定地址

`LOCAL_OUT` 的 REDIRECT 目标是 loopback，`PREROUTING` 的目标是**入接口自己的
地址**——这是 `nf_nat_redirect_*` 按 hooknum 分支的语义，也是 conntrack 反向映射
对回包源地址的要求。因此 listener 分两组：loopback 组服务本机查询，客户端入口组
（热点 / USB 共享 / AP）逐个绑定到接口地址上。详见
[`docs/P3-takeover.md`](docs/P3-takeover.md) §2。

### 客户端入口只认「已建好 listener」的白名单

PREROUTING 只对**已成功绑定 listener 的入接口**接管，名单由模块参数
`client_ifaces` 给出。名单外的接口一律 `NF_ACCEPT`——方案 §5.2 要求「外部接口
默认不允许主动访问这个 listener」，这也是「手机在运营商网络上的地址不会变成
开放解析器」的实现方式。宁可少接管一个接口，也不能「先接管、后建 listener」
把客户端的 DNS 打进黑洞（`nf_nat_redirect_*` 在接口无地址时直接 `NF_DROP`）。

### NAT 接管必须走 NAT hook provider 机制

方案 §5.2 明确禁止「在任意普通 hook 里调一次 `nf_nat_setup_info()`」。
正确做法是经 `nf_nat_ipv4_register_fn()` 把 ops 插进 **nat 核心自己的 hook**，
由 nat 核心完成改写并借 conntrack 建立反向转换。见 `kernel/kdg_nat.c` 头注。

### 上游失败必须**回一个应答**，不能静默丢包

严格模式（方案 §18）的「返回 SERVFAIL/API 错误」是字面要求：不回包等于把失败
转嫁给调用方，客户端只能等到自己的超时，而且拿不到任何可区分信号。见
`kdg_wire_make_error_response()`。

---

## 构建与测试

```bash
# 宿主侧单元测试（需要 gcc；带 ASan/UBSan）
cd tests && make run

# Rust 客户端库（宿主单测 + UAPI 布局交叉验证）
cd clients/rust && cargo test --offline

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

## 安装（设备常驻）

发布物是 **KernelSU/Magisk 模块**：`kdnsguard-ksu-<版本>.zip`（见 Releases）。

```
ksud module install kdnsguard-ksu-0.2.0.zip      # 或 KernelSU 应用里「安装模块」
```

开机时模块脚本只做两件内核做不了的事（`insmod`、`mknod`），其余全部在模块内部：
信任锚编在 `.ko` 里、所有权的 `PREPARE → COMMIT` 由内核自己的延迟工作带重试完成
（网络就绪前反复尝试，ownership 被他人持有时让位、对方释放后接管）。因此
**开机不需要任何部署脚本，也不需要代理进程活着**。

模块带引导保护：`post-fs-data` 落 `.boot` 标记、`service.sh` 开机后清除；下次开机若
仍看到标记即自我停用，绝不进入开机循环（删除模块目录下的 `disable` 可恢复）。

诊断：模块目录内附带 `kdgctl`（`health` / `query <域名>` / `bpftest <秒>`）。

构建模块包：`bash tools/build-ksu-module.sh` → `dist/kdnsguard-ksu-<版本>.zip`。

---

## 与工作区的关系

本仓库是独立 git 仓库（`github.com/Wcoom/kdnsguard`，默认分支 `main`）。
内核源码在 `/home/wcoom/桌面/oplus13/android_kernel_common_oneplus_sm8750`，
模块以**树外**方式（`M=...`）针对其 `out/` 构建，避免 ddl_guard 那种
「源码在内核树、符号链接进模块目录」的双份布局隐患。

⚠️ **曾经尝试过把本工程编进内核（`CONFIG_KDNSGUARD=y`），该路线已放弃并整体回滚**：
内建镜像在真机上引导失败（第一屏无限重启、内核完全没有日志），而同一套刷机流程与
镜像结构在之前的多次刷机中都成立。四个内建提交留在内核仓库历史里备查，树本身已
还原为内建之前的状态。现形态是 KO，由 KernelSU 模块在开机时加载。
