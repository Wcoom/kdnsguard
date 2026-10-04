# P4 第 2 块：代理侧适配器（实现说明）

日期：2026-10-05。仓库：`/home/wcoom/桌面/mihomo-ebpf-smart-export`，
分支 `mihomo/kernel-dns-backend`。

本文件说明**代理侧**怎么接内核 DNS，以及哪些部分被卡住了。
内核侧的映射表见 [`P4-mapping.md`](P4-mapping.md)。

> ⚠️ **本轮只做代码，没有真机验证。** 与内核侧不同，适配器要验证的是「日常
> 使用中 DNS 全走内核」时的行为，需要手机进入较长接管态 —— 按约定另开窗口。

---

## 1. 集成点只有一处：`resolver.Enhancer`

`tunnel/tunnel.go`：

```go
func needLookupIP(metadata *C.Metadata) bool {
	return resolver.MappingEnabled() && metadata.Host == "" && metadata.DstIP.IsValid()
}

func preHandleMetadata(metadata *C.Metadata) error {
	if needLookupIP(metadata) {
		host, exist := resolver.FindHostByIP(metadata.DstIP)
		...
	}
}
```

也就是说：**只要提供一个 `MappingEnabled()` 为真、`FindHostByIP()` 能给出候选的
Enhancer，mihomo 就能在 DNS 挪出代理之后继续按域名分流** —— `tunnel.go` 一行
都不用改。这就是方案 §12.2 要的落点。

旧的内核后端把 `DefaultHostMapper` 设成 `nil`（block 1 阶段内核还没有映射表时的
临时状态），等于把这条路径关掉了。新增的 `KernelEnhancer` 把它打开。

### 歧义：内核给集合，接口只要一个

方案 §12.2 要求「保留集合和歧义」，而 `FindHostByIP` 只能返回一个字符串。处理：

| 手段 | 说明 |
|---|---|
| 按「剩余 TTL 最长」挑 | 唯一可用的信号；顺序确定、可解释 |
| 单独计数 `ambiguous` | 歧义是**可观测**的，不是悄悄吞掉 |
| `FindHostsByIP` 返回全量 | 需要自己裁决的调用方走这个 |
| 交给嗅探纠正 | `sniffer.override-destination: true` 时，嗅探到的 SNI/HTTP Host 会**无条件覆盖** `metadata.Host`（`component/sniffer/dispatcher.go` 的 `replaceDomain`）—— 歧义到此被真实证据消解 |

反过来看：嗅探只在能读到 TLS/HTTP 头时有效，**非 TLS 的私有协议读不到**。
那种流量上「挑一个候选」严格好于「什么都不给」—— 至少域名规则有机会命中。

**FakeIP 一律关闭**（`FakeIPEnabled()` 恒假）。内核返回真实地址，用户空间再伪造
一套假地址会让「内核是唯一解析者」这个前提直接失效。

---

## 2. 🔴 修掉一个真回归：非 Linux 平台编译失败

上一轮的改动让 `hub/executor` 直接引用了 `resolver.KernelResolver` /
`NewKernelResolver` / `KernelDNSConfig` —— 而这些类型只在 `linux || android`
的构建标签下存在。实测：

```
$ GOOS=darwin GOARCH=arm64 go build ./hub/executor/
hub/executor/executor.go:257:31: undefined: resolver.KernelResolver
```

mihomo 是跨平台项目，这是必须避免的回归。修法是加一层**平台中立门面**：

| 文件 | 构建约束 | 作用 |
|---|---|---|
| `component/resolver/kernel_backend.go` | 无 | `KernelDNSConfig`（纯字段）+ `KernelBackend` 接口 + `ErrKernelBackendUnsupported` |
| `component/resolver/kernel_backend_linux.go` | `linux \|\| android` | 真实现 |
| `component/resolver/kernel_backend_stub.go` | `!linux && !android` | 返回 `ErrKernelBackendUnsupported` |

`KernelBackend` 把 Resolver / Service / Enhancer / Delegate 一起交出来，理由是
这三者**必须同时**替换：只换 Resolver 而留着旧 Enhancer，就会出现「DNS 由内核
解析、IP→域名 映射却还是一张空表」，表现为按域名分流时好时坏。

验证：`GOOS=linux`、`GOOS=darwin GOARCH=arm64`、`GOOS=windows GOARCH=amd64`
三个平台 `go build ./hub/executor/ ./component/resolver/` 全部通过。

---

## 3. 所有权生命周期：三个必须做对的地方

### 3.1 COMMIT 的代际只能从 GET_HEALTH 拿

内核的 COMMIT 处理器要求 `expected_generation` 与当前值**精确相等**，而
PREPARE/COMMIT/DISABLE 的处理器**只 return errno、不构造回包**（客户端因此必须
带 `NLM_F_ACK`，否则 `recvfrom` 永久阻塞）。所以流程只能是：

```
SET_TRUST → PREPARE（gen+1） → GET_HEALTH 读回 gen → COMMIT(gen)
```

这不是绕路，是那条 UAPI 的形状决定的。已在 `kernel_backend_linux.go` 的
`Commit()` 里注明。

### 3.2 重载不能无脑重建

ownership 是**一次性**的：已经是 ACTIVE 时再发 PREPARE 返回 `-EBUSY`。所以
`updateDNS` 记住当前的 `KernelDNSConfig`，配置没变就复用后端（只把
resolver/mapper 重新挂回去），变了才 `Close()`（交还 53）再新建。

### 3.3 关闭时必须**同时**摘掉全局 delegate

`closeKernelBackend()` 除了 `DISABLE` 与释放 fd，还必须
`resolver.SetKernelDNSDelegate(nil)`：那个全局指向刚被关掉的客户端，留着的话
eBPF 劫持路径（`listener/sing_ebpf/relay_dns.go` 查 `KernelDNSDelegateReady()`）
会继续把 DNS 报文送进一条已关闭的连接，症状是「DNS 全部超时」而不是明确失败。

---

## 4. 启动失败时的行为：明确记录 + 回退用户态

内核后端任何一条失败路径（fake-ip 冲突、缺 trust file、设备不存在、PREPARE/
COMMIT 失败）**都不 return**，而是落到下面的用户态管线，并在每一步打 Error 日志。

为什么不是直接返回：直接返回会把 `DefaultResolver` 留在原值（首次加载时就是
`nil`）——结果是「手机完全没有 DNS」，用户看到的是「网断了」，而不是「内核后端
没起来」。回退至少让网络可用，且姿态变化是显式可见的。

**这里不存在「两个 DNS 处理器串联」的风险**：能走到失败路径就说明 COMMIT 没有
成功，53 的 NAT 拦截从未打开。

**FakeIP 冲突单独硬拒**：`dns.backend: kernel` + `enhanced-mode: fake-ip` 时，
内核返回真实 IP，映射永远不会建立、`IsFakeIP` 永远为假，规则会**静默地按错误的
前提**分流 —— 那种「看起来在跑、实际全错」比启动失败危险得多。

---

## 5. 两条所有权交接路径（一条被卡住）

| 路径 | 需要改什么 | 本轮状态 |
|---|---|---|
| **A. eBPF 放行**：代理把 `listeners[].dns-mode` 置 `off`，53 走 Netfilter | **需要改 BoxProxy 的配置生成器**（它注入 `listeners:` 块） | ⛔ **卡住** |
| **B. eBPF 转交**：保留 `hijack`，`dns.kernel-delegate-ebpf: true` 让劫持到的 raw wire 转给内核 | 只改 mihomo 配置 + mihomo 代码 | ✅ 已实现（`kernel_relay.go` + `relay_dns.go`） |

**为什么 A 卡住**：设备上跑的是 BoxProxy 应用（`com.boxproxy.box`，Rust 写的
`boxctl`），它从自己的 DB 生成 `run/state/startup-config` 并注入 `listeners:` 块。
**该应用的源码不在本机**（只有 APK 与官方 Magisk 模块 `boxp/upstream/boxproxy-box`，
后者是 shell 脚本的另一套分发）。`boxp/` 目录是 sing-box 的 Rust 重写项目，不是它。

A 路径要落地，生成器需要改三件事（记录下来待其源码可得时执行）：

1. 内核后端启用时，在 `listeners[].ebpf-in` 上写 `dns-mode: off`；
2. 保证**先**内核 PREPARE 成功、**再**用该配置重启核心（否则窗口期内无 DNS）；
3. 内核后端关闭时把 `dns-mode` 改回 `hijack`。

方案 §5.1 的「DNS 53 流量交给本项目，不再重定向进代理 DNS 管道」指的是 A；
B 是方案 §12.1 提到的兼容转发路径。**两条路径下「解析全在内核」这一点是相同的**
（B 的 relay 送的是原始 wire，代理不做任何解析），差别只在报文由谁转发。

---

## 6. 真机验证结果（2026-10-05）

分三阶段做，每阶段都可单独回滚。**设备最后已完全还原**（核心 md5
`0d5e82a1…`、配置 md5 `0a82d3f0…`，二者与改动前逐字节一致；模块卸载、0 告警）。

### Stage 1（零行为影响）：适配器 ↔ 内核那一层

只 `SET_TRUST + PREPARE`，不 COMMIT、不打开 NAT 拦截。跑 `resolver` 包的真机探针
（宿主上自动 skip）：

```
解析 example.com   -> 172.66.147.243   （经 Go 适配器走内核 DoH）
解析 www.baidu.com -> 36.152.44.93
反查 172.66.147.243 -> example.com  ✓
反查 36.152.44.93   -> www.baidu.com ✓
enhancer stats: lookups=3 hits=2 misses=1 errors=0 ambiguous=0
内核计数:       map_entries=4 map_hits=2 map_misses=1
```

**Go 侧与内核侧逐项对上**，说明手写偏移解析与内核真实产出的帧完全一致 —— 这是
宿主单测测不到的一层（宿主只能验证「解析器对我自己构造的帧」）。

### Stage 2（短暂接管）：完整所有权事务

`PREPARE → 读代际 → COMMIT → 接管态解析+反查 → DISABLE`，**跑两轮**（可重复性）：
`generation=2` → COMMIT 成功 → 解析 `example.com` → 反查回域名 → DISABLE →
`ownership=0 / listener_ready=0` → 手机 DNS 立刻回到原链路。

### Stage 3a：换真实核心二进制（配置不动）

用 NDK r29 + `with_gvisor with_ebpf` 编出 `1.10.0-kdgp4`，按 boxp 既有下发约定
（同目录临时文件 + 原子 rename，保留 `root:net_admin` / 6755 / `app_data_file`）
替换 `files/box/bin/mihomo`。核心正常起来、流量照常按规则分流、0 告警。

### Stage 3b：真正启用内核后端 —— **P4 的核心验收**

配置改为 `enhanced-mode: redir-host` + `dns.backend: kernel` +
`kernel-trust-file` + `kernel-delegate-ebpf: true`，模块以 `allow_intercept=1` 加载。

```
mihomo 日志: kernel DNS backend active: 53 ownership handed to the kernel (device=/dev/kdnsguard)
内核 health: ownership=2 (ACTIVE)  nat_seen=76  nat_redirected=72  map_entries=78  doh_ok=37
```

**决定性的一条**：从手机发一个**纯 IP、无域名**的连接

```
$ busybox nc 172.66.147.243 443          # 该 IP 就是 example.com 解析出来的
mihomo 日志: [TCP] 127.0.0.1:34657(busybox) --> example.com:443 match Match using 漏网之鱼
内核计数:    map_hits 0 -> 2
```

**连接被还原成了域名**，走的正是 `tunnel.needLookupIP()` → `KernelEnhancer` →
内核映射表 —— 这就是方案 §12.2 要证明的东西。若没有它，这一行日志的 `-->`
后面会是一个裸 IP，域名规则全部失效。

> 观测：真实流量里 `map_misses` 远多于 `map_hits`（数百 vs 2）。这是**正常混合**：
> 大量连接的目标 IP（代理节点、应用自己缓存的 IP、字面 IP）本就不在映射表里，
> 那些连接的域名由嗅探补齐；两者互为兜底。命中率取决于应用"先解析再连接"的
> 比例，不是缺陷指标。

---

## 7. 🔴 只有真机能抓到的两个 bug（都已修，并加锁）

### 7.1 `KDG_CMD_GET_HEALTH` 的编号写错

```
读代际: kdnsguard GET_HEALTH: netlink receive: operation not supported
```

编号是 **enum 位置 − 1**：`GET_HEALTH` 是 **11**，而我写成了 10 —— 那是
`GET_STATS`，内核没注册它的处理器，generic netlink 直接回 `-EOPNOTSUPP`。

**编译、`go vet`、宿主单测全都不会报。** 这正是 CI 之外必须有真机窗口的理由。

修法不只是改数字：新增 `kernel_uapi_test.go`，**从 C 头解析 `enum kdg_genl_cmd` /
`kdg_genl_attr` / `kdg_ioctl_op` 并逐项比对**（另外用 `cc` 编译 C 头比对
`sizeof`/`offsetof`）。反向注入验证过：把编号改回 10，测试立刻报
`KDG_CMD_GET_HEALTH: 客户端用 10，UAPI 头是 11`。

### 7.2 `Start()` 与 `Commit()` 用了**不同**的事务号

```
COMMIT: kdnsguard transaction 3: netlink receive: stale file handle   (-ESTALE)
```

两处各自调了一次 `time.Now().UnixNano()`，内核判 `tx != transaction_id` 直接拒绝。
**这不是测试的问题 —— `executor.go` 里是同一个写法，真实路径下 COMMIT 必然失败。**

根因是接口让调用方重复传一个已经记录过的值。改成 `Commit()` **不带参数**、用
`Start()` 记下的那一个：把「能传错」这件事从接口上消掉。

---

## 8. 从还原路径推出来的一个生命周期缺口（已修并真机验证）

ownership 是**进程级**状态：代理进程被 kill / 重启时没有任何人发 `DISABLE`，
于是 53 的所有权一直留在内核手里，而下一个进程的 `PREPARE` 会撞 `-EBUSY` ——
**一次核心重启之后就再也接管不了，只能靠 `rmmod` 清场。**

两处修法，都已在真机上验证：

1. `Start()` 遇到 `-EBUSY` 时：记一条 Warn，显式 `DISABLE`，**再重试一次 PREPARE**。
   合法的 owner 只可能是本模块的上一个进程（否则走不到这里）。
2. `Close()` 从「只在 committed 时 DISABLE」改为「只要 Start 成功过就 DISABLE」
   —— **PREPARE 成功但 COMMIT 失败**这一档很容易被漏掉：那时已建好 listener、
   占着 PREPARED 状态，只把 Go 侧引用置 nil 会让 listener 一直开着。

验证方式：先跑一次「COMMIT 后故意不交还」模拟崩溃（内核 `ownership=2`），
再跑一次正常流程 —— 第二次的 PREPARE 只可能走 EBUSY 恢复路径，它成功了，
结束时 `ownership=0 / listener_ready=0`。

顺带修了内核侧的一处**诊断缺口**：`GET_HEALTH` 原本从 `intercept_enabled` 反推
ownership，把 `PREPARED` 折叠成了 `NONE`。现在如实上报 `kdg_cfg.ownership`
本身 —— 「listener 已建好但没人有资格 COMMIT」恰恰是排障时最需要看见的那一档。

---

## 9. 术语澄清：P5 的「私人 DNS 状态桥」

用户 2026-10-05 明确：方案 §10 的「安卓私人 DNS 状态桥」指的是**内核态 DNS 的
效果与设置里的私人 DNS 一致**，**不是**去兼容/桥接安卓的设置与状态。

这把 P5 的范围缩小了一个数量级：内核侧 DNS 本来就是严格模式（单一上游 DoH、
证书验证、零明文回落），与私人 DNS 的 strict **行为等价**，只是由内核而非
Settings 提供。因此**不需要** AOSP DnsResolver/APEX 的状态桥，也不需要把
off/automatic/strict 语义搬进内核。

⚠️ **由此推出一条可测的配置约束：安卓私人 DNS 必须保持 `off`。** strict 走
**853 端口**，而方案 §10.3 说明了内核不能接管 853（证书语义不允许）——系统若
自己开 strict，就会绕过内核去连 853，变成两套解析器并存，而不是「等效」。

P5 剩下的因此是工程项（非 root 访问 `/dev/kdnsguard` 的 ueventd 规则、把
`private_dns_mode=off` 作为部署前提写进安装步骤），不是「拿不到 ROM/APEX 材料
就阻塞」的那类。

---

## 10. 仍然未覆盖

1. **eBPF 放行路径（§5 的 A 路径）** 仍卡在 BoxProxy 源码不可得；本轮走的是
   B 路径（delegate）。两条路径下「解析全在内核」相同，差别只在谁转发报文。
2. **长时间浸泡**：本轮每阶段都是分钟级窗口，没有跑"日常使用一整天"。
3. **FakeIP**：本轮把 `enhanced-mode` 临时改为 `redir-host`；长期是否放弃
   fake-ip 需要产品决策（方案 §12.2 的立场是首期返回真实 IP）。
4. **映射命中率的调参**：`map_misses` 占比高是正常的（见 §6 的观测），但
   「多少算好」需要真实使用数据来定。
