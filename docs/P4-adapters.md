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

## 6. 本轮验证到哪一步

| 项 | 状态 |
|---|---|
| 三个平台编译 | ✅ linux / darwin-arm64 / windows-amd64 |
| `go vet` | ✅ 无告警 |
| `component/resolver` 单测 | ✅ 12 个（含帧解析、歧义保序、truncated、miss 与 error 区分、nil 安全） |
| 全仓单测 | ✅ 59 包通过；4 个失败（VMess interop ×3、sudoku HTTPMask）**已在基线提交 `official-20260828` 上用干净 worktree 复现，属既有环境问题**（需要外部 v2ray 二进制），非本次引入 |
| **真机** | ⬜ **未做**（按约定另开窗口） |

真机要跑的事（下一窗口）：

1. 模块 `insmod allow_intercept=1`，配好 `dns.kernel-trust-file`；
2. 核心配 `dns.backend: kernel` + `enhanced-mode: redir-host`；
3. 先试 B 路径（不动 BoxProxy 配置）：`dns.kernel-delegate-ebpf: true`；
4. 看启动日志里的 `kernel DNS backend active`；
5. 关键验收：**建立一条只有 IP 没有域名的连接**，确认 `FindHostByIP` 从内核
   拿到域名（对照 `map_hits` 计数增长），且规则按域名命中。
