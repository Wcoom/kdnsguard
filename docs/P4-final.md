# P4 收尾：核心 DNS 移交 + Path A 真机接管

日期：2026-10-05。设备：OnePlus 13 / PJZ110，Android 16，内核
`6.6.118-android15-8-gf4dc45704e54-abogki20260727-4k`（**#16，本窗口只加载
模块，从未刷机**）。私人 DNS `off`。出口蜂窝 + USB rndis0 热点。

被测对象：

- kdnsguard HEAD 相对 `4e6ac65` 的本轮内核修复（字符设备 enter/exit、init
  回滚、`SO_REUSEADDR`）
- mihomo 分支 `mihomo/kernel-dns-backend` 相对 `6e5a9a302` 的本轮适配器修复
  （`Invalid()` 契约、SystemResolver 覆盖、`PatchFrom` 类型断言）

原始输出：[`docs/evidence/P4-final/`](evidence/P4-final/)（`host.log`、设备侧
`device/`、脚本、配置变体）。`SO_REUSEADDR` 的最小窗口脚本是
`reuse-window.sh`。

---

## 0. 一句话结论

**方案 §12 的主线在真机上接通了：mihomo 自身解析走内核字符设备，App 的
53 走 Path A（eBPF `dns-mode: off` + 内核 NAT），热点客户端同样由内核应答。**
窗口结束设备逐字节还原。本轮还修掉三处开窗口前就会让「移交」名不副实或让
`rmmod` 卡死的缺陷。

热重载「切到用户态再切回内核」在第一窗口撞上 `PREPARE -EADDRINUSE`（TCP
查询留下的 `TIME_WAIT` 占着 1054）。已用 `SO_REUSEADDR` 修掉，并在**独立
最小窗口**里用「TCP 查询 → DISABLE → 立刻 PREPARE」复现原故障条件后验证
通过。第一窗口后半段（注入 / SIGKILL）因 ownership 已被热重载关掉而**污染**，
不作通过依据。

---

## 1. 开窗口前修掉的代码缺陷

这些都是审计对照方案 §12.1 抓到的，宿主测试原先全绿。

### 1.1 `KernelResolver.Invalid()` 写反（方案点名警告过）

用户态 `dns.Resolver.Invalid()` 的语义是「能用才 true」。调用点
`Lookup*WithResolver` 在 `r.Invalid()==true` 时才使用 `r`，否则掉进
`SystemResolver`（明文 UDP `114.114.114.114` / `8.8.8.8`）。

内核适配器写成了「坏了才 true」。结果：节点域名、direct 出站、ECH、订阅
URL **全部旁路内核**。设备上 `ExchangeContext` 直调和 eBPF hijack 都不经过
这条辅助函数，所以 P4 Stage 3b 测不出来。

修法：`Invalid() { return r != nil && r.client != nil }`。契约测试
`TestKernelResolverInvalidMatchesLookupContract` 锁死布尔值；反向注入
（改回旧实现）立刻红。

### 1.2 `SystemResolver` 覆盖

`dns/system.go` 的 `init()` 永远建好一份明文 UDP 客户端。即便 `Invalid()`
契约正确，`ClearCache` / `ResetConnection` 仍无条件打它。内核后端成功时把
`SystemResolver` 换成同一份 `KernelResolver`，关闭时还原。

### 1.3 `PatchFrom` 类型断言会 panic

热重载从 kernel 退回用户态时，`DefaultHostMapper` 是 `*KernelEnhancer`，
旧代码 `old.(*dns.ResolverEnhancer)` 会炸。改成逗号 ok。内核映射的事实源
在内核里，用户态缓存接不上，跳过即可。

### 1.4 `parseDNS` 在 `backend: kernel` 时仍强制用户态 nameserver

成功路径不会实例化那些客户端，空列表却让配置解析失败。放宽
`backend == "kernel"` 时的「不得为空」检查。

### 1.5 `kdg_chr_write` / `kdg_chr_read` 的 `kdg_op_enter` 泄漏

校验失败路径（短写、ABI 不符、偏移≠0）在 `kdg_op_enter()` 之后直接
return，不调 `kdg_op_exit()`。一次畸形 write 就把 `kdg_active_ops` 留在
>0，`kdg_chardev_exit()` 永久等待，**`rmmod` 卡死**。旧写法还有「没加锁就
unlock」的双重解锁。宿主没有字符设备，正向查询也走不到这些分支。

修法：所有失败路径统一 `out_entered: kdg_op_exit(); kfree(kbuf)`。新增
`tools/chrneg.c`：10 个拒绝用例 × 64 次。真机 640/640、随后 `rmmod` 15 s
内完成。

### 1.6 init 失败回滚漏 `kdg_map_exit`

`sflight` / `pool` / `chardev` / `pernet` 四条错误路径没释放映射表。insmod
成功则无关，失败会漏 316 KiB。已补。

### 1.7 TCP 监听口没有 `SO_REUSEADDR`

TCP 查询走完，已 accept 的套接字在 `127.0.0.1:1054` 进入 `TIME_WAIT`
（约 60 s）。DISABLE 之后立刻 PREPARE，`kernel_bind` 得到 `-EADDRINUSE`。
第一窗口的「用户态 → 内核」热重载和「kill 后再 boxctl restart」都撞上。

修法：`kdg_listener_bind()` 在 `kernel_bind` 之前 `sock_set_reuseaddr`。
独立最小窗口：TCP 两次查询留下 `TIME_WAIT`，DISABLE 后立刻 PREPARE
成功（generation 2→5），COMMIT 后再查 UDP 成功。

---

## 2. 窗口怎么开、怎么关

Path A（方案 §5.1 正路），不是上一轮的 delegate：

```yaml
dns:
  enhanced-mode: redir-host          # fake-ip 与内核互斥
  backend: kernel
  kernel-device: /dev/kdnsguard
  kernel-trust-file: /data/local/tmp/kdg_root.pem
  kernel-delegate-ebpf: false
listeners:
- name: ebpf-in
  dns-mode: off                      # 53 放行到 Netfilter
```

核心换成 `1.10.0-kdgp4final`（`with_gvisor with_ebpf`，NDK r29）。模块
`allow_intercept=1`。major 从 dmesg 读，不写死 440。

还原：停核心 → chrneg → DISABLE → 原二进制 md5 `0d5e82a1…` → 原配置 md5
`0a82d3f0…`（与 P3 备份同一份）→ `rmmod`。私人 DNS 全程 `off`。内核未刷。
mihomo 窗口开始就是停的，结束仍停。

---

## 3. 结果

### 3.1 通过（第一窗口前半 + 复用窗口）

| 项 | 实测 |
|---|---|
| 内核后端启动 | mihomo 日志 `kernel DNS backend active: 53 ownership handed to the kernel`；health `ownership=2`、`listener_ready=1` |
| Path A：eBPF 不再劫持 53 | `getpeername()` 是真实 DNS IP（`223.5.5.5:53` / `8.8.8.8:53` / `[2001:4860:4860::8888]:53`），**不是** `127.x` |
| conntrack 反向映射 | IPv4 UDP/TCP → `src=127.0.0.1 sport=1054`；IPv6 → `src=::1 sport=1054` |
| 热点 PREROUTING | 笔记本 `dig @172.31.172.56 example.com` → NOERROR，两条 A，50 ms |
| 用户态 1053 | 无 UDP/TCP 监听（内核后端关掉了 `dns.listen`） |
| DoH 上游归属 | `ss` 上 mihomo 拥有的 `:443` = 0；conntrack 有 `49.234.186.103:443` |
| 池化 | `pool_connects=1`、`pool_reused=43`、`stream_limit=64`、槽位无泄漏 |
| 字符设备查询 | example.com / baidu / github 都有 A |
| REST `/dns/query` | HTTP 200，真实 A 记录（直调 `DefaultResolver.ExchangeContext`） |
| `Invalid()` 生效 | 启动瞬间、任何测试查询之前，`map_entries=27`、`doh_queries=39` —— mihomo 自己把节点/订阅域名走了内核 |
| 热重载同配置 | PUT 204，ownership 仍为 2 |
| 热重载切到用户态 | PUT 204，ownership 0（DISABLE 成功，`PatchFrom` 未 panic） |
| chrneg | 10 用例 × 64 = 640，失败 0；随后 `rmmod` 干净 |
| 告警 | `BUG/WARNING/Oops/CFI/Internal error` **0** |
| `SO_REUSEADDR` | TCP 留下 TIME_WAIT 后立刻 PREPARE 成功（独立窗口） |
| 还原 | 核心/配置 md5 与改动前逐字节一致；670 模块；私人 DNS `off` |

### 3.2 污染、不作通过依据

热重载切回内核（第一窗口，修 `SO_REUSEADDR` **之前**）PREPARE 报
`address already in use`，适配器回退用户态，ownership 停在 0。此后：

- 故障注入：App 查询打到真实的 `223.5.5.5`，返回 **NXDOMAIN / 94 ms**，不是
  内核 SERVFAIL / 1 s。字符设备仍能打到内核（`status=8 errno=110` = 上游被
  REJECT 后超时）—— 只证明字符设备通路还在，不证明接管还在。
- SIGKILL：「内核仍应答」是 Aliyun DNS 在答，ownership 已经是 0。
- 随后 `boxctl restart` 再次 PREPARE `EADDRINUSE`，回退用户态。

这些步骤的脚本还在 `evidence/P4-final/`，读的时候按本节理解，不要当验收绿。

### 3.3 测量口径上的两个坑（可复用）

1. **`nat_seen=0` 不否定 NAT 发生过。** health 是在 App 查询**之前**读的
   （部署刚结束 / 矩阵 A 段）。矩阵 B 的 netprobe 跑完，conntrack 已经有
   `127.0.0.1:1054` 的反向映射。hook_calls=36 是部署期的背景流量，分类器没
   把它们判成 DNS。**判据用 conntrack，不要用一张拍早了的计数快照。**
2. **设备上的 `grep` 会把 `>` 当重定向。** `grep -a "--> example.com"` 在
   toybox 下变成 `grep: Unknown option '>'`。IP-only 反查那一段因此没拿到
   mihomo 日志。P4 Stage 3b 已经用同一路径证过 enhancer；本窗口用
   `map_entries` 增长和 REST 查询代替，不把「日志里出现 example.com」写成
   本窗口证据。

### 3.4 没测到 / 测不了

- **uid-0 明文 53 REJECT**：本机 `iptables -m owner` 返回 Invalid argument
  （`xt_owner` 不可用）。计划用来证明 mihomo 内部 Lookup 不走明文 UDP 的
  那条规则插不进去。退化为「启动瞬间 map_entries>0 + REST 查询走内核」。
- **节点 delay 测试**：`/proxies` 里 VMess/Trojan/SS 等被包在策略组里，
  顶层一个都没扫到，targets 为空。没有打到 `ProxyServerHostResolver`。
- **FakeIP 产品决策**：窗口把 `enhanced-mode` 临时改成 `redir-host`，结束
  改回 `fake-ip`。长期是否放弃 FakeIP 仍待定（方案 §12.2）。
- **eBPF 生成器持久化**：`dns-mode: off` 是改 `startup-config`，BoxProxy
  从 DB 再生配置时会写回 `hijack`。受控窗口够用，无人值守常驻不够。
- 能耗、Wi-Fi↔蜂窝、netId/fwmark、IPv6-only 上游：与既有未覆盖清单相同。

---

## 4. 对照方案 §12

| §12.1 入口 | 本窗口 |
|---|---|
| KernelResolver，全部 DNS 网络查询调内核 | **DONE**（`Invalid()` 修好 + SystemResolver 覆盖）。启动瞬间 27 条映射、REST 查询走内核。节点 delay 没打到，但不阻塞「辅助函数已接到内核」 |
| KernelService，不进旧 DNS 查询/缓存管道 | **PARTIAL**：eBPF Path A 下 53 根本不进 relay；TUN / `type: dns` / REST DoH 仍走 `RelayDnsPacket` → `ServeMsg`（查询落在内核，多一次 unpack/pack） |
| executor 新 backend；热重载不覆盖 | **DONE**（同配置复用、切用户态不 panic）。切回内核的 `EADDRINUSE` 已在独立窗口修掉并验证 |
| relay_dns 默认把 53 交内核 | **DONE（Path A）**：`dns-mode: off`，eBPF 不劫持。生成器持久化仍卡住 |
| Enhancer 内核映射，FakeIP 关 | **DONE**（接口层）。配置层 fake-ip 仍回退用户态，窗口用 redir-host 绕开 |
| doh.go 新 backend 不实例化 | **DONE**（成功路径不调 `NewResolver`）。`SystemResolver` 的 UDP 客户端仍在 init 里建，但已被覆盖成 KernelResolver |

§12.2：集合/歧义/真实 IP 与上一轮相同。节点/订阅域名在本窗口由启动瞬间的
映射条目间接证明走了内核。

---

## 5. 下一步（不在本轮）

1. BoxProxy 配置生成器：内核后端启用时写 `dns-mode: off`，关闭时写回
   `hijack`（P4-adapters.md §5，源码仍不在本机）。
2. P5 工程项：ueventd 创建 `/dev/kdnsguard`、网络事件驱动 ownership、常驻
   交付（内建 vs LKM）。
3. FakeIP 产品决策。
4. `RelayDnsPacket` 在内核后端下改走 raw-wire（TUN / REST DoH 的包装开销）。
5. P7 全内核 H3；能耗（无功率仪，不宣传）。
