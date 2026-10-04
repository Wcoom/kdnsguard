# P3：全局 DNS 接管（真机验证记录）

日期：2026-10-05（北京时间）。设备：OnePlus 13 / PJZ110，Android 16，内核
`6.6.118-android15-8-gf4dc45704e54-abogki20260727-4k #16`。

本文件记录**实测到的事实与偏离**，不复述《便携设备全局 DNS 内核架构与实施方案》
的正文。方案 §16 给 P3 定的通过条件是「UDP/TCP、conntrack 回包、热点、网络切换
通过」，下面逐项对应。

> ⚠️ **本节的所有真机结论都是在一个受控窗口里取得的**：把代理核心的 eBPF
> `dns-mode` 从 `hijack` 改成 `off`，让 53 端口的所有权真正移交到内核，跑完
> 验收矩阵后**立即把配置改回 hijack 并重启核心**，配置与备份逐字节一致
> （md5 `0a82d3f0674a61c99bd7057d03dfc5ef`）。设备当前不处于接管态。

---

## 1. P3 的真正门槛：所有权在 socket 层，不在 Netfilter

2026-10-04 的路径取证结论在本次复现确认：

| 路径 | 实测 | 含义 |
|---|---|---|
| IPv4 连接式 UDP `->8.8.8.8:53` | `getpeername()` 返回 `127.x:33507` | mihomo 的 cgroup eBPF 在 **connect()/sendmsg() 层**改写了目的地址 |
| IPv4 TCP `->223.5.5.5:53` | 同上 | TCP 也一样，不能只按 UDP 推断 |
| IPv6 UDP/TCP `->2001:4860:4860::8888:53` | 真实 IPv6 对端，69–217 ms | 当前代理 `ipv6-mode: off`，IPv6 53 **未被接管** |

cgroup `connect`/`sendmsg` 程序跑在 socket 系统调用入口，**早于** Netfilter 的
`LOCAL_OUT`。所以只要代理还在 hijack，kdnsguard 的 NAT hook 对 IPv4 53 一个包都
看不到——这不是配置问题，是所有权问题。

**让出机制不需要改 eBPF 源码**。`common/ebpf/native/cgroup.bpf.c:571`：

```c
if (port == 53U && config->dns_mode == SB_EBPF_DNS_MODE_OFF) return 1;
```

即 `listeners[].dns-mode: off` 会让 53 直接放行到 Netfilter。这正是方案 §5.1
「DNS 53 流量交给本项目，不再重定向进代理 DNS 管道」的落点。

实测（改配置 + `boxctl service restart` 后）：

```
uid=0 mode=udp target=223.5.5.5:53
peer=223.5.5.5:53            ← 不再是 127.x
local=10.86.13.30:48921
```

---

## 2. 两条路径的地址选择**不可互换**

`net/netfilter/nf_nat_redirect.c` 按 hooknum 分支：

- `LOCAL_OUT` → 目的地址改成 **loopback**（IPv4 `127.0.0.1`，IPv6 `::1`）；
- `PREROUTING` → 目的地址改成**入接口自己的地址**（IPv4 取 `ifa_list` 首项，
  IPv6 取第一个 scope 匹配的可用地址）；找不到地址时**返回 `NF_DROP`**。

conntrack 的反向映射期望「回包源地址 = 改写后的目的地址与端口」，所以：

- loopback listener 服务 LOCAL_OUT（若绑 `0.0.0.0`，回包源地址会由路由选成网卡地址，
  元组对不上 conntrack，回包会被当成新包丢掉）；
- **必须**有一份绑在客户端入口接口地址上的 listener 服务 PREROUTING，
  否则热点客户端的 53 会被改写到没人听的地方。

实测到的反向映射（这是 P3 最硬的一条证据）：

```
# 本机自身发出的查询
ipv4 udp src=10.86.13.30 dst=223.5.5.5 sport=55015 dport=53
         src=127.0.0.1  dst=10.86.13.30 sport=1054 dport=55015
ipv6 tcp src=240a:…:ea7f dst=2001:4860:4860::8888 sport=56800 dport=53
         src=::1        dst=240a:…:ea7f    sport=1054 dport=56800

# USB 共享客户端（本机笔记本 10.56.139.42）发出的查询
ipv4 udp src=10.56.139.42 dst=10.56.139.93 sport=55038 dport=53
         src=10.56.139.93 dst=10.56.139.42 sport=1054 dport=55038
```

最后一条同时证明了**热点路径**：查询从 PREROUTING 进入，被改写到 rndis0 自己的
地址 `10.56.139.93:1054`，由客户端入口 listener 应答，回包经 conntrack 还原成
「来自 10.56.139.93:53」。

---

## 3. 本轮修掉的两个真实缺陷

### 3.1 缺陷一：IPv4 地址添加**不产生 netdev 事件**

第一版只挂 `netdev_chain`，结果是「接口先 up、地址后配」这条路径**永远不会被
接管**，而日志上一切正常（只在客户端连不上时才暴露）。

定位过程（值得记住，因为症状极具误导性）：用 dummy 接口做实验，日志显示

```
usb0: 入口事件 ev=1 running=1 flags=0x83
usb0: read_addrs ip_ptr=… in_dev_dev=usb0 dead=0 n_ifa=0 has4=0
```

即接口 up、`in_device` 有效且属于正确的设备，但 `ifa_list` 链**是空的**——而
同一时刻 `ip -o addr show usb0` 明确显示 `192.168.99.1/24` 在位。矛盾点在于：
`ip addr add` 走的是 `inet_insert_ifa()`，它发的是

```c
blocking_notifier_call_chain(&inetaddr_chain, NETDEV_UP, ifa);
```

—— **`inetaddr_chain`，不是 `netdev_chain`**。`netdev_chain` 只在链路状态变化时
发事件。

修法：额外注册 `register_inetaddr_notifier()` 与 `register_inet6addr_notifier()`，
从 `ifa->ifa_dev->dev` / `ifa->idev->dev` 取回 net_device 后走同一条 sync 路径。
这两条链都是 blocking notifier，回调在进程上下文、可睡眠，且调用时持有 rtnl
（所以回调里同样不能再取 rtnl）。

### 3.2 缺陷二：上游失败时**静默丢包**

原实现对 `kdg_resolve()` 的失败是 `if (ret) goto out;` —— 不回包。客户端只能等到
自己的超时（真机实测 3.05 s），而且拿不到任何可区分信号。方案 §18 要求的是
「返回 SERVFAIL/API 错误」。

修法：新增 `kdg_wire_make_error_response()`，按请求原样回填 ID 与问题区，置
`QR=1`、给定 rcode、其余计数为 0。三处刻意取舍：

1. **不回填 OPT**：OPT 的 TTL 字段承载 ext-rcode/版本/flags，正确回填要连 badvers
   语义一起做，而失败应答上没有收益（RFC 6891 允许应答方不实现 EDNS）。少一个出错面。
2. **清 AA/TC/RA/AD/Z，保留 opcode/RD/CD**：AD 尤其不能带——那是「已做 DNSSEC
   验证」的声明，失败应答上带它等于伪造安全状态（§8/§10.1）。
3. **问题区解析失败时回 FOrmERR 且 `QDCOUNT=0`**，而不是整体拒绝：畸形请求也应当
   收到应答。

rcode 映射：内核侧 wire 校验失败（`-EBADMSG`）→ FORMERR；配额/队列满 → SERVFAIL
（§7.3 明确要求）；其余 → SERVFAIL。

---

## 4. 验收矩阵（实测）

### 4.1 功能

| 项 | 结果 |
|---|---|
| LOCAL_OUT IPv4 UDP / TCP / 非连接 sendto | 全部由内核应答（`rcode=0`，真实 IP，非 fake-ip） |
| LOCAL_OUT IPv6 UDP / TCP | 同上 |
| 应用可见性 | `getpeername()` 仍是原始 DNS 服务器地址，改写对调用方不可见 |
| conntrack 反向映射 | IPv4 → `127.0.0.1:1054`；IPv6 → `[::1]:1054`（见 §2 原文） |
| **热点 / USB 共享（PREROUTING）** | 笔记本（10.56.139.42）查手机 rndis0:53 → 内核应答，`elapsed=2 ms`（缓存命中）；conntrack 反向映射为 `10.56.139.93:1054` |
| **客户端入口生命周期** | dummy 接口：建地址 → 绑定 listener；改地址 → 重绑；删地址/删接口 → 释放。`client_ifaces` 计数随之 1↔2 |
| 缓存 | 冷查询 143–242 ms（含 TLS 握手），热查询 **0–1 ms**；`cache_entries` 与 `cache_hits` 一致 |
| 上游健康 | TLS 1.3 + ALPN h2，`doh_last_status=200`，`doh_last_rtt_ms` 200–300 ms |

### 4.2 故障注入（方案 §17.2 红线）

手段：`iptables -I OUTPUT 1 -d 49.234.186.103 -j REJECT`（第一次用 `blackhole` 路由
**无效**——Android 的按网络策略路由表优先于 main 表，注入没生效，这点本身值得记住）。

| 观察 | 结果 |
|---|---|
| UDP 查询 | **1.007 s 收到 `rcode=2`（SERVFAIL）**，不是等到超时 |
| TCP 查询 | 0.999 s 收到 SERVFAIL |
| 字符设备 API 面 | `status=11`（`KDG_ST_EUPSTREAM`）`errno=111` |
| **是否回落运营商 DNS** | **否**。同一窗口内只要查询失败就没有任何答案返回；若发生回落，查询会成功 |
| 解除注入后 | 立刻恢复（`rcode=0`，缓存继续命中） |
| 残留 | iptables 规则计数 0，无残留 |

### 4.3 退出与恢复

`DISABLE` 后 `ownership=0`、四个 listener 全部消失、DNS 立刻回到原链路；
`rmmod` 干净；dmesg 全程 `BUG/WARNING/Oops/CFI failure = 0`。

---

## 5. 落地后独立审核发现并修掉的问题（同日）

P3 的实现提交前跑了一轮独立审核（`/code-review`，high）。真机上跑通并不等于
并发与地址选择规则都对了 —— 下面 5 条都是**真机上不会暴露**的那类问题，
已全部修掉并重新做了真机回归（PREPARE / 客户端入口生命周期 / DISABLE 后重建 /
rmmod，`client_ifaces` 计数与监听集合全部符合预期，0 告警）。

| # | 问题 | 后果 | 修法 |
|---|---|---|---|
| 1 | `kdg_client_read_addrs()` 绑「第一个**全局** IPv6 地址」，而 `nf_nat_redirect_ipv6()` 在全局目的地下取「第一个**可用**地址」且**完全跳过 scope 过滤** | 地址表里链路本地排在全局之前时，改写目标 ≠ 绑定地址 ⇒ 客户端 IPv6 查询被改写到一个没人监听的地址上（静默黑洞）。当前设备恰好是全局排在前面，所以真机测不出来 | 逐字复刻 `nf_nat_redirect_ipv6_usable()`：绑「第一个可用地址」，只有**它**是全局时才申报 `KDG_CLI_CAP_V6` |
| 2 | `kdg_listener_prepare()` 持 `g_listener.lock` 做上游 DoH 探测 | 该锁现在也被通知链回调持有，而回调**持 rtnl** 进来 ⇒ 一次慢探测（实测 143–257 ms，上游异常时接近 3 s）会把全系统的 rtnl 按住同样久 | 探测移到锁外；状态机仍在锁内串行 |
| 3 | `kdg_listener_stop()` 先拆客户端 listener、后置 `stopping`/`ready` | 拆除期间 `kdg_listener_ready()` 仍报 true，并发 PREPARE 会不建 listener 就返回成功，随后 COMMIT 可能打开接管 ⇒ 53 被改写到正在被拆掉的端口，DNS 全断 | 先置 `stopping`+清 `ready`，再动 socket；PREPARE 在发布 `ready=true` 前**再查一次** `stopping` |
| 4 | `kdg_listener_stop()` 与通知链回调对客户端入口表无互斥 | 回调可在 `release_all` 腾出槽位后立刻又建一个 listener 而本次 stop 不管它；到模块退出就是「kthread 仍在跑已释放的模块镜像」 | 靠 `write(stopping) → unregister → release` 的次序做互斥（注销本身会等在途回调：netdev 链的回调持 rtnl 而注销要取 rtnl；inet/inet6 是 blocking notifier，注销要写锁而回调持读锁）。~~额外持 rtnl 圈住 release~~ 被否决——那会把 rtnl 按住 `kthread_stop` 的时长（客户端线程可能正卡在一次 DoH 往返里） |
| 5 | `kdg_client_sync()` 不区分子网命名空间 | 通知链是全局的，而绑定固定 `init_net`；容器/VPN 里出现同名接口会白占 4 个槽位之一并每次事件打一条告警 | 入口处加 `dev_net(dev) != &init_net` 早退 |

**一条被审核本身纠正的做法**：最初为了修 #4，我打算在 `kdg_listener_stop()`
里 `rtnl_lock()` 圈住客户端拆除。查 `net/core/dev.c` 后发现
**`unregister_netdevice_notifier()` 内部自己会取 rtnl** —— 圈进去就是自死锁。
顺着这条线才想清楚：注销动作本身已经等完了在途回调，额外持 rtnl 既不必要
又会让 rtnl 被按住 `kthread_stop` 的时长。最终采用次序保证，不引入新的
rtnl 长持有。

---

## 6. 尚未覆盖 / 明确不在本轮范围

1. **真正的 Wi-Fi ↔ 蜂窝切换未做**。当前手机是本机（笔记本）唯一的上网出口，
   切换会切断本次验证的通路。本轮用**接口/地址生命周期**（建地址、改地址、删地址、
   删接口）覆盖了客户端入口的重建逻辑，用**每次查询重连**（见 README：上游按查询
   建连）覆盖了「上游跟随路由」这一面，但**没有**做真实的默认网络切换实测。
2. **内核 DoH 上游的旁路是"事实上成立"而非内核强制**。conntrack 显示内核发往
   `49.234.186.103:443` 的连接是**直达**（`src=10.86.13.30 dst=49.234.186.103:443`，
   未被改写到 127.x）——因为内核 socket 建在线程上下文里、不在代理附着 BPF 的
   cgroup 中。这是当前代理附着位置的副产品，不是内核侧的强制旁路。方案 §5.3 要求
   的 socket-cookie 旁路集合属 **P4**（与代理的接口协作）。
3. **`0.0.0.0` 通配 listener 被明确否决**。它能让 PREROUTING 无需按地址绑定，
   但 (a) LOCAL_OUT 的回包源地址会选错、对不上 conntrack；(b) 会在运营商接口上
   暴露一个解析器。当前「按接口地址绑定 + 入口白名单」的设计两条都避开。
4. **网络身份（netId / fwmark / 每个网络的隔离）尚未实现**。当前所有路径共用
   一个上游 profile，方案 §5.3 与 §7.2 的多网络隔离属后续阶段。
5. **上游仍是 IPv4 bootstrap**。IPv6-only 网络下不可达（方案 §17.1 明确要求
   「必须证明 IPv6-only 可达方案后再标称支持」）。
6. `nf_nat_redirect_*` 在 PREROUTING 找不到接口地址时返回 `NF_DROP`。当前靠
   「只在 listener 绑定成功的接口上接管」把这条路封住，但没有在 hook 里再兜一层
   —— 若日后放宽白名单条件，必须同时补上这个防御。

---

## 7. 相关代码

| 文件 | 本轮变化 |
|---|---|
| `kernel/kdg_listener.c` | 客户端入口表 + netdev/inet/inet6 三条通知链；绑定函数泛化到任意地址；失败应答构造；线程错误分类（原先 socket 出错会 100% CPU 忙等） |
| `kernel/kdg_nat.c` | 判据收紧为**目的端口 53**；PREROUTING 入口白名单 + 按地址族的能力位；IPv6 scope 判据修正 |
| `kernel/kdg_wire.c` / `.h` | 新增 `kdg_wire_make_error_response()` |
| `kernel/kdg.h` / `kdg_listener.h` | 客户端入口表、`kdg_v6_addr_is_global()` |
| `kernel/kdg_main.c` | `client_ifaces` 模块参数 |
| `include/uapi/kdnsguard.h` | 新增健康属性（fwd_seen / fwd_bypassed / sport53 / client_ifaces / listener_ready） |
| `tools/kdgctl.c` | 健康属性名表；`client_ifaces` 等在诊断输出里带名字 |
| `tests/test_wire.c` | 失败应答的 24 条断言 |

### 一个容易写错、值得单独记下的点：IPv6 的 scope 判据

`__ipv6_addr_type()` 把 scope 编码在 **bit16+**（`IPV6_ADDR_SCOPE_TYPE(s) = s << 16`），
而 `ipv6_addr_type()` 只保留低 16 位 —— 于是**低字节里的 `0x00f0` 区间承载的是
「非全局」的类别位**（loopback `0x10` / link-local `0x20` / site-local `0x40` /
compatv4 `0x80`），全局单播恰好一位都不占。**「与 `IPV6_ADDR_SCOPE_MASK` 相与为 0」
才等价于「全局」**。`IPV6_ADDR_SCOPE_GLOBAL`(0x0e) 属于另一套编码，只能与
`ipv6_addr_src_scope()`（即 `>>16`）的结果比较。

最初写成 `(type & MASK) != IPV6_ADDR_SCOPE_GLOBAL`，后果是**所有全局地址都被判成
非全局**，客户端入口的 IPv6 listener 一个都建不起来；日志上只表现为「IPv4-only」，
不容易当场看出。判据现已集中在 `kdg_v6_addr_is_global()` 一处，注释里写了完整的
推导，并对照 `nf_nat_redirect_ipv6_usable()` 的写法交叉验证。
