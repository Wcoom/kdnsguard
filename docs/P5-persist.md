# 常驻交付与方案边界（H3 / App 内置 DNS）

日期：2026-10-05。设备 PJZ110，内核 #16，**当前处于接管态**（不再是「窗口结束即还原」）。

上游：`https://d6382545.6.00p.net/gd/h596382545`（内核 H2 DoH，TLS 1.3）。
`h3://` 同一 identity 的 HTTP/3 路径**本轮不能启用**，理由见 §3。

---

## 1. 现在设备上实际在跑的

| 项 | 值 |
|---|---|
| 模块 | `kdnsguard` 已加载，`allow_intercept=1` |
| `/dev/kdnsguard` | major 440，开机脚本按 `/proc/devices` `mknod` |
| mihomo | `1.10.0-kdgp4final`（md5 `dae11afe…`），原核心备份在 `/data/adb/kdnsguard/mihomo.stock` |
| 配置 | `enhanced-mode: redir-host`、`backend: kernel`、`dns-mode: off` |
| 私人 DNS | `off`（脚本会再写一次） |
| health | `ownership=2`、`listener_ready=1`、DoH 走内核连接池 |
| App 明文 53 | Path A：eBPF 不劫持，Netfilter NAT 到 `127.0.0.1:1054` / 接口地址:1054 |
| 热点 | PREROUTING 客户端入口 listener（rndis0 等） |

**FakeIP 已关掉。** 内核返回真实 IP；`fake-ip` 与内核后端互斥，适配器会回退用户态。方案 §12.2 的立场就是「首期返回真实 IP」。依赖 FakeIP 的规则会按真实地址分流，嗅探 `override-destination: true` 仍可用。

卸载：`sh /data/adb/kdnsguard/disable.sh`（还原核心/配置、`rmmod`、删 `service.d` 脚本）。

---

## 2. 开机怎么接上（P5 常驻，LKM 形态）

不是内建进内核。模块仍是树外 `.ko`，放 `/data/adb/kdnsguard/`。

```
service.d/99-kdnsguard.sh  （boot.sh）
  等 bootanim 停
  insmod allow_intercept=1
  mknod /dev/kdnsguard
  等 BoxProxy 写出 startup-config
  apply.sh：换核心（md5 不对才换）+ 补丁 YAML + boxctl restart
  loop.sh：每 20 秒再跑一次 apply.sh（已是目标态则什么都不做）
```

`loop.sh` 挂在 `service.d` 的子 shell 里，是 init 的子孙。**不要**用 `adb su -c` 拉守护进程 —— KernelSU 的 `su -c` 会话结束会清掉整棵进程树（`setsid`、`start-stop-daemon`、double-fork 都活不过）。这就是为什么没用 `inotifyd` 做即时监视。

BoxProxy 从 DB 重生配置（打开 App、保存、`boxctl boot`）后，最多 20 秒会被补回 `backend: kernel` + `dns-mode: off`。换内核镜像后必须用匹配 vermagic 的 `.ko` 再装一次（AnyKernel3 `do.modules=0` 不装模块）。

安装（开发机）：`bash deploy/install.sh`

---

## 3. H3 / DoH3：按方案原文停在 H2

用户点名的 `h3://d6382545.6.00p.net/gd/h596382545` 是方案 §6.1 的配置表示，`:scheme` 仍是 `https`。§6.5 写明：H3 是独立立项，**禁止偷放用户态握手**；TLS 若不能提供 wolfSSL 级 QUIC API，必须停在 H2。

本轮核验（2026-10-05）：

| 阻塞 | 事实 |
|---|---|
| mbedTLS 3.6.7 **没有 QUIC API** | 全树无 `quic.h`。`mbedtls_ssl_set_export_keys_cb` 是 NSSKeylog / EAP-TLS 用的密钥导出，不是加密级别 / CRYPTO 流 / transport parameters |
| 方案指定的 wolfSSL `quic.h` | 已因 GPLv3（GPLv2 例外清单不含 Linux 内核）**拒绝** |
| 本机 6.6.118 树 **没有** in-tree QUIC | 无 `CONFIG_INET_QUIC` / `CONFIG_IP_QUIC` / `net/quic` |
| `lxin/quic` | 内核侧许可证实为 **GPL-2.0+**（`third_party.lock` 的 NOASSERTION 过时，是 GitHub 没识别拆开的 COPYING）。**设计仍把握手放在用户态**（GnuTLS / libquic / tlshd）。按 §6.5 用它当「全内核 H3」是禁止的 |
| nghttp3 | MIT，未引入 |

**H3 capability 保持 false。** 不要把用户态握手的 QUIC 叫做全内核 DoH3。H2 DoH 是已验证、已常驻的主线。

---

## 4. App 内置 DNS：方案 §1.1 / §11 的边界

| 流量 | 本交付 |
|---|---|
| 任意目标 UDP/TCP **53** | **已接管**（Path A，含系统和 App 自带明文客户端、热点） |
| TCP 853 DoT | **不能** NAT 替换（证书语义，§10.3）。私人 DNS 必须 `off` |
| UDP 853 DoQ | 未做精确目标限制 |
| 已知专用 DoH endpoint | 未做 IP 黑名单；可后续加窄范围限制 |
| 任意 TCP/UDP **443** 加密 DNS | **无法**无损识别（共享 IP/CDN、ECH、私有隧道）。禁止全站 TLS 中间人，禁止默认封锁 UDP 443 |
| VPN 内嵌 DNS | 隧道外往往只看到加密流量 |

「拦截掉 App 内置 DNS」在方案里只保证**明文 53**。加密内置 DNS 没有通用、无损、低能耗的识别方法 —— 这不是还没做，是做不到。

---

## 5. 对照方案目标

| 目标 | 状态 |
|---|---|
| 全局明文 DNS 由内核解析 | ✅ 常驻 Path A |
| 上游固定账户 DoH（H2） | ✅ `d6382545.6.00p.net/gd/h596382545`，证书验证，零明文回落 |
| mihomo DNS 走内核 | ✅ KernelResolver + SystemResolver 覆盖；`Invalid()` 契约已修 |
| App 明文 53 走内核 | ✅ eBPF `dns-mode: off` + NAT |
| 上游 H3 | ⛔ 方案门槛未过，停在 H2 |
| 任意 App 加密 DNS | ⛔ 方案 §1.1 不可实现边界 |
