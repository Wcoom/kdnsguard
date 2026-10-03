# kdnsguard P0 结论：环境锁定与方案事实核验

核验日期：2026-10-03。核验人：Wcoom + Claude Code。
设备：OnePlus 13 / PJZ110，Android 16 / SDK 36，运行内核
`6.6.118-android15-8-gf4dc45704e54-abogki20260727-4k`。

本文只记录**实测结论**，不复述方案原文。凡与方案冲突者一律标注「更正」并给出取证方式。

---

## 1. 结论摘要

| 类别 | 结论 |
|---|---|
| 方案的核心 TLS 依赖 | 🔴 **不可用**（许可证），已按方案自设规则换选 mbedTLS |
| Netfilter/NAT 接管入口 | ✅ **可用**，且已在真机跑通 |
| 内核自带密码学与 X.509 | ✅ **齐备**，存在纯 GPLv2 的备用路线 |
| 方案 §2.1 的 nftables 记述 | ⚠️ **错误**（读到了不可信的配置源），已更正 |
| 内核骨架 | ✅ 已建成并真机验证（模块加载/注册/调用/卸载全链路） |

---

## 2. 逐项核验

### 2.1 方案 §2.1「`# CONFIG_NF_TABLES is not set`」——**更正**

`out/.config` 的真值是 **`CONFIG_NF_TABLES=y`**，且设备侧
`grep -c ' nft_' /proc/kallsyms` 有 892 个符号。

**误判来源**：方案那一行读的是 `/proc/config.gz`。该文件用汇编 `.incbin` 把配置
嵌进 `.rodata`（`kernel/configs.c`），这个依赖对 ccache 与 ThinLTO 后端缓存
**均不可见**，因此它**永远停留在第一次构建时的那份配置**。

**判据纠正**：核配置只认 ① `out/.config` ② `/proc/kallsyms` 的符号。
不认 `/proc/config.gz`。（此结论与 `oplus13/CLAUDE.md` 第 27 项的 C-16 一致。）

### 2.2 方案 §5.2 的接管入口——**确认可用**

| 符号 | 位置 | 导出方式 | `Module.symvers` CRC |
|---|---|---|---|
| `nf_nat_ipv4_register_fn` | `net/netfilter/nf_nat_proto.c:822` | `EXPORT_SYMBOL_GPL` | `0x2b347909` |
| `nf_nat_ipv6_register_fn` | `net/netfilter/nf_nat_proto.c:1061` | `EXPORT_SYMBOL_GPL` | `0xd821a5c9` |
| `nf_nat_redirect_ipv4/ipv6` | `net/netfilter/nf_nat_redirect.c:79/138` | `EXPORT_SYMBOL_GPL` | 有 |
| `nf_nat_setup_info` | `net/netfilter/nf_nat_core.c:852` | `EXPORT_SYMBOL` | 有 |
| `nf_register_net_hooks` | `net/netfilter/core.c` | `EXPORT_SYMBOL` | 有 |
| `sock_create_kern` / `kernel_sendmsg` / `kernel_recvmsg` | `net/socket.c` | `EXPORT_SYMBOL` | 有 |

**方案 §5.2 关于「不能在任意普通 hook 里调一次 `nf_nat_setup_info()` 就认为正反向
NAT 完整了」的警告是完全正确的**。读本树 `nf_nat_core.c:nf_nat_inet_fn()` 可确证
正确做法：

1. `nf_nat_ipv4_register_fn()` 把你的 ops 插进 **nat 核心自己的 hook** 的
   `priv->entries` 里（`nf_hook_entries_insert_raw`）；
2. `nf_nat_inet_fn()` 只对 `IP_CT_NEW`/`RELATED` 且 `nf_nat_initialized()` 为假的
   连接遍历这些内层 ops；
3. 任一内层 ops 建立 NAT 后 `goto do_nat → nf_nat_packet()`，由 **nat 核心**完成
   改写并借 conntrack 建立反向转换。

**推论（重要，影响性能模型）**：内层 hook 的调用频率是**每个新连接一次**，
不是每包一次。实测印证：两次 `nslookup` 产生 14 次调用。

### 2.3 内核自带能力——**超出方案预期**

| 能力 | 配置真值 | 意义 |
|---|---|---|
| X.509 证书解析 | `CONFIG_X509_CERTIFICATE_PARSER=y` | 证书解析不必从零写 |
| PKCS#7 | `CONFIG_PKCS7_MESSAGE_PARSER=y` | |
| 系统信任密钥环 | `CONFIG_SYSTEM_TRUSTED_KEYRING=y` | |
| AES-GCM / SHA-256 / SHA-512 / ECC / ECDH / RSA / ECDSA / ChaCha20-Poly1305 | 全部 `=y` | TLS 1.3 所需原语齐备 |
| `CONFIG_TLS` | `# is not set` | 与方案一致；本路线不依赖 kTLS |

**这意味着：即便 mbedTLS 路线受阻，仍存在纯 GPLv2 的备用路线**——用树内 crypto +
树内 X.509 手写 TLS 1.3 客户端（仅需自补 HKDF，树内只有 fscrypt 的私有实现）。
零第三方、零许可风险，代价是工作量最大。

⚠️ `CONFIG_CRYPTO_CURVE25519` **未启用**，X25519 当前不可用。P-256 可用，而
RFC 8446 将 secp256r1 列为 TLS 1.3 必须支持项，故不阻塞；需要 X25519 时加一个 CONFIG。

⚠️ `CONFIG_KUNIT=m`。KUnit 的 Kconfig 要求 `KUNIT=y` 才编入用例，
**设备构建里 KUnit 用例根本不会被编译**。这是本项目把 DNS wire 校验器做成
双态可编译（宿主 gcc + ASan/UBSan）的直接原因。

### 2.4 许可证审计——**方案的依赖路线受阻**

wolfSSL 的 `LICENSING` 给出的 GPLv2 例外是**封闭清单**
（MariaDB Server / MariaDB Client Libraries / OpenVPN-NL / Fetchmail / OpenVPN /
SWUpdate / RPCS3 / VDE / U-Boot(Cisco)），**不含 Linux 内核**；
`linuxkm/README.md` 亦未提供额外授权。GPLv3 代码与 GPLv2-only 的内核组合，
除非取得商业许可，否则不成立。

方案 §3.1 自己写了判定规则——「若无法获得适用授权，应停止此依赖路线并重新选型」。
**规则触发**。经用户裁决改用 **mbedTLS**（`Apache-2.0 OR GPL-2.0-or-later`，
按 GPL-2.0 使用与内核相容）。

其余依赖许可均干净：nghttp2 / nghttp3 / llhttp = MIT，dnsproxy = Apache-2.0，
ldns = ISC。⚠️ `lxin/quic` = **NOASSERTION**（GitHub 未能识别标准许可），
引入前必须人工核实。

详见 `third_party/third_party.lock`。

---

## 3. 内核骨架：真机验证记录

`kdnsguard.ko` 以树外模块构建（`M=...`），针对本地 `out/` 的同一份内核。
vermagic 与设备 `uname -r` 逐字符一致。

### 3.1 验证结果

| 项 | 结果 |
|---|---|
| `insmod` | exit=0 |
| NAT hook 注册 | dmesg `NAT hook 已注册（IPv4+IPv6，LOCAL_OUT + PREROUTING）` |
| 模块参数 | `allow_intercept=N` / `listen_port=1054` / `deadline_ms=3000` 正确暴露 |
| Generic Netlink 族 | `KDNSGUARD` 存在，id=72，version=1 |
| `CAPS` 回包 | ABI v1，capability=`0x00000003`（IPv4\|IPv6，**如实申报，未实现项不置位**） |
| `GET_HEALTH` | 嵌套块正确解析，`LAST_ERRNO=0xffffff95=-107=-ENOTCONN`（传输层未落地，不假报正常） |
| **NAT hook 实际被调用** | ✅ 14 次 |
| **DNS 识别正确** | ✅ 14/14（`NAT_SEEN=14`） |
| 接管未启用时**零改写** | ✅ `NAT_REDIRECTED=0`，`NAT_BYPASSED=14` |
| DNS 功能无影响 | ✅ 加载与卸载前后 `nslookup` 均正常 |
| 干净卸载 | ✅ `rmmod` exit=0，genl 族消失 |
| 内核告警 | ✅ dmesg 无 BUG/WARNING/Oops，仅有本模块的加载/卸载信息 |

为做上述验证，另交付了 `tools/kdgctl`——一个 **freestanding aarch64 静态二进制**
（4.2 KB，不链接任何 libc，只发裸系统调用）。它同时证明
`include/uapi/kdnsguard.h` **真的能被用户态使用**。

### 3.2 排障中定位的两个真实缺陷（已修）

#### 缺陷 1：`skb_header_pointer()` 返回值被丢弃

```c
/* 错误写法 */
skb_header_pointer(skb, off, sizeof(tmp), &tmp);
*out = tmp;
```

`skb_header_pointer()` 的契约是**返回指针**：头部线性（快路径）时直接返回
`skb->data + off`，**根本不写 `buffer`**；只有数据跨页时才把内容拷进 `buffer`。
上述写法在最常见的快路径上读的是**未初始化的栈内存**。

**表现**：端口恒读为 0（栈上恰好是零），因而 53 端口判定永远不匹配，
`NAT_SEEN` 恒为 0——而 hook 明明被调用了 14 次。**不崩溃，极具迷惑性。**

**定位手段**：在 hook 里用 `print_hex_dump()` 打出原始报文。
字节 `a4 1b 00 35` 直接显示 sport=42011 / dport=53，两分钟锁定。

#### 缺陷 2：`pr_fmt` 依赖了尚未定义的宏

```c
#define pr_fmt(fmt) KDG_MOD_NAME ": " fmt     /* KDG_MOD_NAME 来自稍后才 include 的 kdg.h */
#include <linux/module.h>                     /* 其链条里的 gfp.h 已经在用 pr_warn() */
```

展开成「标识符后跟字符串字面量」的语法错误，而**报错位置落在内核头里**
（`gfp.h:251: error: expected ')'`），看上去像内核坏了。

**正确做法**：用 `KBUILD_MODNAME`——它由 kbuild 通过 `-D` 命令行预定义，
在任何 include 之前就存在，与包含顺序无关。这也是内核全树的统一写法。

### 3.3 构建旗标必须与主构建一致

树外模块若不带上与 `内核构建.sh` 相同的 `CUSTOM_FLAGS`（尤其 `-Wno-error`），
会在 `include/linux/signal.h` 的 `_SIG_SET_BINOP` 上炸出 `-Warray-bounds`
（`_NSIG_WORDS==1` 时 `sig[2]`/`sig[3]` 仍被 clang 做死代码分析）。
主构建正是靠 `-Wno-error` 压住的。代价是本模块自身的告警也被降级，
故 `tools/build.sh` 里**单独 grep 本目录的告警**把严格性补回来。

---

## 4. 未决事项

1. **BoxProxy/代理运行时的 DNS 路径未测。** 本次验证时 `com.boxproxy.box` 处于
   `do_freezer_trap`（被系统冻结），DNS 直接走 LOCAL_OUT 53 端口。
   方案 §5.1 指出 eBPF 入站可能在 socket connect/sendmsg 阶段就改写 53 目的地址，
   **发生在 Netfilter LOCAL_OUT 之前**。代理真正工作时这条路径必须重测——
   它决定 P3 的所有权协调方案。
2. **mbedTLS 内核移植层未验证。** 它是换选路线的**唯一技术门槛**，
   必须在 P1 最先做掉：内存/时间/熵/threading alt + socket send/recv 回调。
   本机无 aarch64 交叉 libc，移植层要能在内核树里编过。
3. **`lxin/quic` 许可证未核实**（P7 才需要，但已标记 BLOCKED）。
4. **`CONFIG_CRYPTO_CURVE25519` 未启用**，X25519 不可用（P-256 可用，不阻塞）。
5. **骨架尚未纳入内核树**。当前是树外 LKM。设备常规交付走 AnyKernel3
   （`do.modules=0`，只换 boot 内核段、不装模块），故 kdnsguard 要常驻设备
   必须改为内建集成——这是 P3 的决策。

---

## 5. 复现方式

```bash
# 1. 内核侧单元测试（宿主 gcc + ASan/UBSan）
cd kdnsguard/tests && make run

# 2. 构建模块（需要 oplus13/android_kernel_common_oneplus_sm8750/out 已构建）
bash kdnsguard/tools/build.sh

# 3. 构建诊断客户端
bash kdnsguard/tools/build-kdgctl.sh

# 4. 生成构建清单（方案 §15）
bash kdnsguard/tools/manifest.sh third_party/manifest.txt

# 5. 真机
adb push kernel/kdnsguard.ko tools/kdgctl /data/local/tmp/
adb shell su -c 'insmod /data/local/tmp/kdnsguard.ko'
adb shell su -c '/data/local/tmp/kdgctl'
adb shell su -c 'rmmod kdnsguard'
```
