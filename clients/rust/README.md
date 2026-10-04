# kdg-client（Rust）

kdnsguard 的**用户空间客户端库**：封装 `/dev/kdnsguard`（方案 §14.2 的查询面）
与 DNS wire 编解码。

内核侧仍是 C（`kernel/`），这里只做接口封装与返回值转换 —— 语言选择按层分：
内核跟着内核树的现实走，用户空间用有内存安全保证的语言。

## 它不做什么（刻意的）

不含重试、缓存、并发合并、DoH/DoT 上游。方案 §14.2：

> Go/C++ 客户端只是接口封装、DNS wire 编解码和返回值转换，不能保留一套上游
> retry/cache/DoH 实现。

客户端再实现一套，两边行为必然分叉，而内核那套是唯一被真机验证过的。

## 零依赖

`[dependencies]` 是空的，且刻意保持。理由：交叉编译到 Android 时不引入任何
第三方 crate，不要求 crates.io 可达（本机网络受限），也不给设备端加包袱。

## 构建与测试

```bash
# 宿主（x86_64）：单测 + **UAPI 布局交叉验证**
cd clients/rust && cargo test --offline

# 设备（aarch64-linux-android）
bash clients/rust/build-android.sh
adb push target/aarch64-linux-android/release/examples/kdgctl /data/local/tmp/kdgctl-rs
```

## 最有价值的那一块：`tests/layout.rs`

它**现场用 `cc` 编译 `include/uapi/kdnsguard.h`**，把 C 报出的
`sizeof`/`offsetof` 与本 crate 的 Rust 定义逐项比对。

这不是「在 Rust 里写死一串数字再断言」——那样只能证明常量没被人改过，证明不了
它和 C 头一致。而两边不一致正是这类 ABI 最危险的失败模式：编译通过、测试全绿、
真机上内核按错误偏移读调用方缓冲。

**它已经抓到过一次真问题**：`ReqV1` 最初漏了 `#[repr(C)]`。Rust 默认
`repr(Rust)` **不保证字段顺序**，编译器为减少填充把字段重排了 ——
`size_of::<ReqV1>()` 恰好还是 40（大小对），而
`offset_of!(ReqV1, abi_version)` 变成了 36（偏移错）。
**大小对、偏移错**，正是最难察觉的一种不一致。

## 结构

| 文件 | 职责 |
|---|---|
| `src/uapi.rs` | `include/uapi/kdnsguard.h` 的镜像 + **手工**编解码（显式 `to_ne_bytes`，不做 `transmute`） |
| `src/wire.rs` | DNS wire 编解码：构造查询、解析应答、解码 MAP_LOOKUP 的 wire 域名。有界：压缩指针带跳数上限且强制前向 |
| `src/device.rs` | `/dev/kdnsguard` 的 open/exchange；cookie 配对；读到凑齐整帧 |
| `src/error.rs` | 三类错误分开：内核协议状态 / 设备 IO / 报文错误 |
| `examples/kdgctl.rs` | `query` / `maplookup` / `roundtrip` 三个诊断子命令 |

## 两个容易写错的地方（已处理，写在这里以免被"简化"掉）

1. **cookie 是唯一配对凭据**。不要用 DNS ID 配对 —— 内核把上游 ID 规范为 0，
   多个调用方的 ID 也天然会撞。
2. **读必须循环到凑齐整帧**。内核 read 的语义是 `min(剩余, 调用方缓冲)`，
   缓冲不够时剩下的留在内核里等下一次读；单次读会把响应**静默截断**。
