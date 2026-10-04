// SPDX-License-Identifier: GPL-2.0
//! # kdg-client —— kdnsguard 的用户空间客户端
//!
//! 封装 `/dev/kdnsguard`（方案 §14.2 的查询面）与 DNS wire 编解码。
//!
//! ## 它**不**做什么（这是刻意的）
//!
//! 不含重试、缓存、并发合并、DoH/DoT 上游 —— 全在内核里。方案 §14.2：
//! 「Go/C++ 客户端只是接口封装、DNS wire 编解码和返回值转换，不能保留一套
//! 上游 retry/cache/DoH 实现」。客户端再实现一套，两边行为就会分叉，而
//! 内核那套是唯一被验证过的。
//!
//! ## 例子
//!
//! ```no_run
//! use kdg_client::{Device, wire};
//!
//! # fn main() -> kdg_client::Result<()> {
//! let mut dev = Device::open()?;
//!
//! // 解析一个域名（内核侧完成 DoH 往返，客户端只编解码）
//! let msg = dev.query("example.com", wire::TYPE_A)?;
//! for ip in msg.ipv4_answers() {
//!     println!("{ip}");
//! }
//!
//! // 反查：这个 IP 可能是哪些域名（方案 §12.2）
//! if let Some(ip) = msg.ipv4_answers().first() {
//!     for e in dev.map_lookup_v4(*ip)?.entries {
//!         println!("{} (剩 {:?})", e.name, e.ttl);
//!     }
//! }
//! # Ok(())
//! # }
//! ```

pub mod device;
pub mod error;
pub mod uapi;
pub mod wire;

pub use device::{Device, MapEntry, MapLookup};
pub use error::{Error, Result, WireError};
pub use uapi::{Op, Status};
