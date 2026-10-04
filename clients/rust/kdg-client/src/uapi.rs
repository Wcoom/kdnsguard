// SPDX-License-Identifier: GPL-2.0
//! `include/uapi/kdnsguard.h` 的 Rust 镜像。
//!
//! # 为什么要逐字节镜像而不是「大概对上就行」
//!
//! 这份 UAPI 是**内核与用户空间之间的二进制契约**，两边是独立编译的。任何
//! 字段顺序、宽度或对齐的偏差都不会在编译期报错，只会在真机上变成「字段读到
//! 了隔壁的值」——最坏情况是内核按错误的 `query_len` 去读调用方的缓冲。
//!
//! 因此这里做两件事：
//!   1. 所有跨边界的编解码都**手写字节序**（`to_ne_bytes`/`from_ne_bytes`），
//!      不对结构体做 `transmute`/`ptr::read` —— 那样会把 Rust 的对齐假设
//!      偷偷带进去；
//!   2. `tests/layout.rs` 会**现场编译 C 头文件**、读出 `sizeof`/`offsetof`，
//!      与下面 `LAYOUT` 表里的常量逐项比对。C 头改了而这里没改，测试就红。
//!
//! # 字节序
//!
//! 方案 §14 的纪律：多字节字段一律**主机字节序**（内核本地 ABI 惯例），不用
//! 网络序。`to_ne_bytes` 正是这个语义，且它让「这里用的是本地序」在代码里
//! 一眼可见。

/// 版本不匹配时内核返回 [`Status::Eabi`]，调用方不得尝试解析。
pub const ABI_VERSION: u16 = 1;

/// 单条 DNS 报文的硬上限，与内核 `KDG_MAX_WIRE_MSG` 一致。
pub const MAX_WIRE_MSG: usize = 4096;

/// 查询面设备节点。
pub const DEVICE_PATH: &str = "/dev/kdnsguard";

/// 管理面 Generic Netlink 族名（本 crate 暂不实现 genl，仅登记事实）。
pub const GENL_NAME: &str = "KDNSGUARD";

/// `struct kdg_req_v1`。
///
/// C 侧布局：`u16, u16, u32, u64, u32, u32, u32, u32, u32, u32` ⇒
/// 大小 40、对齐 8（`u64` 迫使 8 字节对齐，故 4..8 处有 4 字节空洞）。
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ReqV1 {
    pub abi_version: u16,
    pub opcode: u16,
    /// 本次 write 的总字节数（含本头）。内核用它校验调用方缓冲长度。
    pub total_len: u32,
    /// 调用方自选，回包原样带回。是**唯一**的配对凭据 —— 不要用 DNS ID 配对。
    pub request_cookie: u64,
    pub expected_generation: u32,
    pub requested_network_handle: u32,
    pub deadline_ms: u32,
    pub query_len: u32,
    pub flags: u32,
    pub reserved0: u32,
}

/// `struct kdg_resp_v1`。
///
/// C 侧布局：`u16, u16, u32, u64, u32, u32, u32, u32` ⇒ 大小 32、对齐 8。
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RespV1 {
    pub abi_version: u16,
    pub status: u16,
    pub errno_hint: u32,
    pub request_cookie: u64,
    pub actual_network: u32,
    pub generation: u32,
    pub response_len: u32,
    pub reserved0: u32,
}

/// `struct kdg_map_item_v1`：MAP_LOOKUP 响应里的一条候选。
///
/// 载荷（域名 wire 或裸地址）**紧随其后、按 4 字节对齐补齐**，不跨结构体边界
/// 复制 —— 变长项这样写才不会把「对齐补齐」误当成载荷的一部分。
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct MapItemV1 {
    pub len: u16,
    /// 0 = DNS 名（wire，未压缩）；4/16 = 裸地址字节数。
    pub kind: u16,
    pub ttl_ms: u32,
}

/// `struct kdg_map_result_v1`：MAP_LOOKUP 响应体的头。
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct MapResultV1 {
    /// provenance：这些关联是在哪一代 profile 下建立的。
    pub profile_generation: u32,
    pub actual_network: u32,
    pub count: u32,
    /// 非 0 = 还有候选未装下。**不能**当成「就这几个」——调用方据此知道
    /// 自己的分流依据是不完整的。
    pub truncated: u32,
}

/// 查询面 opcode（`enum kdg_ioctl_op`）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum Op {
    Query = 0,
    Cancel = 1,
    MapLookup = 2,
    GetHealth = 3,
}

/// 协议自有状态（`enum kdg_status`）。负值区间留给 errno 直通。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum Status {
    Ok = 0,
    Eabi = 1,
    Eop = 2,
    Emsgsize = 3,
    Ecookie = 4,
    Egeneration = 5,
    Eperm = 6,
    Ecanceled = 7,
    Etimedout = 8,
    Ebadwire = 9,
    Eagain = 10,
    Eupstream = 11,
}

impl Status {
    pub fn from_u16(v: u16) -> Option<Self> {
        use Status::*;
        Some(match v {
            0 => Ok,
            1 => Eabi,
            2 => Eop,
            3 => Emsgsize,
            4 => Ecookie,
            5 => Egeneration,
            6 => Eperm,
            7 => Ecanceled,
            8 => Etimedout,
            9 => Ebadwire,
            10 => Eagain,
            11 => Eupstream,
            _ => return None,
        })
    }
}

/// 单个 IP 最多带回多少个候选域名，与内核 `KDG_MAP_MAX_ITEMS` 一致。
pub const MAP_MAX_ITEMS: u32 = 4;

/// 域名 wire 形式的最大字节数，与内核 `KDG_MAP_NAME_MAX` 一致。
pub const MAP_NAME_MAX: usize = 128;

// ── 手工编解码 ──────────────────────────────────────────────────────────
//
// 全部用显式的 `to_ne_bytes`/`from_ne_bytes`。不用 `#[derive]` + 二进制
// 反序列化库，也不做 `transmute`：前者加依赖，后者把 Rust 的对齐假设带进
// 一个以内核布局为准的契约里。

impl ReqV1 {
    pub fn encode(&self) -> [u8; 40] {
        let mut b = [0u8; 40];
        b[0..2].copy_from_slice(&self.abi_version.to_ne_bytes());
        b[2..4].copy_from_slice(&self.opcode.to_ne_bytes());
        b[4..8].copy_from_slice(&self.total_len.to_ne_bytes());
        b[8..16].copy_from_slice(&self.request_cookie.to_ne_bytes());
        b[16..20].copy_from_slice(&self.expected_generation.to_ne_bytes());
        b[20..24].copy_from_slice(&self.requested_network_handle.to_ne_bytes());
        b[24..28].copy_from_slice(&self.deadline_ms.to_ne_bytes());
        b[28..32].copy_from_slice(&self.query_len.to_ne_bytes());
        b[32..36].copy_from_slice(&self.flags.to_ne_bytes());
        b[36..40].copy_from_slice(&self.reserved0.to_ne_bytes());
        b
    }

    pub fn decode(b: &[u8]) -> Option<Self> {
        if b.len() < 40 {
            return None;
        }
        let g2 = |o: usize| u16::from_ne_bytes([b[o], b[o + 1]]);
        let g4 = |o: usize| u32::from_ne_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]]);
        let g8 = |o: usize| {
            u64::from_ne_bytes([
                b[o], b[o + 1], b[o + 2], b[o + 3], b[o + 4], b[o + 5], b[o + 6], b[o + 7],
            ])
        };
        Some(ReqV1 {
            abi_version: g2(0),
            opcode: g2(2),
            total_len: g4(4),
            request_cookie: g8(8),
            expected_generation: g4(16),
            requested_network_handle: g4(20),
            deadline_ms: g4(24),
            query_len: g4(28),
            flags: g4(32),
            reserved0: g4(36),
        })
    }
}

impl RespV1 {
    pub const SIZE: usize = 32;

    pub fn decode(b: &[u8]) -> Option<Self> {
        if b.len() < Self::SIZE {
            return None;
        }
        let g2 = |o: usize| u16::from_ne_bytes([b[o], b[o + 1]]);
        let g4 = |o: usize| u32::from_ne_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]]);
        let g8 = |o: usize| {
            u64::from_ne_bytes([
                b[o], b[o + 1], b[o + 2], b[o + 3], b[o + 4], b[o + 5], b[o + 6], b[o + 7],
            ])
        };
        Some(RespV1 {
            abi_version: g2(0),
            status: g2(2),
            errno_hint: g4(4),
            request_cookie: g8(8),
            actual_network: g4(16),
            generation: g4(20),
            response_len: g4(24),
            reserved0: g4(28),
        })
    }
}

impl MapResultV1 {
    pub const SIZE: usize = 16;

    pub fn decode(b: &[u8]) -> Option<Self> {
        if b.len() < Self::SIZE {
            return None;
        }
        let g4 = |o: usize| u32::from_ne_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]]);
        Some(MapResultV1 {
            profile_generation: g4(0),
            actual_network: g4(4),
            count: g4(8),
            truncated: g4(12),
        })
    }
}

impl MapItemV1 {
    pub const SIZE: usize = 8;

    pub fn decode(b: &[u8]) -> Option<Self> {
        if b.len() < Self::SIZE {
            return None;
        }
        Some(MapItemV1 {
            len: u16::from_ne_bytes([b[0], b[1]]),
            kind: u16::from_ne_bytes([b[2], b[3]]),
            ttl_ms: u32::from_ne_bytes([b[4], b[5], b[6], b[7]]),
        })
    }
}

/// 变长 item 载荷的对齐补齐长度（内核按 4 字节对齐推进）。
pub const fn align4(n: usize) -> usize {
    (n + 3) & !3
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn req_roundtrip() {
        let r = ReqV1 {
            abi_version: ABI_VERSION,
            opcode: Op::MapLookup as u16,
            total_len: 44,
            request_cookie: 0x1122_3344_5566_7788,
            expected_generation: 7,
            requested_network_handle: 0,
            deadline_ms: 3000,
            query_len: 4,
            flags: 0,
            reserved0: 0,
        };
        assert_eq!(ReqV1::decode(&r.encode()), Some(r));
    }

    #[test]
    fn cookie_is_not_byte_swapped() {
        // request_cookie 是配对凭据，任何字节序转换都会让它对不上。
        let r = ReqV1 {
            request_cookie: 0x0102_0304_0506_0708,
            ..Default::default()
        };
        let e = r.encode();
        assert_eq!(&e[8..16], &[8, 7, 6, 5, 4, 3, 2, 1]); // 小端：低字节在前
        assert_eq!(ReqV1::decode(&e).unwrap().request_cookie, 0x0102_0304_0506_0708);
    }

    #[test]
    fn short_buffers_are_rejected_not_padded() {
        // 短缓冲必须拒绝而不是补零解析 —— 补零会把不存在的字段读成 0，
        // 那正是「静默出错」的样子。
        assert!(ReqV1::decode(&[0u8; 39]).is_none());
        assert!(RespV1::decode(&[0u8; 31]).is_none());
        assert!(MapResultV1::decode(&[0u8; 15]).is_none());
        assert!(MapItemV1::decode(&[0u8; 7]).is_none());
    }

    #[test]
    fn align4_matches_kernel() {
        assert_eq!(align4(0), 0);
        assert_eq!(align4(1), 4);
        assert_eq!(align4(4), 4);
        assert_eq!(align4(5), 8);
        assert_eq!(align4(128), 128);
    }

    #[test]
    fn status_mapping_is_total_over_defined_values() {
        for v in 0u16..=11 {
            assert!(Status::from_u16(v).is_some(), "status {v} 未映射");
        }
        assert!(Status::from_u16(12).is_none());
    }
}
