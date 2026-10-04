// SPDX-License-Identifier: GPL-2.0
//! `/dev/kdnsguard` 的封装。
//!
//! 一次 `write` 提交一条请求、随后 `read` 取回**同一 cookie** 的响应。内核保证
//! 响应在 write 返回时已经就绪（同步语义），所以这里不需要 poll/等待。
//!
//! # 两个必须做对的地方
//!
//! 1. **cookie 由本层生成并逐字节带回**。它是唯一的配对凭据 —— 用 DNS ID 配对
//!    是错的：内核会把上游 ID 规范为 0，多个调用方的 ID 也天然会撞。
//! 2. **读必须循环到凑齐整帧**，不能假设一次 `read` 拿到全部。内核的 read 语义
//!    是 `min(剩余, 调用方缓冲)`，缓冲不够时剩下的留在内核里等下一次读 ——
//!    单次读会把响应**静默截断**。

use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::error::{Error, Result, WireError};
use crate::uapi::{
    self, MapItemV1, MapResultV1, Op, ReqV1, RespV1, Status, MAP_MAX_ITEMS, MAX_WIRE_MSG,
};
use crate::wire;

/// 一次 MAP_LOOKUP 的完整结果。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MapLookup {
    pub profile_generation: u32,
    /// 内核明确告知「还有候选没装下」。**不要**当成「就这几个」。
    pub truncated: bool,
    pub entries: Vec<MapEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MapEntry {
    /// wire 域名（未压缩）已解码成点分文本。
    pub name: String,
    pub ttl: Duration,
}

pub struct Device {
    file: File,
    cookie: u64,
}

impl Device {
    /// 打开设备节点。
    ///
    /// 失败时把「需要 root、且模块已加载、且节点已创建」写进错误里 ——
    /// 这三种原因在设备上都表现为一句没有上下文的 `No such file` 或
    /// `Permission denied`，是实际排障时最耗时的一步。
    pub fn open() -> Result<Self> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(uapi::DEVICE_PATH)
            .map_err(|e| {
                Error::Io(std::io::Error::new(
                    e.kind(),
                    format!(
                        "打开 {} 失败（{e}）：需要 root，且 kdnsguard 模块已加载、\
                         节点已由 mknod 创建",
                        uapi::DEVICE_PATH
                    ),
                ))
            })?;
        Ok(Device {
            file,
            cookie: seed_cookie(),
        })
    }

    fn next_cookie(&mut self) -> u64 {
        self.cookie = self.cookie.wrapping_add(1);
        self.cookie
    }

    /// 底层一次请求/响应交换，返回响应体的原始字节。
    pub fn exchange(&mut self, op: Op, body: &[u8], deadline_ms: u32) -> Result<Vec<u8>> {
        let cookie = self.next_cookie();
        let total = 40 + body.len();
        let req = ReqV1 {
            abi_version: uapi::ABI_VERSION,
            opcode: op as u16,
            total_len: total as u32,
            request_cookie: cookie,
            expected_generation: 0,
            requested_network_handle: 0,
            deadline_ms,
            query_len: body.len() as u32,
            flags: 0,
            reserved0: 0,
        };

        let mut frame = Vec::with_capacity(total);
        frame.extend_from_slice(&req.encode());
        frame.extend_from_slice(body);
        debug_assert_eq!(frame.len(), total);

        self.file.write_all(&frame)?;
        self.read_frame(cookie)
    }

    fn read_frame(&mut self, expect_cookie: u64) -> Result<Vec<u8>> {
        let mut buf: Vec<u8> = Vec::with_capacity(RespV1::SIZE + 512);
        let mut chunk = vec![0u8; RespV1::SIZE + MAX_WIRE_MSG];

        loop {
            let n = self.file.read(&mut chunk)?;
            if n == 0 {
                return Err(Error::Io(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "内核没有返回响应帧",
                )));
            }
            buf.extend_from_slice(&chunk[..n]);

            if buf.len() < RespV1::SIZE {
                continue; // 连头都没凑齐，继续读
            }
            let hdr = RespV1::decode(&buf).ok_or(Error::Wire(WireError::Truncated))?;
            if buf.len() >= RespV1::SIZE + hdr.response_len as usize {
                return self.finish(buf, hdr, expect_cookie);
            }
        }
    }

    fn finish(&self, buf: Vec<u8>, hdr: RespV1, expect_cookie: u64) -> Result<Vec<u8>> {
        if hdr.abi_version != uapi::ABI_VERSION {
            return Err(Error::UnknownStatus(hdr.status));
        }
        if hdr.request_cookie != expect_cookie {
            // 回包不属于本次请求。继续用它会读到别人的数据，必须硬失败。
            return Err(Error::Wire(WireError::Malformed));
        }
        let status = Status::from_u16(hdr.status).ok_or(Error::UnknownStatus(hdr.status))?;
        if status != Status::Ok {
            return Err(Error::Status {
                status,
                errno: hdr.errno_hint,
            });
        }
        let body = buf[RespV1::SIZE..RespV1::SIZE + hdr.response_len as usize].to_vec();
        Ok(body)
    }

    /// 提交一条 DNS wire 查询，返回 DNS wire 响应。**不做**任何重试。
    pub fn query_wire(&mut self, wire_query: &[u8], deadline_ms: u32) -> Result<Vec<u8>> {
        if wire_query.is_empty() || wire_query.len() > MAX_WIRE_MSG {
            return Err(Error::Wire(WireError::Truncated));
        }
        self.exchange(Op::Query, wire_query, deadline_ms)
    }

    /// 解析一个域名，返回内核给出的应答（已解析成结构化形式）。
    pub fn query(&mut self, name: &str, qtype: u16) -> Result<wire::Message> {
        let q = wire::build_query(name, qtype, 0x4b44)?; // 'KD'
        let resp = self.query_wire(&q, 5000)?;
        let msg = wire::parse(&resp)?;
        Ok(msg)
    }

    /// 反查：这个 IP 可能是哪些域名（方案 §12.2）。
    ///
    /// 「没有关联」返回 `entries` 为空的 `Ok`，**不是错误** —— 调用方据此回退到
    /// SNI 嗅探；只有设备/内核层面的失败才是 `Err`。
    pub fn map_lookup(&mut self, ip: IpAddr) -> Result<MapLookup> {
        let body = match ip {
            IpAddr::V4(v4) => v4.octets().to_vec(),
            IpAddr::V6(v6) => v6.octets().to_vec(),
        };
        let raw = self.exchange(Op::MapLookup, &body, 0)?;

        let hdr = MapResultV1::decode(&raw).ok_or(Error::Wire(WireError::Truncated))?;
        let mut off = MapResultV1::SIZE;
        let mut entries = Vec::new();

        for _ in 0..hdr.count.min(MAP_MAX_ITEMS) {
            let item = MapItemV1::decode(raw.get(off..).unwrap_or(&[]))
                .ok_or(Error::Wire(WireError::Truncated))?;
            off += MapItemV1::SIZE;
            let len = item.len as usize;
            let payload = raw
                .get(off..off + len)
                .ok_or(Error::Wire(WireError::Truncated))?;

            // kind 目前只定义 0（域名）。出现别的值说明内核加了新语义而这里
            // 不认识 —— 跳过而不是猜，猜错会让调用方按错误的东西分流。
            if item.kind == 0 {
                let name = wire::name_from_wire(payload)?;
                entries.push(MapEntry {
                    name,
                    ttl: Duration::from_millis(item.ttl_ms as u64),
                });
            }
            off += uapi::align4(len);
        }

        Ok(MapLookup {
            profile_generation: hdr.profile_generation,
            truncated: hdr.truncated != 0,
            entries,
        })
    }

    pub fn map_lookup_v4(&mut self, ip: Ipv4Addr) -> Result<MapLookup> {
        self.map_lookup(IpAddr::V4(ip))
    }

    pub fn map_lookup_v6(&mut self, ip: Ipv6Addr) -> Result<MapLookup> {
        self.map_lookup(IpAddr::V6(ip))
    }
}

/// cookie 的起始值。
///
/// **不是安全需求**（内核只要求它与本次请求配对），所以不引入随机数依赖；
/// 用纳秒时间戳避免同一进程重启后与旧 cookie 碰撞即可。注意内核会拒绝
/// cookie 为 0 之外的重复值——重复的是**同一 fd** 上的，时间戳天然不会重复。
fn seed_cookie() -> u64 {
    match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(d) => d.as_nanos() as u64,
        Err(_) => 0x5eed_0000_0000_0001,
    }
}
