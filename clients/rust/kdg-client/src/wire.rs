// SPDX-License-Identifier: GPL-2.0
//! DNS wire 编解码 —— **只做查询构造与应答解析**，不含任何重试/缓存/上游逻辑。
//!
//! 方案 §14.2 明确：Go/C++ 客户端（这里同理）「只是接口封装、DNS wire 编解码
//! 和返回值转换，不能保留一套上游 retry/cache/DoH 实现」。缓存、合并、重试全都
//! 在内核里；客户端重复一套只会让两边行为分叉。
//!
//! # 边界纪律
//!
//! 真正的安全边界在内核侧（`kernel/kdg_wire.c`）。这里的解析器是**第二道**：
//! 它面对的是内核已经校验过的报文，但代码仍然有界 —— 压缩指针带跳数上限、
//! 每次推进都查长度。理由不是不信任内核，而是「客户端拿到畸形数据就挂死」
//! 本身就是缺陷，而且这类代码的边界检查一旦被当作「反正上游校验过」而省略，
//! 将来换数据源时就成了真漏洞。

use std::net::{Ipv4Addr, Ipv6Addr};

use crate::error::WireError;

pub const TYPE_A: u16 = 1;
pub const TYPE_NS: u16 = 2;
pub const TYPE_CNAME: u16 = 5;
pub const TYPE_SOA: u16 = 6;
pub const TYPE_PTR: u16 = 12;
pub const TYPE_TXT: u16 = 16;
pub const TYPE_AAAA: u16 = 28;
pub const TYPE_SRV: u16 = 33;
pub const TYPE_OPT: u16 = 41;
pub const TYPE_HTTPS: u16 = 65;
pub const CLASS_IN: u16 = 1;

const HDR_LEN: usize = 12;
const MAX_PTR_JUMPS: usize = 64;
const MAX_NAME: usize = 255;

/// 把点分域名编码成 wire 形式（带结尾 root 字节）。
///
/// 拒绝：空标签（`a..b`）、单标签超过 63 字节、整体超过 255 字节。
/// **不做** IDN punycode 转换 —— 那是调用方的事，这里悄悄转会把「用户输入的
/// 是什么」变得不可见。
pub fn encode_name(name: &str) -> Result<Vec<u8>, WireError> {
    let trimmed = name.strip_suffix('.').unwrap_or(name);
    let mut out = Vec::with_capacity(trimmed.len() + 2);

    if trimmed.is_empty() {
        out.push(0);
        return Ok(out);
    }

    for label in trimmed.split('.') {
        if label.is_empty() {
            return Err(WireError::EmptyLabel);
        }
        let bytes = label.as_bytes();
        if bytes.len() > 63 {
            return Err(WireError::LabelTooLong);
        }
        out.push(bytes.len() as u8);
        out.extend_from_slice(bytes);
    }
    out.push(0);

    if out.len() > MAX_NAME {
        return Err(WireError::NameTooLong);
    }
    Ok(out)
}

/// 构造一条标准查询。`id` 由调用方给定（内核侧会把上游 ID 规范为 0）。
pub fn build_query(name: &str, qtype: u16, id: u16) -> Result<Vec<u8>, WireError> {
    let qname = encode_name(name)?;
    let mut m = Vec::with_capacity(HDR_LEN + qname.len() + 4);
    m.extend_from_slice(&id.to_be_bytes());
    m.extend_from_slice(&0x0100u16.to_be_bytes()); // RD=1（客户端永远要求递归）
    m.extend_from_slice(&1u16.to_be_bytes()); // qdcount
    m.extend_from_slice(&0u16.to_be_bytes()); // ancount
    m.extend_from_slice(&0u16.to_be_bytes()); // nscount
    m.extend_from_slice(&0u16.to_be_bytes()); // arcount
    m.extend_from_slice(&qname);
    m.extend_from_slice(&qtype.to_be_bytes());
    m.extend_from_slice(&CLASS_IN.to_be_bytes());
    Ok(m)
}

/// 一条资源记录。`rdata` 保持原始字节。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Record {
    pub name: String,
    pub rtype: u16,
    pub class: u16,
    pub ttl: u32,
    pub rdata: Vec<u8>,
}

impl Record {
    pub fn as_ipv4(&self) -> Option<Ipv4Addr> {
        if self.rtype != TYPE_A || self.rdata.len() != 4 {
            return None;
        }
        Some(Ipv4Addr::new(
            self.rdata[0],
            self.rdata[1],
            self.rdata[2],
            self.rdata[3],
        ))
    }

    pub fn as_ipv6(&self) -> Option<Ipv6Addr> {
        if self.rtype != TYPE_AAAA || self.rdata.len() != 16 {
            return None;
        }
        let mut o = [0u8; 16];
        o.copy_from_slice(&self.rdata);
        Some(Ipv6Addr::from(o))
    }
}

/// 解析后的应答。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Message {
    pub id: u16,
    pub flags: u16,
    pub qdcount: u16,
    pub ancount: u16,
    pub nscount: u16,
    pub arcount: u16,
    pub question: Vec<Question>,
    pub answers: Vec<Record>,
    pub authority: Vec<Record>,
    pub additional: Vec<Record>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Question {
    pub name: String,
    pub qtype: u16,
    pub class: u16,
}

impl Message {
    pub fn rcode(&self) -> u8 {
        (self.flags & 0x000f) as u8
    }

    pub fn is_response(&self) -> bool {
        self.flags & 0x8000 != 0
    }

    pub fn is_truncated(&self) -> bool {
        self.flags & 0x0200 != 0
    }

    pub fn ipv4_answers(&self) -> Vec<Ipv4Addr> {
        self.answers.iter().filter_map(|r| r.as_ipv4()).collect()
    }

    pub fn ipv6_answers(&self) -> Vec<Ipv6Addr> {
        self.answers.iter().filter_map(|r| r.as_ipv6()).collect()
    }
}

struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Reader { buf, pos: 0 }
    }

    fn need(&self, n: usize) -> Result<(), WireError> {
        if self.pos + n > self.buf.len() {
            return Err(WireError::Truncated);
        }
        Ok(())
    }

    fn u16(&mut self) -> Result<u16, WireError> {
        self.need(2)?;
        let v = u16::from_be_bytes([self.buf[self.pos], self.buf[self.pos + 1]]);
        self.pos += 2;
        Ok(v)
    }

    fn u32(&mut self) -> Result<u32, WireError> {
        self.need(4)?;
        let b = &self.buf[self.pos..self.pos + 4];
        self.pos += 4;
        Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }

    /// 读一个（可能被压缩的）域名，返回点分文本与**本字段之后**的偏移。
    ///
    /// 跳数上限 + 偏移必须严格前进（目标小于当前位置）两条一起用：前者防
    /// 恶意环，后者让「指针指向自己」在构造上不可能。只靠跳数上限的话，
    /// 一个 64 跳的环仍会被完整走完。
    fn name(&mut self) -> Result<(String, usize), WireError> {
        let mut labels: Vec<String> = Vec::new();
        let mut pos = self.pos;
        let mut after: Option<usize> = None;
        let mut jumps = 0usize;
        let mut total = 0usize;

        loop {
            if pos >= self.buf.len() {
                return Err(WireError::Truncated);
            }
            let len = self.buf[pos];

            if len & 0xc0 == 0xc0 {
                if pos + 1 >= self.buf.len() {
                    return Err(WireError::Truncated);
                }
                let target =
                    (((len as usize) & 0x3f) << 8) | self.buf[pos + 1] as usize;
                if after.is_none() {
                    after = Some(pos + 2);
                }
                if target >= pos {
                    return Err(WireError::BadPointer); // 前向/自指，直接拒
                }
                jumps += 1;
                if jumps > MAX_PTR_JUMPS {
                    return Err(WireError::BadPointer);
                }
                pos = target;
                continue;
            }

            if len & 0xc0 != 0 {
                return Err(WireError::Malformed); // 0x40/0x80 保留
            }
            if len == 0 {
                pos += 1;
                if after.is_none() {
                    after = Some(pos);
                }
                break;
            }
            if len > 63 {
                return Err(WireError::LabelTooLong);
            }
            let l = len as usize;
            if pos + 1 + l > self.buf.len() {
                return Err(WireError::Truncated);
            }
            total += l + 1;
            if total > MAX_NAME {
                return Err(WireError::NameTooLong);
            }
            // 标签里可能出现非 UTF-8 字节（二进制标签），用 lossy 而非 panic。
            labels.push(
                String::from_utf8_lossy(&self.buf[pos + 1..pos + 1 + l]).into_owned(),
            );
            pos += 1 + l;
        }

        self.pos = after.ok_or(WireError::Malformed)?;
        Ok((labels.join("."), self.pos))
    }

    fn record(&mut self) -> Result<Record, WireError> {
        let (name, _) = self.name()?;
        let rtype = self.u16()?;
        let class = self.u16()?;
        let ttl = self.u32()?;
        let rdlen = self.u16()? as usize;
        self.need(rdlen)?;
        let rdata = self.buf[self.pos..self.pos + rdlen].to_vec();
        self.pos += rdlen;
        Ok(Record {
            name,
            rtype,
            class,
            ttl,
            rdata,
        })
    }
}

/// 解析一条 DNS 报文。**不**校验它是否匹配某个请求 —— 那是调用方或内核的事。
pub fn parse(msg: &[u8]) -> Result<Message, WireError> {
    if msg.len() < HDR_LEN {
        return Err(WireError::Truncated);
    }
    let mut m = Message {
        id: u16::from_be_bytes([msg[0], msg[1]]),
        flags: u16::from_be_bytes([msg[2], msg[3]]),
        qdcount: u16::from_be_bytes([msg[4], msg[5]]),
        ancount: u16::from_be_bytes([msg[6], msg[7]]),
        nscount: u16::from_be_bytes([msg[8], msg[9]]),
        arcount: u16::from_be_bytes([msg[10], msg[11]]),
        ..Default::default()
    };

    let mut r = Reader::new(msg);
    r.pos = HDR_LEN;

    for _ in 0..m.qdcount {
        let (name, _) = r.name()?;
        let qtype = r.u16()?;
        let class = r.u16()?;
        m.question.push(Question { name, qtype, class });
    }
    for _ in 0..m.ancount {
        m.answers.push(r.record()?);
    }
    for _ in 0..m.nscount {
        m.authority.push(r.record()?);
    }
    for _ in 0..m.arcount {
        m.additional.push(r.record()?);
    }
    Ok(m)
}

/// 从 MAP_LOOKUP 的载荷里解出 wire 域名文本。
///
/// 载荷是**未压缩**的 wire 名（内核侧保证），所以不需要压缩指针处理；但仍然
/// 逐字节查边界 —— 这里的输入最终来自网络。
pub fn name_from_wire(payload: &[u8]) -> Result<String, WireError> {
    let mut labels: Vec<String> = Vec::new();
    let mut pos = 0usize;
    let mut total = 0usize;

    loop {
        if pos >= payload.len() {
            return Err(WireError::Truncated);
        }
        let l = payload[pos];
        if l == 0 {
            return Ok(labels.join("."));
        }
        if l & 0xc0 != 0 {
            return Err(WireError::BadPointer); // 载荷里不该出现压缩指针
        }
        let l = l as usize;
        if pos + 1 + l > payload.len() {
            return Err(WireError::Truncated);
        }
        total += l + 1;
        if total > MAX_NAME {
            return Err(WireError::NameTooLong);
        }
        labels.push(String::from_utf8_lossy(&payload[pos + 1..pos + 1 + l]).into_owned());
        pos += 1 + l;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_names() {
        assert_eq!(encode_name("example.com").unwrap(), b"\x07example\x03com\x00");
        assert_eq!(encode_name("example.com.").unwrap(), b"\x07example\x03com\x00");
        assert_eq!(encode_name(".").unwrap(), b"\x00");
        assert_eq!(encode_name("a..b"), Err(WireError::EmptyLabel));
        assert_eq!(encode_name(&"x".repeat(64)), Err(WireError::LabelTooLong));
        let long = vec!["abcdefghij"; 26].join(".");
        assert_eq!(encode_name(&long), Err(WireError::NameTooLong));
    }

    #[test]
    fn parse_roundtrip() {
        let q = build_query("example.com", TYPE_A, 0x1234).unwrap();
        let m = parse(&q).unwrap();
        assert_eq!(m.id, 0x1234);
        assert_eq!(m.qdcount, 1);
        assert_eq!(m.question[0].name, "example.com");
        assert_eq!(m.question[0].qtype, TYPE_A);
        assert!(!m.is_response());
    }

    #[test]
    fn parse_truncated_is_error_not_panic() {
        let q = build_query("example.com", TYPE_A, 1).unwrap();
        for n in 0..q.len() {
            let _ = parse(&q[..n]); // 绝不能 panic
        }
        assert!(parse(&q[..5]).is_err());
    }

    #[test]
    fn compression_loop_is_rejected() {
        // 构造一个指向自己的压缩指针：必须被拒，且**不能**死循环。
        let mut msg = vec![0u8; 12 + 2];
        msg[4..6].copy_from_slice(&1u16.to_be_bytes()); // qdcount=1
        msg[12] = 0xc0;
        msg[13] = 0x0c; // 指向 12，也就是它自己
        assert_eq!(parse(&msg), Err(WireError::BadPointer));
    }

    #[test]
    fn name_from_wire_rejects_compression() {
        assert_eq!(name_from_wire(b"\x07example\x03com\x00").unwrap(), "example.com");
        assert_eq!(name_from_wire(&[0xc0, 0x0c]), Err(WireError::BadPointer));
        assert_eq!(name_from_wire(b"\x07exam"), Err(WireError::Truncated));
        assert_eq!(name_from_wire(&[]), Err(WireError::Truncated));
    }
}
