// SPDX-License-Identifier: GPL-2.0
//! 错误类型。
//!
//! 分三类是刻意的：调用方对它们的处置完全不同 ——
//!   * [`Error::Status`]：内核明确告知的协议级失败（配额、上游不可达…），
//!     可以直接上报给用户；
//!   * [`Error::Io`]：设备节点打不开、写失败。多数是权限或模块没加载；
//!   * [`Error::Wire`]：报文本身有问题。**到这一步说明前面某道防线漏了**，
//!     不该静默吞掉。

use std::fmt;

use crate::uapi::Status;

#[derive(Debug)]
pub enum Error {
    /// 内核在 `kdg_resp_v1.status` 里给出的协议状态。
    Status { status: Status, errno: u32 },
    /// 内核回了一个本 crate 不认识的 status —— 说明两边 ABI 不一致。
    UnknownStatus(u16),
    Io(std::io::Error),
    Wire(WireError),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WireError {
    Truncated,
    /// 域名过长（> 255 字节的 wire 形式）。
    NameTooLong,
    /// 标签过长（> 63）。
    LabelTooLong,
    /// 域名里出现了空标签（`a..b`）—— 除根之外都不合法。
    EmptyLabel,
    /// 压缩指针非法：指向自身、构成环、或跳数超限。
    BadPointer,
    /// 结构上不合法（保留位、计数与内容不符等）。
    Malformed,
}

impl fmt::Display for WireError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            WireError::Truncated => "报文截断",
            WireError::NameTooLong => "域名过长",
            WireError::LabelTooLong => "标签过长",
            WireError::EmptyLabel => "域名含空标签",
            WireError::BadPointer => "压缩指针非法",
            WireError::Malformed => "报文结构不合法",
        };
        f.write_str(s)
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Status { status, errno } => {
                write!(f, "内核拒绝：{status:?}（errno_hint={errno}）")
            }
            Error::UnknownStatus(v) => {
                write!(f, "内核返回了未知 status {v}（ABI 不一致？）")
            }
            Error::Io(e) => write!(f, "设备 IO 失败：{e}"),
            Error::Wire(e) => write!(f, "DNS 报文错误：{e}"),
        }
    }
}

impl std::error::Error for Error {}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Error::Io(e)
    }
}

impl From<WireError> for Error {
    fn from(e: WireError) -> Self {
        Error::Wire(e)
    }
}

pub type Result<T> = std::result::Result<T, Error>;
