// SPDX-License-Identifier: GPL-2.0
//! UAPI 布局交叉验证：**现场编译 C 头文件**，把它报出的 `sizeof`/`offsetof`
//! 与本 crate 的 Rust 定义逐项比对。
//!
//! # 为什么不是「在 Rust 里写死一串数字再断言」
//!
//! 那样只能证明「Rust 里的常量没被人改过」，证明不了**它和 C 头一致**。
//! 两边不一致正是这类 ABI 最危险的失败模式：编译通过、测试全绿、真机上内核按
//! 错误的偏移读调用方的缓冲。
//!
//! 这里把 C 头当**唯一事实源**：`cc` 编译出的值就是契约，Rust 侧对不上就红。
//! 因此这个测试必须能在**宿主**上跑（`tests/include/linux/types.h` 提供了
//! `<linux/types.h>` 的最小替身，uapi 头的宿主可用性是刻意维持的）。

use std::collections::HashMap;
use std::mem::offset_of;
use std::path::PathBuf;
use std::process::Command;

use kdg_client::uapi::{MapItemV1, MapResultV1, ReqV1, RespV1};

/// 与 `include/uapi/kdnsguard.h` 里对应结构体的字段名一一对应。
/// 写成 `(C 里的表达式, Rust 报出的值)`，两边都由程序产出，没有手抄的数字。
fn c_manifest() -> Option<HashMap<String, usize>> {
    // CARGO_MANIFEST_DIR = <repo>/clients/rust/kdg-client
    let crate_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let repo = crate_dir.parent()?.parent()?.parent()?.to_path_buf();
    let inc = repo.join("include");
    let stub_inc = repo.join("tests").join("include");
    if !inc.join("uapi/kdnsguard.h").exists() {
        return None;
    }

    // 刻意**不用 format!**：这段 C 源码里有 printf 的 `%` 与 `{t}`/`{f}`
    // 之类的花括号，format! 会把它们当成插值，要么报错要么悄悄改写内容。
    // 一段纯静态的 C 源码不需要任何 Rust 侧插值。
    let src = r#"
#include <stdio.h>
#include <stddef.h>
#include "uapi/kdnsguard.h"

#define P(t, f) printf(#t "." #f " %zu\n", offsetof(struct t, f))
#define S(t)    printf(#t ".__size %zu\n", sizeof(struct t))
#define A(t)    printf(#t ".__align _Alignof(struct t)\n")

int main(void) {
    S(kdg_req_v1); A(kdg_req_v1);
    P(kdg_req_v1, abi_version); P(kdg_req_v1, opcode); P(kdg_req_v1, total_len);
    P(kdg_req_v1, request_cookie); P(kdg_req_v1, expected_generation);
    P(kdg_req_v1, requested_network_handle); P(kdg_req_v1, deadline_ms);
    P(kdg_req_v1, query_len); P(kdg_req_v1, flags); P(kdg_req_v1, reserved0);

    S(kdg_resp_v1); A(kdg_resp_v1);
    P(kdg_resp_v1, abi_version); P(kdg_resp_v1, status); P(kdg_resp_v1, errno_hint);
    P(kdg_resp_v1, request_cookie); P(kdg_resp_v1, actual_network);
    P(kdg_resp_v1, generation); P(kdg_resp_v1, response_len); P(kdg_resp_v1, reserved0);

    S(kdg_map_item_v1); A(kdg_map_item_v1);
    P(kdg_map_item_v1, len); P(kdg_map_item_v1, kind); P(kdg_map_item_v1, ttl_ms);

    S(kdg_map_result_v1); A(kdg_map_result_v1);
    P(kdg_map_result_v1, profile_generation); P(kdg_map_result_v1, actual_network);
    P(kdg_map_result_v1, count); P(kdg_map_result_v1, truncated);

    printf("const.KDG_ABI_VERSION %d\n", KDG_ABI_VERSION);
    printf("const.KDG_MAX_WIRE_MSG %d\n", KDG_MAX_WIRE_MSG);
    printf("const.KDG_MAP_MAX_ITEMS %d\n", KDG_MAP_MAX_ITEMS);
    printf("const.KDG_MAP_NAME_MAX %d\n", KDG_MAP_NAME_MAX);
    printf("const.KDG_OP_QUERY %d\n", KDG_OP_QUERY);
    printf("const.KDG_OP_CANCEL %d\n", KDG_OP_CANCEL);
    printf("const.KDG_OP_MAP_LOOKUP %d\n", KDG_OP_MAP_LOOKUP);
    printf("const.KDG_OP_GET_HEALTH %d\n", KDG_OP_GET_HEALTH);
    printf("const.KDG_ST_OK %d\n", KDG_ST_OK);
    printf("const.KDG_ST_EABI %d\n", KDG_ST_EABI);
    printf("const.KDG_ST_EOP %d\n", KDG_ST_EOP);
    printf("const.KDG_ST_EMSGSIZE %d\n", KDG_ST_EMSGSIZE);
    printf("const.KDG_ST_ECOOKIE %d\n", KDG_ST_ECOOKIE);
    printf("const.KDG_ST_EGENERATION %d\n", KDG_ST_EGENERATION);
    printf("const.KDG_ST_EPERM %d\n", KDG_ST_EPERM);
    printf("const.KDG_ST_ECANCELED %d\n", KDG_ST_ECANCELED);
    printf("const.KDG_ST_ETIMEDOUT %d\n", KDG_ST_ETIMEDOUT);
    printf("const.KDG_ST_EBADWIRE %d\n", KDG_ST_EBADWIRE);
    printf("const.KDG_ST_EAGAIN %d\n", KDG_ST_EAGAIN);
    printf("const.KDG_ST_EUPSTREAM %d\n", KDG_ST_EUPSTREAM);
    printf("const.KDG_DEVICE_NAME %s\n", KDG_DEVICE_NAME);
    return 0;
}
"#;

    let dir = std::env::temp_dir().join("kdg-client-layout");
    std::fs::create_dir_all(&dir).ok()?;
    let csrc = dir.join("layout.c");
    let cbin = dir.join("layout");
    std::fs::write(&csrc, src).ok()?;

    let out = Command::new("cc")
        .arg("-std=c11")
        .arg("-I")
        .arg(&stub_inc)
        .arg("-I")
        .arg(&inc)
        .arg("-o")
        .arg(&cbin)
        .arg(&csrc)
        .output()
        .ok()?;
    if !out.status.success() {
        panic!(
            "编译 C 布局程序失败 — UAPI 头可能在宿主上已不可解析：\n{}",
            String::from_utf8_lossy(&out.stderr)
        );
    }

    let run = Command::new(&cbin).output().ok()?;
    assert!(run.status.success(), "C 布局程序运行失败");

    let text = String::from_utf8_lossy(&run.stdout);
    let mut m = HashMap::new();
    for line in text.lines() {
        let mut it = line.rsplitn(2, ' ');
        let val = it.next()?;
        let key = it.next()?;
        // `__align` 行给的是符号值（如 "8"），其余是数字；两种都要能进表。
        let v: usize = match val.parse() {
            Ok(v) => v,
            Err(_) => continue,
        };
        m.insert(key.to_string(), v);
    }
    Some(m)
}

fn get(m: &HashMap<String, usize>, k: &str) -> usize {
    *m.get(k)
        .unwrap_or_else(|| panic!("C 侧没有给出 {k}（头文件被改动了？）"))
}

#[test]
fn uapi_layout_matches_c_header() {
    let m = match c_manifest() {
        Some(m) => m,
        None => {
            eprintln!("跳过：找不到 cc 或 include/uapi/kdnsguard.h（交叉编译时属正常）");
            return;
        }
    };

    // ── 结构体大小 ──
    assert_eq!(get(&m, "kdg_req_v1.__size"), size_of::<ReqV1>(), "kdg_req_v1 大小");
    assert_eq!(
        get(&m, "kdg_resp_v1.__size"),
        RespV1::SIZE,
        "kdg_resp_v1 大小"
    );
    assert_eq!(
        get(&m, "kdg_map_item_v1.__size"),
        MapItemV1::SIZE,
        "kdg_map_item_v1 大小"
    );
    assert_eq!(
        get(&m, "kdg_map_result_v1.__size"),
        MapResultV1::SIZE,
        "kdg_map_result_v1 大小"
    );

    // ── 字段偏移 ──
    assert_eq!(get(&m, "kdg_req_v1.abi_version"), offset_of!(ReqV1, abi_version));
    assert_eq!(get(&m, "kdg_req_v1.opcode"), offset_of!(ReqV1, opcode));
    assert_eq!(get(&m, "kdg_req_v1.total_len"), offset_of!(ReqV1, total_len));
    assert_eq!(
        get(&m, "kdg_req_v1.request_cookie"),
        offset_of!(ReqV1, request_cookie)
    );
    assert_eq!(
        get(&m, "kdg_req_v1.expected_generation"),
        offset_of!(ReqV1, expected_generation)
    );
    assert_eq!(
        get(&m, "kdg_req_v1.requested_network_handle"),
        offset_of!(ReqV1, requested_network_handle)
    );
    assert_eq!(get(&m, "kdg_req_v1.deadline_ms"), offset_of!(ReqV1, deadline_ms));
    assert_eq!(get(&m, "kdg_req_v1.query_len"), offset_of!(ReqV1, query_len));
    assert_eq!(get(&m, "kdg_req_v1.flags"), offset_of!(ReqV1, flags));
    assert_eq!(get(&m, "kdg_req_v1.reserved0"), offset_of!(ReqV1, reserved0));

    assert_eq!(get(&m, "kdg_resp_v1.abi_version"), offset_of!(RespV1, abi_version));
    assert_eq!(get(&m, "kdg_resp_v1.status"), offset_of!(RespV1, status));
    assert_eq!(get(&m, "kdg_resp_v1.errno_hint"), offset_of!(RespV1, errno_hint));
    assert_eq!(
        get(&m, "kdg_resp_v1.request_cookie"),
        offset_of!(RespV1, request_cookie)
    );
    assert_eq!(
        get(&m, "kdg_resp_v1.actual_network"),
        offset_of!(RespV1, actual_network)
    );
    assert_eq!(get(&m, "kdg_resp_v1.generation"), offset_of!(RespV1, generation));
    assert_eq!(
        get(&m, "kdg_resp_v1.response_len"),
        offset_of!(RespV1, response_len)
    );

    assert_eq!(get(&m, "kdg_map_item_v1.len"), offset_of!(MapItemV1, len));
    assert_eq!(get(&m, "kdg_map_item_v1.kind"), offset_of!(MapItemV1, kind));
    assert_eq!(get(&m, "kdg_map_item_v1.ttl_ms"), offset_of!(MapItemV1, ttl_ms));

    assert_eq!(
        get(&m, "kdg_map_result_v1.profile_generation"),
        offset_of!(MapResultV1, profile_generation)
    );
    assert_eq!(
        get(&m, "kdg_map_result_v1.actual_network"),
        offset_of!(MapResultV1, actual_network)
    );
    assert_eq!(get(&m, "kdg_map_result_v1.count"), offset_of!(MapResultV1, count));
    assert_eq!(
        get(&m, "kdg_map_result_v1.truncated"),
        offset_of!(MapResultV1, truncated)
    );

    // 手工编解码的缓冲区长度必须等于 C 结构体大小 —— 这是 encode() 里那个
    // `[u8; 40]` 字面量的独立校验，挪动手写编码长度会在这里立刻暴露。
    assert_eq!(get(&m, "kdg_req_v1.__size"), ReqV1::default().encode().len());
}

#[test]
fn uapi_constants_match_c_header() {
    use kdg_client::uapi as u;
    let m = match c_manifest() {
        Some(m) => m,
        None => return,
    };

    assert_eq!(get(&m, "const.KDG_ABI_VERSION"), u::ABI_VERSION as usize);
    assert_eq!(get(&m, "const.KDG_MAX_WIRE_MSG"), u::MAX_WIRE_MSG);
    assert_eq!(get(&m, "const.KDG_MAP_MAX_ITEMS"), u::MAP_MAX_ITEMS as usize);
    assert_eq!(get(&m, "const.KDG_MAP_NAME_MAX"), u::MAP_NAME_MAX);

    assert_eq!(get(&m, "const.KDG_OP_QUERY"), u::Op::Query as usize);
    assert_eq!(get(&m, "const.KDG_OP_CANCEL"), u::Op::Cancel as usize);
    assert_eq!(get(&m, "const.KDG_OP_MAP_LOOKUP"), u::Op::MapLookup as usize);
    assert_eq!(get(&m, "const.KDG_OP_GET_HEALTH"), u::Op::GetHealth as usize);

    assert_eq!(get(&m, "const.KDG_ST_OK"), u::Status::Ok as usize);
    assert_eq!(get(&m, "const.KDG_ST_EABI"), u::Status::Eabi as usize);
    assert_eq!(get(&m, "const.KDG_ST_EOP"), u::Status::Eop as usize);
    assert_eq!(get(&m, "const.KDG_ST_EMSGSIZE"), u::Status::Emsgsize as usize);
    assert_eq!(get(&m, "const.KDG_ST_ECOOKIE"), u::Status::Ecookie as usize);
    assert_eq!(
        get(&m, "const.KDG_ST_EGENERATION"),
        u::Status::Egeneration as usize
    );
    assert_eq!(get(&m, "const.KDG_ST_EPERM"), u::Status::Eperm as usize);
    assert_eq!(get(&m, "const.KDG_ST_ECANCELED"), u::Status::Ecanceled as usize);
    assert_eq!(get(&m, "const.KDG_ST_ETIMEDOUT"), u::Status::Etimedout as usize);
    assert_eq!(get(&m, "const.KDG_ST_EBADWIRE"), u::Status::Ebadwire as usize);
    assert_eq!(get(&m, "const.KDG_ST_EAGAIN"), u::Status::Eagain as usize);
    assert_eq!(get(&m, "const.KDG_ST_EUPSTREAM"), u::Status::Eupstream as usize);
}
