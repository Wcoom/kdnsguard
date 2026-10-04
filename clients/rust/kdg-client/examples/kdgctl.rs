// SPDX-License-Identifier: GPL-2.0
//! 最小诊断客户端 —— 与 C 版 `tools/kdgctl` 同源能力，用来验证 Rust 绑定。
//!
//! 用法：
//! ```text
//! kdgctl query <域名>         内核侧解析，打印 A/AAAA
//! kdgctl maplookup <IP>       反查该 IP 关联的域名（方案 §12.2）
//! kdgctl roundtrip <域名>     查询 + 对第一个地址做一次反查
//! ```

use std::env;
use std::net::IpAddr;
use std::process::ExitCode;

use kdg_client::{wire, Device, Error};

fn main() -> ExitCode {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!("用法: {} query|maplookup|roundtrip <参数>", args[0]);
        return ExitCode::from(2);
    }

    let mut dev = match Device::open() {
        Ok(d) => d,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::FAILURE;
        }
    };

    let r = match args[1].as_str() {
        "query" => {
            let name = arg(&args, 2);
            cmd_query(&mut dev, name)
        }
        "maplookup" => {
            let text = arg(&args, 2);
            match text.parse::<IpAddr>() {
                Ok(ip) => cmd_maplookup(&mut dev, ip),
                Err(_) => {
                    eprintln!("地址非法：{text}");
                    return ExitCode::from(2);
                }
            }
        }
        "roundtrip" => {
            let name = arg(&args, 2);
            match cmd_query(&mut dev, name) {
                Ok(()) => cmd_roundtrip(&mut dev, name),
                Err(e) => Err(e),
            }
        }
        other => {
            eprintln!("未知子命令：{other}");
            return ExitCode::from(2);
        }
    };

    match r {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("失败：{e}");
            ExitCode::FAILURE
        }
    }
}

fn arg<'a>(args: &'a [String], i: usize) -> &'a str {
    args.get(i).map(|s| s.as_str()).unwrap_or("")
}

fn cmd_query(dev: &mut Device, name: &str) -> Result<(), Error> {
    if name.is_empty() {
        eprintln!("缺域名");
        return Err(Error::Wire(kdg_client::WireError::Malformed));
    }
    let msg = dev.query(name, wire::TYPE_A)?;
    println!(
        "查询 {name}: rcode={} ancount={} truncated={}",
        msg.rcode(),
        msg.ancount,
        msg.is_truncated()
    );
    for r in &msg.answers {
        if let Some(ip) = r.as_ipv4() {
            println!("  A     {ip}  ttl={}", r.ttl);
        } else if let Some(ip) = r.as_ipv6() {
            println!("  AAAA  {ip}  ttl={}", r.ttl);
        } else if r.rtype == wire::TYPE_CNAME {
            // CNAME 的 rdata 可能是压缩名，这里只报类型，不做名字解码 ——
            // 客户端的职责是编解码与展示，不是补全 DNS 语义。
            println!("  CNAME ({} 字节 rdata)  ttl={}", r.rdata.len(), r.ttl);
        } else {
            println!("  type={} len={} ttl={}", r.rtype, r.rdata.len(), r.ttl);
        }
    }
    Ok(())
}

fn cmd_maplookup(dev: &mut Device, ip: IpAddr) -> Result<(), Error> {
    let res = dev.map_lookup(ip)?;
    println!(
        "反查 {ip}: count={} truncated={} profile_gen={}",
        res.entries.len(),
        res.truncated,
        res.profile_generation
    );
    for e in &res.entries {
        println!("  {}  ttl={} ms", e.name, e.ttl.as_millis());
    }
    if res.entries.is_empty() {
        println!("  （该 IP 没有已知关联）");
    }
    if res.truncated {
        println!("  ⚠️ 结果被截断：还有候选未返回，不要当成「就这几个」");
    }
    Ok(())
}

fn cmd_roundtrip(dev: &mut Device, name: &str) -> Result<(), Error> {
    let msg = dev.query(name, wire::TYPE_A)?;
    let Some(ip) = msg.ipv4_answers().into_iter().next() else {
        println!("（没有 A 记录，跳过反查）");
        return Ok(());
    };
    println!("--- 对 {ip} 反查 ---");
    cmd_maplookup(dev, IpAddr::V4(ip))
}
