// SPDX-License-Identifier: GPL-2.0
//! kdgbench —— P6 用的 DNS 查询基准工具（方案 §17.3/§17.4）。
//!
//! 为什么要它：方案要求「同设备、同请求轨迹、同网络」比较不同 DNS 实现，
//! 而且要分离**本地处理**与**上游网络**两部分耗时。现成工具做不到：
//! `dig`/`nslookup` 是单发、没有分位数、读不到内核侧的缓存/合并计数，
//! 也不报 CPU 与上下文切换。
//!
//! 两条路径**都测**，因为 P6 的核心就是拿它们对比：
//!   * `chardev` —— 内核项目路径（/dev/kdnsguard）
//!   * `udp`     —— 往任意 UDP DNS 发（用来测用户态基线，例如 mihomo 的
//!                  127.0.0.1:1053）
//!
//! 输出是单行 `key=value`，便于设备脚本直接 grep/拼接。
//!
//! 用法：
//! ```text
//! kdgbench chardev --trace t.txt --concurrency 16 --repeat 5 --label warm
//! kdgbench udp 127.0.0.1:1053 --trace t.txt --concurrency 16 --label baseline
//! ```

use std::net::UdpSocket;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use kdg_client::{wire, Device};

// ── CPU 时间：std 没有这个 API，直接调 libc ────────────────────────────
//
// 为什么不用 /proc/self/stat：它的 utime/stime 单位是时钟节拍，Android 上
// 通常 HZ=100 ⇒ 10 ms 粒度。而一次 10000 条的基准跑几百毫秒，用节拍去量
// 等于用一个刻度尺量头发丝。
#[repr(C)]
struct Timespec {
    tv_sec: i64,
    tv_nsec: i64,
}
const CLOCK_PROCESS_CPUTIME_ID: i32 = 2;

extern "C" {
    fn clock_gettime(clk_id: i32, tp: *mut Timespec) -> i32;
}

fn cpu_ns() -> u128 {
    let mut ts = Timespec { tv_sec: 0, tv_nsec: 0 };
    // SAFETY: clock_gettime 是 libc 的普通函数；指针指向本栈上的合法
    // Timespec，CLOCK_PROCESS_CPUTIME_ID 在所有 POSIX 目标上都有效。
    let rc = unsafe { clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &mut ts) };
    if rc != 0 {
        return 0;
    }
    (ts.tv_sec as u128) * 1_000_000_000 + (ts.tv_nsec as u128)
}

/// 从 /proc/self/status 读上下文切换次数。读不到就返回 0（不 panic）——
/// 这个量是**辅助证据**，不该因为它拿不到就让整次测量失败。
fn ctxt_switches() -> (u64, u64) {
    let mut vol = 0u64;
    let mut invol = 0u64;
    if let Ok(s) = std::fs::read_to_string("/proc/self/status") {
        for line in s.lines() {
            let mut it = line.split_whitespace();
            match it.next() {
                Some("voluntary_ctxt_switches:") => {
                    vol = it.next().and_then(|v| v.parse().ok()).unwrap_or(0)
                }
                Some("nonvoluntary_ctxt_switches:") => {
                    invol = it.next().and_then(|v| v.parse().ok()).unwrap_or(0)
                }
                _ => {}
            }
        }
    }
    (vol, invol)
}

// ── 参数 ───────────────────────────────────────────────────────────────

struct Args {
    mode: String,
    target: String,
    trace: String,
    concurrency: usize,
    repeat: usize,
    timeout_ms: u64,
    label: String,
    warmup: usize,
}

fn parse_args() -> Result<Args, String> {
    let mut a = std::env::args().skip(1);
    let mode = a.next().ok_or("用法: kdgbench chardev|udp <ip:port> --trace <file> [...]")?;
    // 只有 udp 模式才有位置参数（目标地址）。第一版无条件多取一个，结果
    // chardev 模式把 `--trace` 当成了 target、再把 trace 路径当成未知参数。
    let target = if mode == "udp" {
        a.next().ok_or("udp 模式需要 <ip:port>")?
    } else {
        String::new()
    };
    let mut out = Args {
        mode,
        target,
        trace: String::new(),
        concurrency: 1,
        repeat: 1,
        timeout_ms: 5000,
        label: String::new(),
        warmup: 0,
    };
    while let Some(k) = a.next() {
        let v = a.next().ok_or_else(|| format!("{k} 缺少取值"))?;
        match k.as_str() {
            "--trace" => out.trace = v,
            "--concurrency" => out.concurrency = v.parse().map_err(|_| "并发数非法")?,
            "--repeat" => out.repeat = v.parse().map_err(|_| "重复数非法")?,
            "--timeout-ms" => out.timeout_ms = v.parse().map_err(|_| "超时非法")?,
            "--label" => out.label = v,
            // 预热不计入统计：首条查询要付 TLS/连接建立的钱，
            // 把它算进 p50 会让「热态」这个标签失去意义。
            "--warmup" => out.warmup = v.parse().map_err(|_| "warmup 非法")?,
            other => return Err(format!("未知参数 {other}")),
        }
    }
    if out.trace.is_empty() {
        return Err("必须给 --trace".into());
    }
    if out.concurrency == 0 {
        return Err("并发数不能为 0".into());
    }
    Ok(out)
}

// ── 查询执行 ───────────────────────────────────────────────────────────

/// 一条查询的执行体。
///
/// ⚠️ **每个 worker 各持有自己的一份**，不是全进程共享一个。
/// 共享一份就必须加锁，而加锁会把并发请求串行化 —— 那样测出来的
/// 「并发 16」和「并发 1」是一样的，等于没测。内核的字符设备是**每 fd 一份
/// 上下文**（`kdg_file_ctx`），所以每 worker 开一条 fd 才是它的真实用法；
/// UDP 侧同理，每 worker 一条 socket 复用它（而不是每条查询新建）。
struct ChardevQueryerMut {
    dev: Device,
}

/// 需要 &mut 的实现单独一组方法 —— Rust 里「每 worker 独占」用 `&mut self`
/// 表达最自然，不必为了统一签名引入锁。
trait QueryerMut {
    fn query_mut(&mut self, domain: &str) -> Result<(), String>;
}

impl QueryerMut for ChardevQueryerMut {
    fn query_mut(&mut self, domain: &str) -> Result<(), String> {
        let q = wire::build_query(domain, wire::TYPE_A, 0x4b44)
            .map_err(|e| format!("编码 {domain}: {e}"))?;
        let resp = self.dev.query_wire(&q, 5000).map_err(|e| e.to_string())?;
        wire::parse(&resp).map_err(|e| e.to_string())?;
        Ok(())
    }
}

struct UdpQueryerMut {
    sock: UdpSocket,
    target: String,
}

impl QueryerMut for UdpQueryerMut {
    fn query_mut(&mut self, domain: &str) -> Result<(), String> {
        let q = wire::build_query(domain, wire::TYPE_A, 0x4b44)
            .map_err(|e| format!("编码 {domain}: {e}"))?;
        self.sock.send_to(&q, &self.target).map_err(|e| e.to_string())?;
        let mut buf = [0u8; 4096];
        let n = self.sock.recv(&mut buf).map_err(|e| e.to_string())?;
        wire::parse(&buf[..n]).map_err(|e| e.to_string())?;
        Ok(())
    }
}

/// 每个 worker 造一条自己的查询通道。
fn make_queryer(a: &Args) -> Result<Box<dyn QueryerMut>, String> {
    if a.mode == "chardev" {
        Ok(Box::new(ChardevQueryerMut {
            dev: Device::open().map_err(|e| format!("打开设备: {e}"))?,
        }))
    } else {
        let sock = UdpSocket::bind("0.0.0.0:0").map_err(|e| e.to_string())?;
        sock.set_read_timeout(Some(Duration::from_millis(a.timeout_ms)))
            .map_err(|e| e.to_string())?;
        Ok(Box::new(UdpQueryerMut { sock, target: a.target.clone() }))
    }
}

fn percentile(sorted: &[u128], p: f64) -> u128 {
    if sorted.is_empty() {
        return 0;
    }
    // 最近秩法：索引 = ceil(p/100 * n) - 1，夹到合法范围。
    let n = sorted.len() as f64;
    let mut idx = (p / 100.0 * n).ceil() as isize - 1;
    if idx < 0 {
        idx = 0;
    }
    if idx as usize >= sorted.len() {
        idx = sorted.len() as isize - 1;
    }
    sorted[idx as usize]
}

fn run(a: &Args) -> Result<(), String> {
    let raw = std::fs::read_to_string(&a.trace).map_err(|e| format!("读 trace: {e}"))?;
    let domains: Vec<String> = raw
        .lines()
        .map(|l| l.trim())
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(|l| l.to_string())
        .collect();
    if domains.is_empty() {
        return Err("trace 为空".into());
    }
    // repeat 是**顺序**重复整条轨迹，不是把它拉长：这样每一次重复都对应
    // 「一轮冷/热轨迹」，与方案 §17.3 的表述一致。
    let mut total = Vec::with_capacity(domains.len() * a.repeat);
    for _ in 0..a.repeat {
        total.extend(domains.iter().cloned());
    }
    let work = Arc::new(total);
    let warmup = a.warmup.min(work.len());

    if a.mode != "chardev" && a.mode != "udp" {
        return Err(format!("未知模式 {}", a.mode));
    }
    if a.mode == "udp" && a.target.is_empty() {
        return Err("udp 模式需要 <ip:port>".into());
    }

    // 预热（不计入统计）。用一条独立的通道，避免把建连成本留在被测通道上。
    {
        let mut q = make_queryer(a)?;
        for d in work.iter().take(warmup) {
            let _ = q.query_mut(d);
        }
    }

    let n = work.len() - warmup;
    let lat = Arc::new(Mutex::new(Vec::<u128>::with_capacity(n)));
    let errs = Arc::new(AtomicUsize::new(0));
    let next = Arc::new(AtomicUsize::new(warmup));

    let (v0, i0) = ctxt_switches();
    let cpu0 = cpu_ns();
    let t0 = Instant::now();

    std::thread::scope(|scope| {
        for _ in 0..a.concurrency {
            let work = Arc::clone(&work);
            let lat = Arc::clone(&lat);
            let errs = Arc::clone(&errs);
            let next = Arc::clone(&next);
            scope.spawn(move || {
                // 建通道失败要计入错误而不是静默少跑 —— 那会让 QPS 虚高。
                let mut q = match make_queryer(a) {
                    Ok(q) => q,
                    Err(_) => {
                        errs.fetch_add(1, Ordering::Relaxed);
                        return;
                    }
                };
                let mut local: Vec<u128> = Vec::new();
                loop {
                    let i = next.fetch_add(1, Ordering::Relaxed);
                    if i >= work.len() {
                        break;
                    }
                    let t = Instant::now();
                    match q.query_mut(&work[i]) {
                        Ok(()) => local.push(t.elapsed().as_nanos()),
                        Err(_) => {
                            errs.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                }
                if let Ok(mut g) = lat.lock() {
                    g.extend_from_slice(&local);
                }
            });
        }
    });

    let wall = t0.elapsed();
    let cpu = cpu_ns().saturating_sub(cpu0);
    let (v1, i1) = ctxt_switches();

    let mut sorted = lat.lock().map_err(|_| "锁中毒")?.clone();
    sorted.sort_unstable();
    let err = errs.load(Ordering::Relaxed);
    let ok = sorted.len();

    // 输出单行 key=value：设备脚本直接用，不引入 JSON 依赖。
    println!(
        "label={} mode={} concurrency={} n_ok={} n_err={} wall_ms={} cpu_ms={} \
         ctxt_vol={} ctxt_invol={} p50_us={} p95_us={} p99_us={} max_us={} \
         min_us={} qps={:.1}",
        if a.label.is_empty() { "-" } else { &a.label },
        a.mode,
        a.concurrency,
        ok,
        err,
        wall.as_millis(),
        cpu / 1_000_000,
        v1 - v0,
        i1 - i0,
        percentile(&sorted, 50.0) / 1000,
        percentile(&sorted, 95.0) / 1000,
        percentile(&sorted, 99.0) / 1000,
        sorted.last().copied().unwrap_or(0) / 1000,
        sorted.first().copied().unwrap_or(0) / 1000,
        if wall.as_secs_f64() > 0.0 {
            ok as f64 / wall.as_secs_f64()
        } else {
            0.0
        }
    );
    Ok(())
}

fn main() {
    let a = match parse_args() {
        Ok(a) => a,
        Err(e) => {
            eprintln!("{e}");
            std::process::exit(2);
        }
    };
    if let Err(e) = run(&a) {
        eprintln!("失败: {e}");
        std::process::exit(1);
    }
}
