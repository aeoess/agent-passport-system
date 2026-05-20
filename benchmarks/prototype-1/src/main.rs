//! Prototype 1 benchmark harness — narrow Stream C scope (L0 + L1).
//!
//! Spec reference: `specs/PROTOTYPE-1-RUNTIME-PASSPORT.md` §12
//! (Stream C measurements) and §13.3 (Apple Silicon developer
//! reference environment).
//!
//! L0 measures the pure-verifier allow path (`aps_check` returning
//! Allow against a happy fixture); L1 measures the cheapest deny
//! path (spec §9 step 0 `ACTION_HASH_INVALID`). Both go through the
//! `NullSink` so no durability work happens inside the timed loop.
//! L2 / L3 / L4 require Stream B and the gateway baseline; out of
//! scope here.
//!
//! Usage:
//!
//! ```text
//! aps-bench L0
//! aps-bench L1
//! ```
//!
//! Output: JSON written to
//! `benchmarks/prototype-1/results/mac-apple-silicon/<benchmark>.json`.

mod env_capture;
mod stats;
mod workload;

use std::fs;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::atomic::Ordering;
use std::sync::Barrier;
use std::thread;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use serde::Serialize;

use crate::env_capture::EnvironmentSnapshot;
use crate::stats::LatencyStats;
use crate::workload::{
    concurrency_levels, per_thread_samples, run_check, AllowThreadFixture, DenyThreadFixture,
    Fixture, ALLOW_POOL_SIZE, ALLOW_SEQ_START,
};

const WARMUP_ITERATIONS: usize = 100_000;
const MEASURE_ITERATIONS: usize = 1_000_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Benchmark {
    L0,
    L1,
}

impl Benchmark {
    fn parse(s: &str) -> Option<Self> {
        match s {
            "L0" | "l0" => Some(Benchmark::L0),
            "L1" | "l1" => Some(Benchmark::L1),
            _ => None,
        }
    }
    fn label(self) -> &'static str {
        match self {
            Benchmark::L0 => "L0",
            Benchmark::L1 => "L1",
        }
    }
    fn description(self) -> &'static str {
        match self {
            Benchmark::L0 => "rust_core_allow_hot_cache_no_event",
            Benchmark::L1 => "rust_core_deny_hot_cache_action_hash_invalid",
        }
    }
}

#[derive(Debug, Serialize)]
struct Result {
    benchmark: &'static str,
    description: &'static str,
    environment: EnvironmentSnapshot,
    methodology: Methodology,
    samples: LatencyStats,
    run: RunMeta,
}

#[derive(Debug, Serialize)]
struct Methodology {
    warmup_iterations: usize,
    measure_iterations: usize,
    single_threaded: bool,
    timer: &'static str,
    percentile_method: &'static str,
    includes_durability: bool,
    sink: &'static str,
    deny_kind: Option<&'static str>,
    spec_step: Option<&'static str>,
    notes: &'static str,
}

#[derive(Debug, Serialize)]
struct RunMeta {
    git_commit: String,
    git_branch: String,
    timestamp_unix_ns: u128,
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        eprintln!("usage: aps-bench <L0|L1> [--concurrent]");
        return ExitCode::from(2);
    }
    let bench = match Benchmark::parse(&args[1]) {
        Some(b) => b,
        None => {
            eprintln!("unknown benchmark: {} (supported: L0, L1)", args[1]);
            return ExitCode::from(2);
        }
    };
    let concurrent = args.iter().any(|a| a == "--concurrent");
    let env = env_capture::capture_mac_apple_silicon();

    if concurrent {
        let mut summary_rows: Vec<SummaryRow> = Vec::new();
        for &level in concurrency_levels() {
            let per_thread = per_thread_samples(level);
            let result = run_concurrent(bench, level, per_thread, &env);
            let out_path = concurrent_output_path(&env, bench, level);
            if let Some(parent) = out_path.parent() {
                fs::create_dir_all(parent).expect("create_dir_all");
            }
            let json = serde_json::to_string_pretty(&result).expect("serialize");
            fs::write(&out_path, json).expect("write");
            eprintln!("wrote {}", out_path.display());
            summary_rows.push(SummaryRow {
                level,
                throughput: result.throughput_ops_per_sec,
                merged: result.merged_samples.clone(),
            });
        }
        print_concurrent_summary(bench, &summary_rows);
        return ExitCode::SUCCESS;
    }

    // Single-threaded path. Uses the same true-Allow pool+reset
    // technique as the concurrent sweep so L0 actually measures the
    // Allow path on every iteration.
    let samples = match bench {
        Benchmark::L0 => {
            let fixture = AllowThreadFixture::build().expect("allow fixture build");
            run_single_l0(&fixture)
        }
        Benchmark::L1 => {
            let fixture = Fixture::build().expect("fixture build");
            run_benchmark(bench, &fixture)
        }
    };
    let stats = stats::compute(&samples);

    let result = Result {
        benchmark: bench.label(),
        description: bench.description(),
        environment: env.clone(),
        methodology: methodology_for(bench),
        samples: stats,
        run: capture_run_meta(),
    };

    let out_path = output_path(&env, bench);
    if let Some(parent) = out_path.parent() {
        fs::create_dir_all(parent).expect("create_dir_all");
    }
    let json = serde_json::to_string_pretty(&result).expect("serialize");
    fs::write(&out_path, json).expect("write");
    eprintln!("wrote {}", out_path.display());

    println!(
        "{} n={} p50={}ns p95={}ns p99={}ns p99.9={}ns",
        bench.label(),
        result.samples.n,
        result.samples.p50_ns,
        result.samples.p95_ns,
        result.samples.p99_ns,
        result.samples.p99_9_ns
    );
    ExitCode::SUCCESS
}

// -----------------------------------------------------------------------
// Concurrent sweep
// -----------------------------------------------------------------------

#[derive(Debug, Serialize)]
struct ConcurrentResult {
    benchmark: &'static str,
    description: &'static str,
    environment: EnvironmentSnapshot,
    concurrency_level: usize,
    per_thread_samples: u64,
    total_samples: u64,
    total_wall_time_ns: u64,
    throughput_ops_per_sec: f64,
    merged_samples: LatencyStats,
    per_thread_samples_stats: Vec<LatencyStats>,
    methodology: Methodology,
    run: RunMeta,
}

struct SummaryRow {
    level: usize,
    throughput: f64,
    merged: LatencyStats,
}

fn run_concurrent(
    bench: Benchmark,
    level: usize,
    per_thread: usize,
    env: &EnvironmentSnapshot,
) -> ConcurrentResult {
    // Pre-build all fixtures untimed.
    let all_samples: Vec<Vec<u64>> = match bench {
        Benchmark::L0 => {
            let fixtures: Vec<AllowThreadFixture> = (0..level)
                .map(|_| AllowThreadFixture::build().expect("allow fixture"))
                .collect();
            run_concurrent_l0(fixtures, per_thread)
        }
        Benchmark::L1 => {
            let fixtures: Vec<DenyThreadFixture> = (0..level)
                .map(|_| DenyThreadFixture::build().expect("deny fixture"))
                .collect();
            run_concurrent_l1(fixtures, per_thread)
        }
    };

    let mut merged: Vec<u64> = Vec::with_capacity(level * per_thread);
    for v in &all_samples {
        merged.extend_from_slice(v);
    }
    let total_samples = merged.len() as u64;
    // Wall time is the elapsed time captured inside run_concurrent_{l0,l1};
    // the helpers track it. We need that too — re-do:
    let total_wall_time_ns = max_per_thread_wall_time(&all_samples);
    let throughput = (total_samples as f64) / (total_wall_time_ns as f64 / 1e9);
    let merged_stats = stats::compute(&merged);
    let per_thread_stats: Vec<_> = all_samples.iter().map(|s| stats::compute(s)).collect();

    ConcurrentResult {
        benchmark: bench.label(),
        description: bench.description(),
        environment: env.clone(),
        concurrency_level: level,
        per_thread_samples: per_thread as u64,
        total_samples,
        total_wall_time_ns,
        throughput_ops_per_sec: throughput,
        merged_samples: merged_stats,
        per_thread_samples_stats: per_thread_stats,
        methodology: methodology_for_concurrent(bench, level),
        run: capture_run_meta(),
    }
}

/// Sum each thread's per-call elapsed nanoseconds; the max across
/// threads approximates total wall time for the concurrent run. (Each
/// thread also has setup/teardown not in the per-call samples, but at
/// 100k+ samples per thread the per-call work dominates.)
fn max_per_thread_wall_time(all_samples: &[Vec<u64>]) -> u64 {
    all_samples
        .iter()
        .map(|v| v.iter().sum::<u64>())
        .max()
        .unwrap_or(0)
}

fn run_concurrent_l0(fixtures: Vec<AllowThreadFixture>, per_thread: usize) -> Vec<Vec<u64>> {
    let level = fixtures.len();
    let barrier = Barrier::new(level + 1);
    thread::scope(|s| {
        let handles: Vec<_> = fixtures
            .into_iter()
            .map(|fixture| {
                let barrier = &barrier;
                s.spawn(move || {
                    let ctx = fixture.context();
                    // Warmup (untimed)
                    for i in 0..2048 {
                        let idx = i & (ALLOW_POOL_SIZE - 1);
                        if idx == 0 {
                            fixture
                                .authority
                                .sequence_next
                                .store(ALLOW_SEQ_START, Ordering::Release);
                        }
                        let d = run_check(&fixture.authority, &fixture.actions[idx], &ctx);
                        std::hint::black_box(d);
                    }
                    // Synchronize start
                    barrier.wait();
                    let mut samples = Vec::with_capacity(per_thread);
                    for i in 0..per_thread {
                        let idx = i & (ALLOW_POOL_SIZE - 1);
                        if idx == 0 {
                            fixture
                                .authority
                                .sequence_next
                                .store(ALLOW_SEQ_START, Ordering::Release);
                        }
                        let t0 = Instant::now();
                        let d = run_check(&fixture.authority, &fixture.actions[idx], &ctx);
                        let elapsed = t0.elapsed().as_nanos() as u64;
                        std::hint::black_box(d);
                        samples.push(elapsed);
                    }
                    samples
                })
            })
            .collect();
        barrier.wait();
        handles.into_iter().map(|h| h.join().unwrap()).collect()
    })
}

fn run_concurrent_l1(fixtures: Vec<DenyThreadFixture>, per_thread: usize) -> Vec<Vec<u64>> {
    let level = fixtures.len();
    let barrier = Barrier::new(level + 1);
    thread::scope(|s| {
        let handles: Vec<_> = fixtures
            .into_iter()
            .map(|fixture| {
                let barrier = &barrier;
                s.spawn(move || {
                    let ctx = fixture.context();
                    // Warmup
                    for _ in 0..2048 {
                        let d = run_check(&fixture.authority, &fixture.action, &ctx);
                        std::hint::black_box(d);
                    }
                    barrier.wait();
                    let mut samples = Vec::with_capacity(per_thread);
                    for _ in 0..per_thread {
                        let t0 = Instant::now();
                        let d = run_check(&fixture.authority, &fixture.action, &ctx);
                        let elapsed = t0.elapsed().as_nanos() as u64;
                        std::hint::black_box(d);
                        samples.push(elapsed);
                    }
                    samples
                })
            })
            .collect();
        barrier.wait();
        handles.into_iter().map(|h| h.join().unwrap()).collect()
    })
}

fn methodology_for_concurrent(bench: Benchmark, level: usize) -> Methodology {
    match bench {
        Benchmark::L0 => Methodology {
            warmup_iterations: 2048,
            measure_iterations: per_thread_samples(level),
            single_threaded: false,
            timer: "std::time::Instant",
            percentile_method: "raw sample at index ceil(p * (n-1)), no interpolation",
            includes_durability: false,
            sink: "NullSink (no-op trait dispatch only)",
            deny_kind: None,
            spec_step: Some(
                "§9 all 13 steps + §9 step 13 emit via NullSink (true Allow per call)",
            ),
            notes: "Concurrent L0: N independent sessions per spec §5.2 — each thread owns \
                its CompiledAuthority and a 1024-entry pool of pre-finalized actions with \
                incrementing sequence_ids. Authority.sequence_next is reset to ALLOW_SEQ_START \
                when the pool wraps (untimed atomic store). Every per-call sample is a true \
                Allow; deviates from the single-threaded L0 methodology (which used one \
                action repeatedly and got SEQUENCE_REPLAY for iters 1..N).",
        },
        Benchmark::L1 => Methodology {
            warmup_iterations: 2048,
            measure_iterations: per_thread_samples(level),
            single_threaded: false,
            timer: "std::time::Instant",
            percentile_method: "raw sample at index ceil(p * (n-1)), no interpolation",
            includes_durability: false,
            sink: "NullSink (never invoked on deny path)",
            deny_kind: Some("ACTION_HASH_INVALID (cheapest deny)"),
            spec_step: Some("§9 step 0"),
            notes: "Concurrent L1: N independent sessions, each thread runs the same \
                tampered-action_hash deny in a tight loop. Deny short-circuits at step 0 \
                and never touches sequence/budget, so a single action per thread is \
                sufficient — same methodology as single-threaded L1.",
        },
    }
}

fn print_concurrent_summary(bench: Benchmark, rows: &[SummaryRow]) {
    println!();
    println!("{} concurrency sweep", bench.label());
    println!(
        "{:>5} | {:>8} | {:>10} | {:>14}",
        "Level", "p50", "p99.9", "throughput"
    );
    println!("{:->5}-+-{:->8}-+-{:->10}-+-{:->14}", "", "", "", "");
    for r in rows {
        println!(
            "{:>5} | {:>6}ns | {:>8}ns | {:>10.0} op/s",
            r.level, r.merged.p50_ns, r.merged.p99_9_ns, r.throughput
        );
    }
}

fn concurrent_output_path(env: &EnvironmentSnapshot, bench: Benchmark, level: usize) -> PathBuf {
    let mut p = PathBuf::from("benchmarks/prototype-1/results");
    p.push(&env.label);
    p.push(format!("{}-concurrent-{}.json", bench.label(), level));
    p
}

/// True-Allow single-threaded L0: same pool+reset pattern the
/// concurrent sweep uses, ensuring every sampled call is a real
/// Allow (not a SEQUENCE_REPLAY deny that pre-correction L0 actually
/// measured).
fn run_single_l0(fixture: &AllowThreadFixture) -> Vec<u64> {
    let ctx = fixture.context();
    // Warmup.
    for i in 0..WARMUP_ITERATIONS {
        let idx = i & (ALLOW_POOL_SIZE - 1);
        if idx == 0 {
            fixture
                .authority
                .sequence_next
                .store(ALLOW_SEQ_START, Ordering::Release);
        }
        let d = run_check(&fixture.authority, &fixture.actions[idx], &ctx);
        std::hint::black_box(d);
    }
    // Measure.
    let mut samples = Vec::with_capacity(MEASURE_ITERATIONS);
    for i in 0..MEASURE_ITERATIONS {
        let idx = i & (ALLOW_POOL_SIZE - 1);
        if idx == 0 {
            fixture
                .authority
                .sequence_next
                .store(ALLOW_SEQ_START, Ordering::Release);
        }
        let t0 = Instant::now();
        let d = run_check(&fixture.authority, &fixture.actions[idx], &ctx);
        let elapsed = t0.elapsed().as_nanos() as u64;
        std::hint::black_box(d);
        samples.push(elapsed);
    }
    samples
}

fn run_benchmark(bench: Benchmark, fixture: &Fixture) -> Vec<u64> {
    let ctx = fixture.context();
    let action = match bench {
        Benchmark::L0 => &fixture.action_allow,
        Benchmark::L1 => &fixture.action_deny_action_hash_invalid,
    };

    // For L0, every Allow advances sequence_next. To support 1M+1
    // iterations from a single fixture without re-building between
    // batches, the passport's sequence_end is set to 100_000_001 (see
    // workload.rs). Each measure call mutates only this one fixture
    // and stays well inside the window.
    //
    // For L1 (action_hash_invalid), the deny short-circuits at step 0
    // and never touches sequence/budget.

    // Warmup — for L0 these advances ALSO consume from the same
    // sequence window, so the window is sized to accommodate
    // WARMUP_ITERATIONS + MEASURE_ITERATIONS.
    for _ in 0..WARMUP_ITERATIONS {
        let d = run_check(&fixture.authority, action, &ctx);
        std::hint::black_box(d);
    }

    let mut samples = Vec::with_capacity(MEASURE_ITERATIONS);
    for _ in 0..MEASURE_ITERATIONS {
        let t0 = Instant::now();
        let d = run_check(&fixture.authority, action, &ctx);
        let elapsed = t0.elapsed().as_nanos() as u64;
        std::hint::black_box(d);
        samples.push(elapsed);
    }
    samples
}

fn methodology_for(bench: Benchmark) -> Methodology {
    match bench {
        Benchmark::L0 => Methodology {
            warmup_iterations: WARMUP_ITERATIONS,
            measure_iterations: MEASURE_ITERATIONS,
            single_threaded: true,
            timer: "std::time::Instant",
            percentile_method: "raw sample at index ceil(p * (n-1)), no interpolation",
            includes_durability: false,
            sink: "NullSink (no-op trait dispatch only)",
            deny_kind: None,
            spec_step: Some(
                "§9 all 13 steps + §9 step 13 emit via NullSink (true Allow per call)",
            ),
            notes: "L0 measures the full aps_check Allow pipeline. Single thread, \
                1024-entry pool of pre-finalized actions with incrementing \
                sequence_ids; authority.sequence_next is reset to ALLOW_SEQ_START \
                when the pool wraps (untimed atomic store). Every per-call sample \
                is a true Allow. Earlier L0 result from commit 913cb12 used one \
                action repeatedly and got SEQUENCE_REPLAY for iters 1..N — same \
                BLAKE3 floor, but artifact label did not match measurement. \
                Concurrent L0-concurrent-1.json uses the same corrected \
                methodology by construction.",
        },
        Benchmark::L1 => Methodology {
            warmup_iterations: WARMUP_ITERATIONS,
            measure_iterations: MEASURE_ITERATIONS,
            single_threaded: true,
            timer: "std::time::Instant",
            percentile_method: "raw sample at index ceil(p * (n-1)), no interpolation",
            includes_durability: false,
            sink: "NullSink (never invoked on deny path)",
            deny_kind: Some("ACTION_HASH_INVALID (cheapest deny)"),
            spec_step: Some("§9 step 0"),
            notes: "L1 measures the fast-reject path: the action's action_hash is \
                tampered after finalize, so step 0 fails and aps_check returns \
                immediately without touching the sink or advancing sequence/budget.",
        },
    }
}

fn capture_run_meta() -> RunMeta {
    use std::process::Command;
    let commit = Command::new("git")
        .args(["rev-parse", "HEAD"])
        .output()
        .ok()
        .and_then(|o| {
            if o.status.success() {
                Some(String::from_utf8_lossy(&o.stdout).trim().to_string())
            } else {
                None
            }
        })
        .unwrap_or_else(|| "unknown".into());
    let branch = Command::new("git")
        .args(["rev-parse", "--abbrev-ref", "HEAD"])
        .output()
        .ok()
        .and_then(|o| {
            if o.status.success() {
                Some(String::from_utf8_lossy(&o.stdout).trim().to_string())
            } else {
                None
            }
        })
        .unwrap_or_else(|| "unknown".into());
    let timestamp_unix_ns = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    RunMeta {
        git_commit: commit,
        git_branch: branch,
        timestamp_unix_ns,
    }
}

fn output_path(env: &EnvironmentSnapshot, bench: Benchmark) -> PathBuf {
    let mut p = PathBuf::from("benchmarks/prototype-1/results");
    p.push(&env.label);
    p.push(format!("{}.json", bench.label()));
    p
}
