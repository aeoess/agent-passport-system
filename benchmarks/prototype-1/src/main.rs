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
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use serde::Serialize;

use crate::env_capture::EnvironmentSnapshot;
use crate::stats::LatencyStats;
use crate::workload::{run_check, Fixture};

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
        eprintln!("usage: aps-bench <L0|L1>");
        return ExitCode::from(2);
    }
    let bench = match Benchmark::parse(&args[1]) {
        Some(b) => b,
        None => {
            eprintln!("unknown benchmark: {} (supported: L0, L1)", args[1]);
            return ExitCode::from(2);
        }
    };

    let fixture = Fixture::build().expect("fixture build");
    let env = env_capture::capture_mac_apple_silicon();

    let samples = run_benchmark(bench, &fixture);
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

    // Echo a one-line summary to stdout so log capture is easy.
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
            spec_step: Some("§9 all 13 steps + §9 step 13 emit via NullSink"),
            notes: "L0 measures the full aps_check pipeline on the happy path, \
                including the NullSink trait dispatch overhead and the BLAKE3 \
                event_mac computation in finalize(). Sequence window is sized to \
                accommodate WARMUP + MEASURE iterations from a single fixture.",
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
