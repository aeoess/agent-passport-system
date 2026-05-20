//! Latency statistics computation.
//!
//! Inputs are per-call latency samples in nanoseconds; outputs are
//! the spec §12 reported percentiles plus basic descriptive
//! statistics. Percentile method is documented and embedded into
//! every result JSON so future runs are comparable.

use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub struct LatencyStats {
    pub n: usize,
    pub mean_ns: u64,
    pub stddev_ns: u64,
    pub min_ns: u64,
    pub max_ns: u64,
    pub p50_ns: u64,
    pub p95_ns: u64,
    pub p99_ns: u64,
    pub p99_9_ns: u64,
}

/// Compute the per-percentile reported values plus mean/stddev/min/max.
/// `samples` does not need to be pre-sorted; this routine sorts a
/// copy. Percentile method is the conservative "raw sample at index
/// ceil(p * (n-1))" — no interpolation, no smoothing.
pub fn compute(samples: &[u64]) -> LatencyStats {
    assert!(!samples.is_empty(), "empty sample set");
    let n = samples.len();
    let mut sorted = samples.to_vec();
    sorted.sort_unstable();

    let sum: u128 = sorted.iter().map(|&x| x as u128).sum();
    let mean = (sum / n as u128) as u64;
    let variance: u128 = sorted
        .iter()
        .map(|&x| {
            let d = (x as i128) - (mean as i128);
            (d * d) as u128
        })
        .sum::<u128>()
        / n as u128;
    let stddev = (variance as f64).sqrt() as u64;

    LatencyStats {
        n,
        mean_ns: mean,
        stddev_ns: stddev,
        min_ns: sorted[0],
        max_ns: sorted[n - 1],
        p50_ns: percentile(&sorted, 0.50),
        p95_ns: percentile(&sorted, 0.95),
        p99_ns: percentile(&sorted, 0.99),
        p99_9_ns: percentile(&sorted, 0.999),
    }
}

fn percentile(sorted: &[u64], p: f64) -> u64 {
    let n = sorted.len();
    let idx = ((n as f64 - 1.0) * p).ceil() as usize;
    sorted[idx.min(n - 1)]
}
