//! Prototype 1 benchmark dispatcher (Stream C).
//!
//! Drives the seven measurements from the spec's Stream C table:
//!
//! - L0   Rust core, hot cache, allow path, no event.
//! - L1   Rust core, hot cache, deny path.
//! - L2   TS SDK via N-API, no event.
//! - L3a  TS SDK + Mode A (memory-buffered).
//! - L3b1 TS SDK + Mode B1 (blocking group-commit).
//! - L3b2 TS SDK + Mode B2 (queued group-commit).
//! - L4   Current gateway baseline.
//!
//! See `specs/PROTOTYPE-1-RUNTIME-PASSPORT.md` Section 12 (Stream C)
//! and Section 13 (environments).

mod env_capture;
mod workload;

/// Selects which of the L0..L4 measurements to run. Populated from the
/// `--config configs/<env>.toml` argument.
#[derive(Debug)]
pub enum Benchmark {
    L0,
    L1,
    L2,
    L3a,
    L3b1,
    L3b2,
    L4,
}

/// Loads the environment config TOML, captures Section 13.4 metadata,
/// then dispatches to the selected benchmarks.
///
/// Pending Stream A and Stream B exposing callable interfaces.
fn main() {
    todo!(
        "Stream C dispatcher: parse --config <env>.toml, capture env metadata \
         per spec Section 13.4, run selected L0..L4 benchmarks via criterion, \
         write results to results/<env>/<benchmark>.json."
    );
}
