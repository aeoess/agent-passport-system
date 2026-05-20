//! Synthetic invoice-reconciliation workload (Stream C).
//!
//! Spec reference: `specs/PROTOTYPE-1-RUNTIME-PASSPORT.md` Section 12,
//! Stream C — "Workload: synthetic action stream simulating invoice
//! reconciliation."
//!
//! Throughput is swept across concurrency levels; tail latency is
//! reported at p50, p95, p99, p99.9.

/// A single action in the invoice-reconciliation stream. Mix of read,
/// match, approve, and deny actions calibrated to the proportions
/// observed in real reconciliation traces.
#[derive(Debug, Clone)]
pub struct Action {
    /// Placeholder. Real shape comes from the Action Descriptor builder
    /// in Stream B (spec Section 5).
    pub _placeholder: (),
}

/// Generates a deterministic stream of `n` invoice-reconciliation
/// actions seeded by `seed`. Determinism matters so benchmark runs
/// across environments compare like-for-like.
pub fn invoice_reconciliation_stream(_n: usize, _seed: u64) -> Vec<Action> {
    todo!(
        "Stream C workload generator: synthesize an invoice-reconciliation \
         action mix per spec Section 12, Stream C. Deterministic for given seed."
    );
}

/// Concurrency sweep levels driven by the dispatcher. Tail latency is
/// reported at each level.
pub fn concurrency_levels() -> &'static [usize] {
    todo!(
        "Stream C: define concurrency sweep (e.g. 1, 2, 4, 8, 16, 32, 64) \
         once Stream B exposes the SDK entry point."
    );
}
