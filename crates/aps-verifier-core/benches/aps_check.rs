//! Benchmark stubs for `aps_check`, per Section 13 of
//! `specs/PROTOTYPE-1-RUNTIME-PASSPORT.md`.
//!
//! Targets:
//!   - L0: Rust core, hot cache, allow path, no event. Pure verification.
//!   - L1: Rust core, hot cache, deny path. Fast-reject cost.
//!
//! Storage-config logging (Section 13.4) applies to Mode B benchmarks,
//! which are owned by Stream C's harness. This file covers the pure
//! verifier numbers (L0, L1).
//!
//! TODO: hot CompiledAuthority fixtures, allow + deny ActionDescriptor
//! pre-built, criterion harness wiring.

use criterion::{criterion_group, criterion_main, Criterion};

fn bench_aps_check_l0_allow(c: &mut Criterion) {
    c.bench_function("L0_allow_hot_cache", |b| {
        b.iter(|| {
            todo!("Section 13 L0 benchmark: implementation pending");
        });
    });
}

fn bench_aps_check_l1_deny(c: &mut Criterion) {
    c.bench_function("L1_deny_hot_cache", |b| {
        b.iter(|| {
            todo!("Section 13 L1 benchmark: implementation pending");
        });
    });
}

criterion_group!(benches, bench_aps_check_l0_allow, bench_aps_check_l1_deny);
criterion_main!(benches);
