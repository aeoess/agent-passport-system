# Prototype 1 Benchmark Harness (Stream C)

Criterion-based harness for the APS Runtime Passport Prototype 1 measurements.

- **Spec:** [`specs/PROTOTYPE-1-RUNTIME-PASSPORT.md`](../../specs/PROTOTYPE-1-RUNTIME-PASSPORT.md)
- **Measurement matrix:** Section 12 (Stream C table — L0..L4).
- **Environment requirements:** Section 13 (canonical bare-metal Linux, AWS cloud reference, Apple Silicon developer reference).
- **Mode B metadata logging:** Section 13.4.

## Status

Scaffolding only. Implementation is **pending Stream A** (`aps-verifier-core`)
and **Stream B** (TypeScript SDK / N-API wrapper) exposing a callable
interface that this harness can drive.

All Rust source bodies are `todo!()` with doc comments pointing at the
spec sections that describe what they will measure.

## Layout

```
benchmarks/prototype-1/
  Cargo.toml             criterion-based runner (workspace member)
  src/main.rs            benchmark dispatcher
  src/workload.rs        synthetic invoice-reconciliation workload
  src/env_capture.rs     Section 13.4 metadata capture
  configs/
    bare-metal-linux.toml   Section 13.1 canonical
    aws-c7i-gp3.toml        Section 13.2 cloud reference
    mac-apple-silicon.toml  Section 13.3 developer reference
  results/                  published numbers land here
```

## Workload

Synthetic action stream simulating invoice reconciliation (spec Section 12,
Stream C). Throughput is swept across concurrency levels; tail latency is
reported at p50, p95, p99, p99.9.

## Result table template

Numbers below are placeholders. Fill from `results/` once Stream A and B
expose a callable interface. Every Mode B entry MUST be accompanied by
the Section 13.4 metadata block emitted by `env_capture.rs`.

| Environment | L0 | L1 | L2 | L3a | L3b1 | L3b2 | L4 |
|---|---|---|---|---|---|---|---|
| Bare metal Linux (13.1, canonical) | — | — | — | — | — | — | — |
| AWS c7i.2xlarge + gp3 (13.2)       | — | — | — | — | — | — | — |
| Apple Silicon Mac (13.3)           | — | — | — | — | — | — | — |

Legend (spec Section 12):

- **L0** — Rust core, hot cache, allow path, no event (pure verification).
- **L1** — Rust core, hot cache, deny path (fast-reject).
- **L2** — TS SDK via N-API, no event (FFI overhead).
- **L3a** — TS SDK + Mode A (memory-buffered async append).
- **L3b1** — TS SDK + Mode B1 (blocking group-commit, conservative durable).
- **L3b2** — TS SDK + Mode B2 (queued group-commit, fast-return durable).
- **L4** — Current gateway baseline (network-bound reference).

## Running

Implementation pending Stream A. Once available:

```
cargo bench -p aps-bench-prototype-1 -- --config configs/<env>.toml
```

Results write to `results/<env>/<benchmark>.json` and a summary table is
appended to this README under "Latest published numbers".
