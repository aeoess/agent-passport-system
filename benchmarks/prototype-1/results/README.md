# Prototype 1 benchmark results

**These are prototype, developer-reference measurements. Not canonical claims.**

Each JSON file under this tree is the verbatim output of one `aps-bench <Lx>` invocation. The schema is whatever `src/main.rs` writes at the time of the run; see `git_commit` inside each file for the exact code version. Methodology metadata (sample size, timer, percentile method, whether durability work is included, sink type) is embedded in every file so a reader can judge what the numbers mean without external context.

## What is here

- `mac-apple-silicon/L0.json` — pure-verifier allow path, `aps_check` on a hot-cache happy fixture.
- `mac-apple-silicon/L1.json` — fast-reject deny path (spec §9 step 0 `ACTION_HASH_INVALID`).

## What is NOT here yet

- L2 — TS SDK over N-API (blocked on Stream B).
- L3a / L3b1 / L3b2 — durability-mode latency (blocked on Stream B).
- L4 — current gateway baseline (separate task).
- Concurrency sweep — single-threaded only at this point.
- Canonical bare-metal Linux x86_64 run (spec §13.1) — pending hardware / environment setup.

## No public claims

The chunk-7 / chunk-8 / chunk-9 implementation is committed but the numbers here have not been claims-reviewed and have not been measured on the canonical environment. The CLAIMS.md tier-matrix entry (spec §18) is the gating surface for any external latency language; until that lands, do not summarize these numbers into a top-level README or marketing-facing surface.

Internal language until the canonical Linux run + CLAIMS.md approval: *"Stream A implements the local verifier reference path. Benchmarks pending."*

## Reproducing

```
cargo build --release -p aps-bench-prototype-1
./target/release/aps-bench L0
./target/release/aps-bench L1
```

Output JSON files write to `benchmarks/prototype-1/results/mac-apple-silicon/<benchmark>.json`. Existing files are overwritten — commit them to capture a specific run.
