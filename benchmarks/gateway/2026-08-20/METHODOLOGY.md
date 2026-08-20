# Gateway policy evaluation, 2026-08-20

## What this measures

The full gateway authorization path in TypeScript: signature verification, scope check,
reputation, hybrid logical clock, and every enforcement constraint, end to end in one
process. `tests/benchmark-gateway.ts`, 500 iterations per scenario after 10 warmup calls.

This is NOT the L0 verifier hot path. That lives in `benchmarks/prototype-1/results/` and
is measured in nanoseconds across three canonical environments. Two different layers, two
different numbers, and conflating them would overstate both.

## Environment

Apple M3, 8 cores, macOS 26.5, Node v24.11.1, SDK 4.4.0 at commit
`1f79817504a394d5e6cedb546451357c188a2236`. Full record in `env_capture.json`.

DEVELOPER MACHINE, NOT CANONICAL. The three canonical environments are defined in spec
sections 13.1 (bare metal Linux), 13.2 (AWS c7i.2xlarge) and 13.3 (Apple Silicon
reference) and each has its own captured environment. This run is none of them. Every
public claim derived from this file names the machine, per the CLAIMS.md rule that a
performance claim pins to the measured cpu_model.

## Results

Three consecutive runs, same machine, same commit.

| scenario | p50 | p95 | p99 |
|---|---|---|---|
| minimal, signature and scope only | 0.13 to 0.14 ms | 0.15 to 0.17 ms | 0.19 to 0.23 ms |
| standard, plus reputation and HLC | 0.13 to 0.14 ms | 0.15 to 0.16 ms | 0.19 to 0.23 ms |
| full enforcement | 0.132 to 0.140 ms | 0.15 ms | 0.156 to 0.161 ms |
| burst, 100 sequential | 0.139 ms | 0.15 ms | 0.16 ms |
| denied path | 0.075 ms | 0.086 ms | 0.11 ms |

Burst throughput: 7,147, 7,275 and 7,167 ops per second.

## What gets published, and the rule

Published values take the CONSERVATIVE end of the observed range: the slowest p50 and the
lowest throughput across the three runs, never the best sample.

    policy evaluation p50    0.14 ms
    burst throughput         7,100 ops/sec, single process, Apple M3

Two properties worth stating because they are the interesting part. Full enforcement costs
essentially nothing over signature and scope alone, so the constraint stack is not where
the time goes. And the denied path is roughly twice as fast as the allow path, which is
the evaluation order working as designed: the cheapest checks run first, so a refusal
exits early.

## What this supersedes

`403 ops/sec`, which sat in `.well-known/mcp.json` and `llms-full.txt` for months with no
environment record and no reproduction path. The same harness on the same code path now
reports roughly eighteen times that. The old figure was not wrong so much as unowned, and
it understated the system badly.

## Reproducing

    cd ~/agent-passport-system
    NODE_ENV=development npx tsx tests/benchmark-gateway.ts

Anyone can run it. If the number moves, this directory gets a new dated sibling rather
than an edit, so the history stays readable.
