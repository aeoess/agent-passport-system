# AEOESS Autoresearch

Autonomous adversarial hardening for the Agent Passport System.
Inspired by [Karpathy's autoresearch](https://github.com/karpathy/autoresearch).

## How It Works

```
program.md  →  Claude Code  →  write test  →  npm test  →  keep/discard  →  loop
  (human)       (agent)        (attack)       (metric)     (git commit)    (repeat)
```

The human writes strategy (`program.md`). The agent runs experiments (adversarial tests).
Each iteration adds one adversarial attack scenario targeting the protocol's 8 invariants.
Tests that pass prove robustness. Tests that fail find real bugs. Both are valuable.

## Quick Start

```bash
# Full version with metrics tracking
cd ~/agent-passport-system
mkdir -p autoresearch/logs
cp /path/to/program.md autoresearch/
chmod +x autoresearch/autoresearch.sh
./autoresearch/autoresearch.sh --max-iterations 50

# Minimal Ralph Wiggum version
chmod +x autoresearch/ralph.sh
./autoresearch/ralph.sh
```

## Files

| File | Role | Who edits |
|------|------|-----------|
| `program.md` | Research strategy — attack categories, rules, metrics | Human |
| `autoresearch.sh` | Full loop with metrics, logging, git branches | Fixed |
| `ralph.sh` | Minimal bash loop (Ralph Wiggum style) | Fixed |
| `results.jsonl` | Machine-readable iteration results | Agent (append-only) |
| `logs/` | Per-iteration agent output logs | Agent |

## Arenas

### Arena 1: Adversarial Hardening (current)
- **Metric:** Adversarial test count that exercises real attack surfaces
- **Target:** Push from 23 to 100+ adversarial scenarios
- **File:** `tests/autoresearch-adversarial.test.ts`

### Arena 2: Property-Based Fuzzing (planned)
- **Metric:** Invariant violations found across randomized inputs
- **Target:** 1000+ randomized delegation chains tested
- **File:** `tests/autoresearch-property.test.ts`

### Arena 3: Cross-Language Parity (planned)
- **Metric:** TS↔Python test parity count
- **Target:** Every TS test has a Python counterpart producing identical results
- **File:** `tests/autoresearch-parity.test.ts`

## Reviewing Results

```bash
# See all kept improvements
git log --oneline autoresearch-*

# See metrics
cat autoresearch/results.jsonl | python3 -c "
import sys, json
results = [json.loads(l) for l in sys.stdin]
kept = sum(1 for r in results if r['result'] == 'KEPT')
bugs = sum(1 for r in results if r['result'] == 'BUG_FOUND')
disc = sum(1 for r in results if r['result'] == 'DISCARDED')
print(f'Iterations: {len(results)}')
print(f'Kept: {kept} | Discarded: {disc} | Bugs: {bugs}')
print(f'Final test count: {results[-1][\"tests\"] if results else \"N/A\"}')
"

# Merge when satisfied
git checkout main
git merge autoresearch-adversarial-YYYYMMDD-HHMMSS
```

## The Karpathy Parallel

| Karpathy's autoresearch | AEOESS autoresearch |
|------------------------|---------------------|
| `program.md` (research strategy) | `program.md` (attack strategy) |
| `train.py` (agent edits freely) | `autoresearch-adversarial.test.ts` (agent edits freely) |
| 5-min training budget | `npm test` pass/fail |
| val_bpb (lower = better) | Test count + zero failures |
| Git commits on feature branch | Git commits on feature branch |
| ~100 experiments overnight | ~100 adversarial scenarios overnight |

## Design Principles

1. **Fixed arena, variable experiments.** The test infrastructure never changes. Only the attack scenarios change.
2. **Single metric.** Tests pass = keep. Tests fail on new test = potential bug (keep + flag). Existing tests break = discard.
3. **Git is the memory.** Every kept iteration is a commit. The branch history IS the research log.
4. **Human reviews before merge.** Autonomous up to the PR. Human decides what ships to main.
