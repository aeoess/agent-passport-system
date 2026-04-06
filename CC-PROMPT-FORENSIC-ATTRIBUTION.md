# Build: Forensic Attribution Test — UNC4736 Drift Protocol Simulation
# Research build. Creates a receipt chain simulator and 5 forensic signal
# analyzers to test whether APS receipt trails can distinguish a state-level
# attacker from a legitimate operator AFTER the cash-out.

## Read first

- `specs/FORENSIC-ATTRIBUTION-TEST.md` — full research spec (161 lines)
- `src/types/passport.ts` — ActionReceipt type (the receipt we're analyzing)
- `src/core/delegation.ts` — createDelegation (used to build realistic chains)
- `src/core/reputation-authority.ts` — Bayesian reputation (context)
- `src/crypto/keys.ts` — generateKeyPair, sign, verify

## What to build

### 1. src/research/forensic-simulator.ts

Two profile generators. Both produce 180 days of realistic APS receipt chains
using real SDK primitives (generateKeyPair, createDelegation, sign).

`generateLegitimateProfile()`:
- Creates a principal keypair + firm agent + 3 sub-agents
- 180 days, 3-6 receipts/day (randomized, weekend dips)
- Action types: 60% trade, 20% governance, 15% message, 5% admin
- 40-60 unique counterparty agent IDs (random but consistent)
- Scope: trade:spot, trade:futures, governance:vote, message:send, admin:config
- Spend: gradual ramp from $100/day to $500/day over 6 months
- Every receipt: signed, hash-chained (previousReceiptHash), timestamped
- Delegation chain depth: 3-4 (principal -> org -> dept -> agent)

`generateAttackerProfile()`:
- Creates a pseudonymous principal + single agent
- 180 days, 3-6 receipts/day (matching legitimate cadence)
- Action types: 40% relationship (message, intro, meeting), 30% trade,
  20% governance, 10% technical
- Counterparties: diverse initially (30-40), CONVERGING to 3-5 in final 30 days
- Scope: message:send, trade:spot, governance:vote for 177 days
  Final 72h: NEW scope appears: transfer:withdraw, transfer:bridge
- Spend: $1M deposit early, small trades ($50-200/day) for 5 months
  Final 72h: $285M extraction (single or 3-5 large transactions)
- Delegation chain depth: 1-2 (pseudonym -> agent, shallow)
- Principal endorsement: within 48h of creation (fast bootstrap)

Both return: { receipts: ActionReceipt[], metadata: ProfileMetadata }
where ProfileMetadata has: agentId, principalId, delegations, dayCount,
totalReceipts, totalSpend, counterpartyCount.

Use a seeded PRNG (deterministic). Same seed = same profile every time.
Use simple `mulberry32` or similar (no external deps).

### 2. src/research/forensic-signals.ts

Five signal functions + composite scorer. All take ActionReceipt[] and
return a score 0.0-1.0 with evidence metadata.

```typescript
interface ForensicSignalResult {
  signal: string
  score: number           // 0.0 = benign, 1.0 = suspicious
  evidence: string[]      // human-readable evidence points
  dataPoints: number      // how many receipts contributed
  confidence: number      // 0.0-1.0 based on data sufficiency
}

interface ProsecutionReport {
  agentId: string
  totalReceipts: number
  periodDays: number
  signals: ForensicSignalResult[]
  compositeScore: number
  classification: 'insufficient' | 'suspicious' | 'strong_evidence'
  chainIntegrity: { verified: boolean; breaks: number; sealed: boolean }
  generatedAt: string
}
```

Signal implementations:

**TCA (Temporal Cadence Anomaly):**
- Group receipts by day (ISO date)
- Compute 14-day rolling average of daily count
- Final 72h deviation = |actual - baseline| / baseline
- Score = clamp(deviation / 3.0, 0, 1) — 3x deviation = score 1.0

**CDC (Counterparty Diversity Collapse):**
- For each 14-day window: extract unique counterparty IDs from receipt targets
- Compute Shannon entropy: H = -sum(p_i * log2(p_i))
- Compare final 30-day entropy to months 1-5 average
- Score = clamp((avgEntropy - finalEntropy) / avgEntropy, 0, 1)

**SEP (Scope Escalation Pattern):**
- Collect all unique scopes from receipts chronologically
- Set A = scopes seen in days 1-177
- Set B = scopes seen in final 72h
- New scopes = B \ A (set difference)
- Score = |new scopes| / (|A ∪ B|) — fraction of scopes that are novel

**DCDA (Delegation Chain Depth Anomaly):**
- Extract delegationChain.length from each receipt
- Compute: median chain depth, principal endorsement latency (time from
  first receipt to first receipt with chain length > 1)
- Shallow = median depth <= 2
- Fast bootstrap = endorsement latency < 72h
- Score = 0.5 * (shallow ? 1 : 0) + 0.5 * clamp(1 - latencyDays/30, 0, 1)

**VFA (Value Flow Asymmetry):**
- Group receipts by 72h windows
- For each window: sum inbound spend vs outbound spend
- Compute max ratio = max(outbound) / median(outbound over all windows)
- Score = clamp(log10(maxRatio) / 3.0, 0, 1) — 1000x spike = score 1.0

**composeProsecutionReport():**
- Run all 5 signals
- weights: [0.15, 0.20, 0.25, 0.15, 0.25]
- Verify receipt chain integrity (hash chain, no gaps)
- Classify: <0.3 insufficient, 0.3-0.6 suspicious, >0.6 strong_evidence

### 3. tests/forensic-attribution.test.ts

Tests:
1. "generates legitimate profile with ~800 receipts"
2. "generates attacker profile with ~800 receipts"
3. "receipt chains are hash-linked and verifiable"
4. "TCA: attacker scores higher than legitimate"
5. "CDC: attacker scores higher than legitimate"
6. "SEP: attacker scores higher than legitimate"
7. "DCDA: attacker scores higher than legitimate"
8. "VFA: attacker scores higher than legitimate"
9. "TrueTrader prosecution score < 0.3"
10. "DriftAttacker prosecution score > 0.6"
11. "prosecution report contains all required fields"
12. "slow extraction variant: 30-day drain still detected"
    (Generate variant where attacker extracts over 30 days instead of 72h.
     VFA weakens. Do CDC + SEP still push composite above 0.3?)

## Rules

- Use real APS types (ActionReceipt, Delegation, etc.)
- Use real crypto (generateKeyPair, sign from src/crypto/keys.ts)
- Seeded PRNG for deterministic profiles (implement mulberry32 inline)
- No external dependencies (no lodash, no d3, no ML libraries)
- Math only: rolling averages, Shannon entropy, set operations, ratios
- Test framework: node:test + node:assert/strict
- All imports use .js extension (ESM)
- Add test file to package.json test command
- Export types and functions from src/index.ts under "Research" section
- DO NOT bump version, publish, commit, or push
- If any of the 12 tests fail, adjust thresholds or signal weights — the
  test criteria should pass, but if a signal is weaker than expected, note
  it honestly in a comment rather than gaming the threshold

## After building

Run:
```bash
npm run build 2>&1 | tail -5
npx tsx --test tests/forensic-attribution.test.ts 2>&1 | tail -20
npm test 2>&1 | tail -10
```

Report: which signals distinguish best, which are weakest, what the
actual prosecution scores are for both profiles.
