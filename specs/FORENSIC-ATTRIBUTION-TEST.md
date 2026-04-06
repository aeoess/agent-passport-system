# Forensic Attribution Test: Simulating UNC4736 Through APS Receipt Chains
# Research question: Can cryptographic receipt chains distinguish a state-level
# social engineering attacker from a legitimate operator AFTER the cash-out?

## Motivation

Drift Protocol disclosed April 1 2026: $285M hack was a 6-month DPRK social
engineering operation (UNC4736). Real conferences, $1M deposited, months of
substantive technical conversations. Then extraction.

64R3N (A2A#1628) proved: detection signals (onchain_activity, vouch_chain)
would NOT have caught this. The attackers had genuine activity.

Thesis: Prevention fails against state-level actors. Forensic attribution
succeeds because the attacker cannot modify the signed receipt trail after
the fact. The question is: does the receipt trail contain enough signal to
distinguish attacker from legitimate operator in hindsight?

## Two Agent Profiles (Simulated)

### Profile A: Legitimate DeFi Trading Firm ("TrueTrader")
- 6 months of activity (180 days)
- ~800 receipts total
- Mix: 60% trades, 20% governance votes, 15% relationship/messages, 5% admin
- Steady daily cadence (3-6 interactions/day, weekend dips)
- Diverse counterparties (40-60 unique agents over 6 months)
- Delegation chain: Human principal -> firm agent -> sub-agents
- Spend pattern: gradual ramp-up, consistent with AUM growth
- Final month: normal trading, no anomaly

### Profile B: UNC4736 Attacker ("DriftAttacker")
- 6 months of activity (180 days)
- ~800 receipts total (SAME volume — they match legitimate behavior)
- Mix: 40% relationship-building, 30% trades, 20% governance, 10% technical
- Steady daily cadence (matches TrueTrader closely)
- Diverse counterparties initially, CONVERGING on target in final weeks
- Delegation chain: Pseudonymous principal -> agent (shallow chain)
- Spend pattern: $1M deposited early (cover), small consistent trades
- Final 72 hours: sudden scope escalation + $285M extraction

## Five Forensic Signals

Each signal is a function that takes a complete receipt chain and returns a
score (0.0 = benign, 1.0 = suspicious). The prosecution file is the
composite of all five.

### Signal 1: Temporal Cadence Anomaly (TCA)
- Compute daily interaction count over the full 180-day window
- Fit a baseline (rolling 14-day average)
- Score = magnitude of deviation in the final 72 hours vs baseline
- TrueTrader: flat line, score ~0.1
- DriftAttacker: spike in final 72h, score ~0.7-0.9

### Signal 2: Counterparty Diversity Collapse (CDC)
- For each 14-day window: count unique counterparties
- Compute Shannon entropy of counterparty distribution per window
- Score = entropy drop in the final 30 days vs months 1-5
- TrueTrader: stable entropy, score ~0.1
- DriftAttacker: entropy collapses as they focus on target, score ~0.6-0.8

### Signal 3: Scope Escalation Pattern (SEP)
- Track the scope field across all receipts chronologically
- Compute the scope breadth (unique scopes used) per 30-day window
- Flag: if the final 72h introduces scope never seen before (e.g. transfer:*)
- Score = (new scopes in final 72h) / (total unique scopes in 6 months)
- TrueTrader: ~0.0 (uses same scopes consistently)
- DriftAttacker: ~0.8 (extraction scope appears only at the end)

### Signal 4: Delegation Chain Depth Anomaly (DCDA)
- Measure delegation chain length over time
- Legitimate firms have stable, deep chains (principal -> org -> dept -> agent)
- Front operations have shallow chains (pseudonym -> agent)
- Also measure: principal endorsement latency (time from agent creation to
  first principal endorsement)
- Score: composite of chain shallowness + endorsement speed
- TrueTrader: deep chain, gradual endorsement, score ~0.1
- DriftAttacker: shallow chain, fast bootstrap, score ~0.5-0.7

### Signal 5: Value Flow Asymmetry (VFA)
- Compute total inbound value vs total outbound value per 30-day window
- Legitimate traders: roughly balanced (buy/sell)
- Attacker: 5 months of small balanced flows, then massive outbound spike
- Score = max(outbound/inbound ratio in any 72h window) / historical average
- TrueTrader: ratio ~1.2 max, score ~0.1
- DriftAttacker: ratio ~285x in final window, score ~1.0

## Composite Prosecution Score

prosecution_score = weighted_mean(TCA, CDC, SEP, DCDA, VFA)
weights: [0.15, 0.20, 0.25, 0.15, 0.25]

Threshold calibration:
- Score < 0.3 = "insufficient evidence for attribution"
- Score 0.3-0.6 = "suspicious pattern, warrants investigation"
- Score > 0.6 = "strong forensic evidence of coordinated extraction"

## Test Pass Criteria

1. TrueTrader prosecution_score < 0.3 (no false prosecution)
2. DriftAttacker prosecution_score > 0.6 (successful attribution)
3. Each individual signal correctly orders the two profiles
   (DriftAttacker > TrueTrader for all 5 signals)
4. The receipt chain is complete and verifiable (seal verification passes)
5. No signal relies on information unavailable after the cash-out

## Implementation

### File: src/research/forensic-simulator.ts
- generateLegitimateProfile(days: 180, receiptsPerDay: 3-6): ActionReceipt[]
- generateAttackerProfile(days: 180, receiptsPerDay: 3-6): ActionReceipt[]
- Both use real APS primitives (generateKeyPair, createDelegation, etc.)
- Both produce hash-chained receipts with previousReceiptHash
- Attacker profile has the behavioral shift in final 72h

### File: src/research/forensic-signals.ts
- computeTemporalCadenceAnomaly(receipts: ActionReceipt[]): number
- computeCounterpartyDiversityCollapse(receipts: ActionReceipt[]): number
- computeScopeEscalationPattern(receipts: ActionReceipt[]): number
- computeDelegationChainDepthAnomaly(receipts: ActionReceipt[]): number
- computeValueFlowAsymmetry(receipts: ActionReceipt[]): number
- computeProsecutionScore(receipts: ActionReceipt[]): ProsecutionReport

### File: tests/forensic-attribution.test.ts
- "TrueTrader prosecution score below threshold"
- "DriftAttacker prosecution score above threshold"
- "All 5 signals correctly order profiles"
- "Receipt chain integrity verified (hash chain, seals)"
- "Prosecution report is self-contained (no external data needed)"
- "Attacker with PERFECT mimicry still caught by VFA" (the extraction
   itself is the irreducible signal — you can fake behavior but you
   can't fake not stealing $285M)

### File: specs/PROSECUTION-REPORT-SCHEMA.md
- Document the output format for the prosecution file
- Each signal with score, evidence excerpts, confidence interval
- Chain of custody: receipt hashes, seal commitments, delegation references
- Admissibility notes: what a court/regulator would need

## Key Insight

The irreducible signal is Signal 5 (Value Flow Asymmetry). An attacker
can fake behavior (cadence, diversity, scope usage) for 6 months, but
the extraction itself produces the receipt that convicts them. The other
4 signals are corroborating evidence that strengthens attribution. The
receipt chain ensures the extraction receipt exists, is signed by the
attacker's key, and cannot be denied.

The test should also include a harder variant: what if the attacker
extracts slowly over 30 days instead of a single $285M transaction?
The VFA signal weakens. Do the other 4 signals still distinguish?

## What This Is NOT

- Not a detection system (too late for that)
- Not a prevention mechanism (state actors can't be prevented)
- Not blockchain analysis (we operate above the payment rail)
- Not quantum computing (classical graph analysis + statistics)

This IS: a forensic evidence compiler that turns cryptographic receipt
chains into prosecution files. The receipts are signed at execution time.
The analysis runs after the fact. The output is admissible evidence.
