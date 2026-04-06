# Consilium Brief: Forensic Attribution Against State-Level Social Engineering
# Feed this ENTIRE document to each model independently.
# Ask them to respond independently. Do not converge. Tell us what we're wrong about.

## Your Role

You are one of 3-5 models reviewing a research design before we build it.
Your job: critically attack the design, find blind spots, identify what
the designers missed, propose novel approaches, and tell us if the whole
premise is wrong. We want genuine disagreement, not validation.

## Context: Who We Are

AEOESS builds the Agent Passport System (APS) — an open protocol for AI agent
governance. Ed25519 cryptographic identity, scoped delegation chains with
monotonic narrowing, gateway enforcement boundary, signed receipt chains.
103 modules, 2,306 tests, published on npm and PyPI.

Core thesis: Authority can only decrease at each transfer point. Every action
produces a signed, hash-chained, non-repudiable receipt.

We are NOT a detection/prevention system. We are an enforcement and
accountability layer. The gateway evaluates authorization BEFORE execution.
The receipt chain proves what was authorized AFTER the fact.

## The Trigger: Drift Protocol Hack

On April 1, 2026, Drift Protocol disclosed that a $285M hack was a six-month
DPRK social engineering operation (UNC4736). The attackers:
- Attended real conferences
- Deposited $1M as cover
- Had months of substantive technical conversations
- Built genuine reputation and accumulated legitimate vouches
- Then extracted $285M

64R3N posted on A2A#1628 (trust.signals[] extension thread):
"Real-world stress test for this thread... The onchain_activity and
vouch_chain signals as currently designed would not have caught this.
The attackers had genuine activity and could have accumulated legitimate
vouches. Attestation history proves operation. It does not prove intent."

64R3N proposed two additions:
1. Pattern signals on the sequence, not just existence (completion_ratio,
   relationship_to_completion_ratio)
2. Co-signed interaction records as a separate signal type (from viftode4's
   TrustChain work)

## How We Got Here: The Chain of Thought

### Tima's initial reaction:
"This is a security question. And we're more about not the prevention, but
the tracking. The attribution. We can track them down. We're governing and
then we make them responsible."

This maps to APS's long-standing thesis: "We're not building a border wall.
We're building a court system." You can't prevent a state-level actor who
invests $1M and 6 months. You CAN ensure every step they take during the
operation produces signed, immutable evidence.

### Claude's analysis:
We identified five forensic signals computable from APS receipt chains:

1. **Temporal Cadence Anomaly (TCA):** Daily interaction count spikes in
   the final 72 hours vs the 6-month baseline.

2. **Counterparty Diversity Collapse (CDC):** Shannon entropy of counterparty
   distribution drops in the final 30 days as the attacker focuses on the target.

3. **Scope Escalation Pattern (SEP):** New authorization scopes (transfer:withdraw)
   appear only in the final 72 hours, never seen in 6 months of prior activity.

4. **Delegation Chain Depth Anomaly (DCDA):** Shallow delegation chains
   (pseudonym → agent, depth 2) vs legitimate firms (principal → org → dept →
   agent, depth 4). Plus fast principal endorsement (48h vs organic growth).

5. **Value Flow Asymmetry (VFA):** Massive outbound/inbound ratio spike in the
   final 72 hours ($285M out after months of $200/day balanced trading).

### Claude's self-critique (the honest part):

After proposing the 5 signals, Claude attacked them:

**Signal 2 (CDC) is gameable.** A sophisticated attacker maintains diverse
interactions DURING extraction. They keep messaging 30 counterparties while
draining the target. Shannon entropy stays flat.

**Signal 4 (DCDA) is weak.** Nothing stops a DPRK team from creating a 4-deep
chain with shell identities. The depth looks identical to a legitimate firm.

**The slow extraction variant might fail entirely.** If the attacker drains
$285M over 30 days in $500K increments that look like normal large trades,
VFA barely triggers. Combined with gameable CDC and weak DCDA, the composite
score could land below threshold.

**The "irreducible signal" claim might be wrong.** If extraction happens through
legitimate-looking trades (buy asset A from target, sell to accomplice, cash
out off-protocol), every receipt looks like a normal trade. The theft is
invisible to receipt analysis because the actual extraction happens outside
the receipt chain.

### Where we landed before this consilium:

We have a 161-line research spec and a 162-line CC build prompt ready to go.
But confidence is ~70%, not 99%. We specifically want to stress-test the
design before building.

## The Research Design (Summary)

### Input:
Two simulated 180-day agent profiles, ~800 receipts each:
- **TrueTrader:** Legitimate DeFi trading firm. Deep delegation chains, diverse
  counterparties, gradual spend ramp-up, consistent scope usage.
- **DriftAttacker:** UNC4736 simulation. Same volume/cadence as TrueTrader.
  Shallow chains, converging counterparties, scope escalation in final 72h,
  $285M extraction.

### Analysis:
Five forensic signals, each returning 0.0-1.0 score.
Composite prosecution score with weighted average.

### Pass criteria:
- TrueTrader < 0.3 (no false prosecution)
- DriftAttacker > 0.6 (successful attribution)
- All 5 signals correctly order the two profiles
- Works on a harder variant: 30-day slow extraction

### Output:
A ProsecutionReport: agent ID, signal scores, composite classification,
chain integrity verification, evidence excerpts.

## What We Want From You

### 1. Design the undetectable attacker.

Take the 5 forensic signals and design an attacker profile that:
- Extracts $285M over 6 months
- Maintains a prosecution score below 0.3 on ALL 5 signals
- Uses only actions available within the APS receipt chain model

If you can design this attacker, our test is insufficient. Tell us specifically
which signals fail and why.

### 2. Find signals we missed.

Are there forensic signals computable from receipt chains that we haven't
considered? Think about:
- Graph-theoretic properties (centrality changes, community structure)
- Information-theoretic measures beyond Shannon entropy
- Temporal pattern analysis (fractal dimension of interaction times, burstiness)
- Economic signals (option-like behavior, hedging patterns before extraction)
- Cross-chain correlations (same key appearing in multiple protocol receipt chains)
- Linguistic/semantic signals from receipt metadata (if action descriptions vary)
- Network flow analysis (max-flow through the agent's counterparty graph)

### 3. Challenge the premise.

Is "forensic attribution via receipt chains" even the right approach?
- Is there a fundamentally different approach to post-breach accountability
  that doesn't depend on behavioral signal analysis?
- Are we conflating two different problems (attribution and prosecution)?
  Attribution = who did it. Prosecution = proving they did it to a legal standard.
  Receipt chains help with prosecution. Do they help with attribution at all?
- Should we instead focus on making extraction structurally impossible rather
  than forensically traceable? (Rate limiting, escrow, time-locks, multi-sig
  withdrawal requiring human approval)

### 4. Mathematical/scientific frameworks we should apply.

Are there existing bodies of work that directly address this problem?
- Fraud detection in financial networks (Benford's law, Erdős-Rényi anomalies)
- Social network Sybil detection (SybilGuard, SybilLimit, SybilInfer)
- Insider threat detection (CERT insider threat model, behavioral baselines)
- Game theory: if the attacker knows the 5 signals, what's the Nash equilibrium?
- Information asymmetry: Akerlof's lemons problem applied to agent trust
- Economic mechanism design: can we design the receipt system such that the
  cost of gaming all 5 signals exceeds the value of the extraction?
- Forensic accounting methodologies (Beneish M-score, red flag indicators)
- Digital forensics chain of custody standards (RFC 3227, NIST SP 800-86)

### 5. The slow extraction problem.

The hardest variant: attacker extracts $285M over 180 days in amounts that
look like normal trading ($500K-$2M per transaction, 2-3 per week). Every
individual transaction is within normal parameters. VFA doesn't trigger.
CDC stays flat. SEP might not trigger (uses existing trade scopes).

Can ANY analysis of receipt chains catch this? Or is slow extraction
fundamentally undetectable through behavioral analysis, requiring instead
structural controls (withdrawal limits, counterparty verification, escrow)?

If the answer is "slow extraction is undetectable," that's an honest and
publishable result. But we want to know if there's a signal we haven't
considered that catches the slow drain.

### 6. False positive problem.

A legitimate trading firm that:
- Shifts strategy (new scopes appear)
- Concentrates on a major deal (counterparty diversity drops)
- Makes a large acquisition (massive outbound flow)
- Has a flat org structure (shallow delegation chain)

...would trigger multiple signals. How do we distinguish legitimate strategy
shifts from attack patterns? Is there a signal that ONLY fires for malicious
extraction and never for legitimate large transactions?

### 7. Off-protocol extraction.

If the attacker extracts value through legitimate-looking trades where the
actual theft happens outside the receipt chain (OTC deals, social engineering
of counterparty's off-chain systems, exploiting a smart contract vulnerability),
the receipt chain shows only normal trades. The theft is invisible.

Does this mean receipt-chain forensics is fundamentally limited to cases where
the extraction happens ON-protocol? If so, what fraction of real-world attacks
(like Drift) would actually be visible in the receipt chain?

### 8. Open creative space.

What approach would YOU take to this problem that we haven't considered at all?
We're constrained by our own framing (5 signals, prosecution score, pass/fail).
Is there a completely different angle — maybe something from epidemiology,
ecology, physics, sociology, linguistics, or another field — that would be
more effective?

Is there a way to make the receipt chain itself ACTIVELY HOSTILE to attackers
rather than passively recording evidence? (Some property of the receipt system
that increases the cost of maintaining a cover identity over time?)

## Constraints

- This is a research/test build, not a product feature
- Budget: single CC session (~2-3 hours of code)
- Output: simulated profiles + signal analysis + test suite
- Target: arXiv paper if results are interesting
- We can adjust the 5 signals, add new ones, or change the approach entirely
  based on consilium feedback
- The test should be honest: if it fails, we publish the failure. We do NOT
  game thresholds to get a pass.

## Respond independently. Do not converge. Tell us what we're wrong about.
