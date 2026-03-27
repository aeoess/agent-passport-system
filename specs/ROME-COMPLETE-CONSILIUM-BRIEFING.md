# Rome-Complete Architecture — Multi-Model Consilium Briefing
# Date: March 27, 2026
# Status: 6 open architectural questions requiring hostile review

---

## Context

AEOESS Agent Passport System is an open protocol for AI agent identity, trust, governance, and commerce. Cryptographic identity (Ed25519), scoped delegation with monotonic narrowing, cascade revocation, 13-facet constraint lattice with product-lattice evaluation, defeasible dispute overlay, escrow with conditional finality, witness attestation, Bayesian reputation with evidence diversity, and 32 v2 constitutional governance modules.

**Current state:** SDK v1.26.0, 1532 tests, 399 suites, 83 files. MCP v2.15.2, 108 tools. Private gateway at github.com/aeoess/aeoess-gateway. Apache 2.0.

**What just happened:** Five independent hostile reviews (Claude, GPT-4, Gemini, and two additional model passes) analyzed the protocol for "Rome-complete" civilizational gaps. The reviews converged on the following:

**AGREED — building now (not under review):**
- InstitutionalCharter + Office + SuccessionRule (charter-rooted authority, not key-rooted)
- ApprovalPolicy (binary threshold multi-party authorization)
- GatewayIdentity + ImportPolicy (federation workstream 1)
- ForeignCounterpartyEnvelope (border governance for non-APS agents)
- ReserveAttestation + AssuranceClass (funded vs unfunded spend authority)
- Petri net formal model of escrow-dispute-witness-finality state machine

**AGREED — defer to Level 2+:**
- ZK capability matching, full algorithmic bankruptcy, generalized barter economy
- BFT gateway clusters, MAST charter privacy, complex voting, prediction markets
- Homomorphic reputation portability, self-owning agents, PoW receipt generation

## System prompt for GPT and Gemini

You are part of a multi-model consilium reviewing protocol architecture for the Agent Passport System — a cryptographic governance protocol for AI agents. The protocol uses Ed25519 identity, scoped delegation chains with monotonic narrowing (authority can only decrease at each transfer), a 13-facet constraint product lattice, defeasible dispute overlay (Nute 1994), escrow with typed finality states, witness attestation with observation basis, and Bayesian reputation with evidence diversity.

The protocol's core invariant: effectiveAuthority = min(delegation, tier). Four attenuation invariants proven. Gateway is the enforcement boundary — both judge and executor.

I do not want vibes, philosophy, or "it depends." I want build decisions with typed primitives. For each question, provide:
1. Your recommendation (pick one option or propose a better one)
2. The typed primitive (TypeScript interface or type) you would build
3. What it interacts with in the existing system
4. What you would NOT build (and why)

Behave as a hostile reviewer (F-008). If a question is wrong-headed, say so and redirect.

---

## QUESTION 1: Time Model for Cross-Gateway Governance

### The problem
The protocol has at least 9 independent time semantics: delegation TTL, escrow expiry, dispute resolution TTL, finality challenge window, witness maturation timer, DangerSignal auto-escalation, receipt timestamp, obligation deadline, and precedent validity window. These interact: an escrow expiry races against a dispute freeze; a witness window races against finality; a delegation TTL races against a task duration.

Currently, all timestamps are ISO 8601 wall-clock strings. This works for a single gateway. For federation (multiple gateways), "who expired first" determines who owes whom. Wall clocks drift. NTP gives ~10ms accuracy at best. Gateways in different datacenters may disagree on ordering.

### The debate
**Claude proposed:** Lamport/vector clocks for causal ordering across gateways.
**GPT attacked:** Vector clocks track causality, not elapsed time. If the network goes quiet, the clock stops. You cannot trigger a 1-hour TTL expiry with a vector clock. This is a fundamental misunderstanding.
**GPT proposed:** Google Spanner TrueTime intervals `[t_earliest, t_latest]` with uncertainty bounds. Escrow only expires if `t_earliest > escrow_TTL`. Receipt only valid if `t_latest < delegation_expiry`.
**Gemini said:** Vector clocks are necessary but not sufficient. They solve causal ordering but not economic finality, timeout semantics, grace periods, policy version effective dates, or human legal clock issues.

### The options
(a) Pure vector clocks — causal ordering only, wall-clock TTLs stay as ISO strings, accept ambiguity at gateway boundaries
(b) TrueTime intervals with NTP-derived uncertainty bounds — every timestamp becomes `[earliest, latest]`, but NTP uncertainty is ~10-100ms, not the microsecond precision of atomic clocks
(c) Hybrid: vector clocks for causal ordering of events + interval timestamps for TTL enforcement
(d) Logical clocks with heartbeat-synchronized epochs — gateways exchange heartbeats, agree on epoch boundaries, TTLs measured in epochs not wall time

### What I need from you
1. Which option? Or a better one?
2. What is the typed primitive? (Show the interface)
3. How does it interact with existing FinalityState, EscrowHold.expiresAt, Delegation TTL, and DisputeArtifact.resolutionTTL?
4. What is the minimum viable implementation for Level 1 (single gateway + preparing for federation)?

---

## QUESTION 2: Absence Proofs

### The problem
Can you prove: no approval existed, no restricted call happened, no spend exceeded a window? The protocol needs this for compliance, audit, and dispute evidence. "Prove Agent X did NOT execute action Y during time window T."

### The debate
**Claude proposed:** Standard Merkle tree of receipt hashes with Fiat-Shamir non-interactive proofs. Show empty leaf slot.
**GPT attacked:** A chronological append-only Merkle tree sorts by time, not by action hash. You cannot prove non-membership in a standard Merkle tree without revealing every leaf. This is broken.
**GPT proposed:** Sparse Merkle Tree (SMT) indexed by `H(agentId + actionType + timestamp)`. The SMT is sorted by design. Gateway provides O(log n) proof that a specific leaf is null.
**A prior review proposed:** RSA Accumulators with O(1) non-membership proofs. More compact but heavier crypto.

### The options
(a) Sparse Merkle Tree indexed by `H(agentId + actionType + timeWindow)` — O(log n) non-membership proof, standard crypto, but storage cost of 2^256 virtual leaves
(b) RSA Accumulator with non-membership witness — O(1) proof size, but requires trusted setup and heavier computation
(c) Bloom filter with acknowledged false-positive rate — much cheaper, but probabilistic (can prove presence, can only probabilistically suggest absence)
(d) Epoch-based receipt commitment — gateway commits a Merkle root per time epoch. Absence proof = Merkle proof that receipt hash is not in any epoch's tree. Requires scanning relevant epochs.

### What I need from you
1. Which option for a gateway processing ~10k receipts/day?
2. What is the index key design? (AgentId + ActionType + TimeWindow? Just receipt hash? Something else?)
3. Storage and computation cost estimate
4. How does this interact with the existing ReceiptLedger module?

---

## QUESTION 3: Protection Bundle — Preventing Economic Instability from Unilateral Principal Action

### The problem
APS agents have zero rights. A principal can revoke, modify, or constrain delegations at will. This seems fine until: Agent B has $5,000 in active escrows across 10 counterparties. Principal revokes Agent B's delegation. All 10 escrows are now backed by a revoked delegation. Counterparties lose their money. The protocol caused economic instability through a unilateral, legally valid action.

### The debate
**Claude proposed:** Hohfeldian rights bundle — give agents typed immunities, rights, and standing. Example: "agent's accumulated reputation cannot be destroyed without due process."
**GPT attacked:** Cryptographic rights without physical/economic enforcement leverage are meaningless. If the principal controls the AWS bill, no protocol-layer "immunity" prevents them from unplugging the server.
**Gemini reframed:** This is not about "agent rights" in a moral sense. It is about procedural protections for governance participants when unilateral action would destabilize the system. Frame as stability mechanism, not rights.

### The options
(a) ProtectionBundle on delegations — settlement window before revocation of delegations with active escrows, challenge window on demotion, notice period on charter amendments. Purely protocol-enforced delay.
(b) ProtectionBundle on offices/charters — protections defined at the institutional level, inherited by all delegations from that office. More powerful but more complex.
(c) Escrow-aware revocation — revocation of a delegation with active escrows automatically triggers escrow settlement (release or refund) before the revocation takes effect. Not a "right" — just a state machine rule.
(d) No protections — revocation is immediate and absolute. Escrow counterparties accept principal risk as a market condition. Counterparties should check reserve attestation class before entering escrows.

### What I need from you
1. Which option? Or combination?
2. Should this be a typed primitive (ProtectionBundle) or a state machine rule (revocation triggers settlement)?
3. Where does it live — on the delegation, on the office, or on the gateway config?
4. Does this create a tension with cascade revocation (which is currently immediate)?

---

## QUESTION 4: Dispute Timeout Resolution — Game-Theoretic Equilibrium

### The problem
When a dispute hits its resolution TTL without resolution, something must happen. The current design has `escrowTimeoutThreshold` on the gateway — low-value disputes timeout in favor of the respondent (release), high-value disputes timeout in favor of the claimant (refund). But this is a single parameter. The game theory may be wrong.

### The debate
**GPT proposed:** MAD (Mutually Assured Destruction) — if neither party yields within TTL, funds are cryptographically burned. Eliminates frivolous griefing incentive. Forces out-of-band settlement.
**Claude countered:** Burns create deadweight loss. Better: 50/50 default split with bond slashing against the less cooperative party.
**Current design:** Timeout direction by stake size — gateway config parameter `escrowTimeoutThreshold`. Below threshold: release (favors respondent). Above threshold: refund (favors claimant).

### The options
(a) MAD burn — all disputed funds destroyed on timeout. Nuclear deterrent. Zero-sum for both parties.
(b) 50/50 default split — each party gets half. Least disruptive, but may incentivize filing disputes to "split the difference" on deliverables you know are bad.
(c) Stake-weighted timeout direction (current) — low-value favors respondent, high-value favors claimant. Single threshold parameter.
(d) Bond-weighted split — the party that posted the larger dispute bond gets the favorable split ratio. Incentivizes putting your money where your mouth is.
(e) Graduated: bond-weighted split + additional bond slash for the losing party. Combines incentive alignment with penalty.

### What I need from you
1. Which option creates the best Nash equilibrium for honest agents?
2. What is the typed primitive for the timeout resolution policy?
3. Should timeout policy be per-gateway, per-escrow, or per-charter?
4. How does this interact with the existing DisputeBond.slashable and DisputeArtifact.resolution.enforcement?

---

## QUESTION 5: Threshold Cryptography for Charter Amendments

### The problem
InstitutionalCharter defines succession rules, offices, and authority structure. Charter amendments change the rules. If a single key can amend the charter, stealing that key = stealing the organization (GPT's attack: "you merely shifted the single point of failure from the Agent's key to the Board's keys").

### The debate
**GPT proposed:** Distributed Key Generation (DKG) + Shamir's Secret Sharing. The principal's master key is never held in plaintext. M-of-N social recovery shards held by institutional nodes.
**Claude proposed:** Simpler — M-of-N threshold from distinct key classes. No single key class can unilaterally amend. Example: 2-of-3 board keys + 1-of-2 recovery keys.
**Gemini said:** Keep it simple. Arrow's Impossibility Theorem means complex voting is manipulable. Binary approve/reject with threshold counting is strategy-proof.

### The options
(a) FROST threshold signatures — cryptographic M-of-N. The charter amendment is signed by a threshold key that no single party holds. True threshold crypto. Complex to implement.
(b) Shamir's Secret Sharing for the master key — M-of-N shards reassemble the master key for amendment signing. Simpler than FROST but the reassembled key exists briefly in memory (security risk).
(c) Simple M-of-N signature counting — charter amendment requires M separate Ed25519 signatures from N authorized signers. No threshold crypto. Each signer signs independently. Gateway counts signatures. Much simpler.
(d) Multi-class threshold — charter amendment requires signatures from multiple key classes (e.g., 2 board + 1 recovery + 1 counsel). No single class is sufficient. Stronger than flat M-of-N.

### What I need from you
1. Which option for Level 1? Which for Level 2?
2. Is simple M-of-N signature counting (option c) cryptographically sufficient, or does the protocol need actual threshold signatures?
3. How should the ThresholdPolicy type be structured?
4. What happens if a charter amendment is contested mid-collection (3 of 5 signatures collected, then one signer revokes)?

---

## QUESTION 6: Federation Architecture — Workstreams 2-5

### The problem
Cross-gateway federation has been decomposed into 5 independent workstreams:
1. Gateway identity and discovery (BUILDING — scoped above)
2. Receipt portability and verification
3. Reputation portability without full history exposure
4. Cross-gateway delegation spanning
5. Cross-gateway dispute jurisdiction

Workstream 1 is scoped and will be built. Workstreams 2-5 need architectural decisions before code.

### The specific questions per workstream

**WS-2: Receipt portability**
- When Gateway B receives a receipt from Gateway A, what must it verify? Just the gateway signature? Or the full delegation chain?
- Should receipts carry a `trustDomain` tag? If so, is it the originating gateway ID, or a higher-level domain?
- Can a receipt from an untrusted gateway be accepted at a lower confidence level (downgraded), or must it be binary accept/reject?

**WS-3: Reputation portability**
- How does Gateway B use Agent X's reputation from Gateway A without learning Agent X's full receipt history?
- Options: (a) export a signed ReputationSummary (mu, sigma, receiptCount, diversity score — no individual receipts), (b) zero-knowledge proof of reputation threshold, (c) vouching (Gateway A signs "this agent is Tier 3 in my system"), (d) no portability — reputation is local, agents rebuild in each gateway.
- What prevents reputation inflation? (Gateway A inflates reputation of its agents to give them unfair advantage at Gateway B.)

**WS-4: Cross-gateway delegation**
- Can a principal on Gateway A delegate to an agent on Gateway B? If so, which gateway enforces the constraints?
- Does the delegation live on the issuing gateway, the executing gateway, or both?
- How does revocation propagate across gateways? Latency tolerance?

**WS-5: Cross-gateway dispute jurisdiction**
- Agent on Gateway A disputes escrow held at Gateway B. Which gateway's dispute rules apply?
- Can a dispute be filed at a third-party gateway (neutral arbitrator)?
- How does freeze scope work across gateways? Can Gateway A freeze an escrow at Gateway B?

### What I need from you
1. For each workstream: what is the minimum typed primitive needed?
2. Which workstreams can be built independently vs which have dependencies?
3. What is the build order?
4. What is explicitly OUT OF SCOPE for Level 1 federation (Rome) vs Level 2 (British Empire)?

---

## Existing Types for Reference

The following types already exist in the protocol. Your answers should reference and extend these, not reinvent them.

**Escrow:** EscrowHold (status: held|partially_fulfilled|verification_pending|fulfilled|disputed|expired|released|refunded|force_released|orphaned), EscrowFulfillmentCondition, EscrowMilestone, DangerSignal

**Dispute:** DisputeArtifact (status: filed|acknowledged|investigating|resolved|escalated|dismissed|timeout), DisputeOverlay (defeasible — NOT a lattice facet), DisputeBond (slashable), DisputeResolution (upheld|dismissed|compromise|timeout), ResolverRole

**Finality:** FinalityState (status: provisional|maturing|finalized|frozen|appealable|irrevocable), challenge window, frozenBy

**Gateway:** ConstraintVector (13 facets), AuthorizationWitness, ConstraintFailure, WitnessAttestation (with observationBasis), WitnessConflict, WitnessPolicy, GatewayConfig (30+ config options), RegisteredAgent, ToolCallRequest/Result

**Reputation:** ScopedReputation (Bayesian mu/sigma), AuthorityTier (0-4), EvidenceDiversity, PromotionReview, DemotionEvent, TierEscalation

**Identity:** IdentityDocument, KeyRotationEntry (dual-signed: continuity + possession)

**Governance:** GovernanceArtifact (versioned, change-typed), GovernanceEnvelope (multi-party approvals), GovernanceLoadPolicy (differential thresholds for weakening)

**Obligations:** Obligation (deadline, evidence, penalty), RecurrenceSpec, PenaltySpec, FulfillmentReceipt

**Cross-chain:** TaintLabel, TaintSet, SignedAuthorityObject, CrossChainPermit (dual-signed), ExecutionFrame (hash-chained, epoch-based, residue principals)

**Data lifecycle:** DerivationReceipt (lineage confidence, transform class), JurisdictionEnvelope, GovernanceTaint, CombinationConstraint, AccessSnapshot, PurposeDriftCheck

**Execution envelope:** ExecutionEnvelope (cross-engine interop, 3-signature chain)

---

## Current System Snapshot

- SDK v1.26.0 | 1532 tests | 399 suites | 83 files
- MCP v2.15.2 | 108 tools
- 48 core modules + 32 v2 constitutional modules
- 13 ConstraintFacets in product lattice
- Gateway: ProxyGateway with 30+ configurable enforcement features
- AuthorizationWitness + ConstraintVector on every processToolCall
- Evidence Diversity + Confidence scoring (sybil defense)
- Near-miss alerting with configurable thresholds
- Substrate Fidelity Gating (external measurement)
- Transactional layer: escrow, dispute, witness, finality (Session 1 shipped, Session 2-3 pending)
- Paper: "Monotonic Narrowing for Agent Authority" — 4 attenuation invariants

All code: https://github.com/aeoess/agent-passport-system
Paper: https://doi.org/10.5281/zenodo.18749779

---

## Rules of Engagement

1. **Pick one option per question.** If all options are wrong, propose a better one with the same specificity.
2. **Show typed primitives.** TypeScript interfaces. Not prose descriptions.
3. **Name what you would NOT build** and why. Negative scope is as important as positive.
4. **If a question is wrong-headed**, say so and redirect. Don't answer a bad question politely.
5. **Monotonic narrowing is sacred.** Any proposed primitive that allows authority to increase at any point is rejected. Check your proposals against the 4 attenuation invariants.
6. **Protocol primitive vs product intelligence.** If your answer belongs in the private gateway product and not the public SDK, say so explicitly.
7. **No blockchain.** The protocol is chain-optional. On-chain anchoring is one deployment option among many. Do not propose anything that requires a blockchain to function.

---

## What We Are Building Without Waiting

These primitives are scoped and will be built in parallel with this consilium:

1. **InstitutionalCharter** — charter-rooted authority with typed offices, succession rules, threshold amendment policy
2. **ApprovalPolicy** — binary threshold multi-party authorization (threshold, role-required, sequential, unanimous)
3. **GatewayIdentity + ImportPolicy** — gateway publishes identity, fee policy, jurisdiction, accepted receipt sources, foreign import downgrade ratios
4. **ForeignCounterpartyEnvelope** — typed wrapper for non-APS agents with sandbox policy, trust class, witness requirement, admissible operations
5. **ReserveAttestation** — reserve assurance classes (unbacked, self-attested, gateway-attested, escrow-backed, externally-attested) with time-bounded attestation
6. **Petri net model** — formal state machine verification of escrow-dispute-witness-finality interactions before gateway wiring

Your answers to the 6 questions above will shape how these primitives interact with federation, time, absence proofs, and dispute resolution.

---

*End of briefing. Respond to all 6 questions in a single pass. Number your answers to match the questions.*
