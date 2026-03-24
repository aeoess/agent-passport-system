# Data Modules Gap Analysis — Multi-Model Consilium Briefing

## Context

AEOESS Agent Passport System has 5 data modules (36A, 38-42):
- **Module 36A**: Data Source Registration & Access Receipts
- **Module 38**: Data Contribution Ledger
- **Module 39**: Data Settlement Protocol (Merkle-committed)
- **Module 40**: Data Enforcement Gate
- **Module 41**: Training Attribution & Derivation Chains
- **Data Gateway**: Composable gateway wrapping all of the above

13 gaps identified. All are real problems that will surface as the data economy scales. The question is: which ones need protocol-level primitives vs application-layer guidance, and what's the build order?

## System prompt for GPT and Gemini

You are part of a multi-model consilium reviewing a protocol architecture for AI agent data governance. The protocol already has cryptographic identity (Ed25519), scoped delegation chains, cascade revocation, a 4-gate commerce pipeline, and decision equivalence primitives. Now we're extending the data modules.

I do not want vibes, philosophy, or "it depends." I want build decisions.

---

## The 13 Gaps

### TIER 1: Production-critical

**Gap 1: Consent Revocation Cascade**
Data source revokes consent. Access receipts exist proving past access was legitimate. But downstream artifacts (RAG indices, fine-tuned models, vector stores) still contain the data. GDPR Article 17 requires erasure. Our `revokeSourceReceipt` stops future access but doesn't cascade into training artifacts.
- Q: Should the protocol define a "revocation cascade" that propagates through derivation chains? Or is this an application-layer responsibility?
- Q: Can we reuse our existing cascade revocation mechanism (delegation chains) for data consent?

**Gap 2: Multi-Hop Derivation Chain Breaks**
`resolveAttributionChain` traces: Source C → Agent A accesses → Agent A produces output → training event. But: what if Agent A's output is consumed by Agent B, which produces something consumed by Agent C, which trains Model M? The chain breaks at each agent boundary. Fractional attribution becomes meaningless without full-chain visibility.
- Q: How deep should the protocol track derivations? 1 hop? N hops? Unbounded with cycle detection?
- Q: When data exits our system and re-enters (exported to external system, comes back as new source), how do we detect the link?

**Gap 3: Terms Interpretation Ambiguity**
`checkTermsCompliance` does exact string matching: `allowedPurposes.includes(accessType)`. Real data licenses have gray zones. "Research use" — commercial research? "Non-commercial" — nonprofit consulting?
- Q: Should the protocol define a terms taxonomy (finite set of standard purposes), or stay with freeform strings + application-layer interpretation?
- Q: Is there a middle ground — hierarchical purpose taxonomy where `research:academic` and `research:commercial` are distinct but `research:*` covers both?

### TIER 2: Scale problems

**Gap 4: Data Pricing Discovery**
`DataTerms.compensation.rate` is set by the data owner with no market signal. No mechanism for price discovery. First sources will overprice or underprice.
- Q: Protocol-level price discovery (auction, posted-price market) or application-layer?
- Q: Should access frequency/quality feedback from the settlement module inform recommended pricing?

**Gap 5: Quality-Weighted Attribution**
All accesses count equally: 1 access = 1 contribution unit. But a curated medical dataset is worth more per access than scraped web data. No quality multiplier in the settlement.
- Q: Who determines quality? The data owner (self-reported)? The consuming agent (feedback)? A third-party evaluator?
- Q: Should quality scores live on the access receipt, the source registration, or both?

**Gap 6: Competitive Exclusion Terms**
Real data licenses include: "You can use this, but not if you also use Competitor X's data." Or: "Exclusive access for 90 days." `DataTerms` has no concept of mutual exclusivity, temporal exclusivity, or competitive restrictions.
- Q: Extend `DataTerms` with exclusivity fields? Or is this a terms taxonomy extension (Gap 3)?

**Gap 7: Aggregation Attack Detection**
Individual accesses are innocuous. 10,000 accesses to the same source in 24 hours = bulk extraction. The enforcement gate checks per-access compliance. No aggregate-level gate.
- Q: Rate limiting at the enforcement gate? Or a separate aggregation monitor?
- Q: Should aggregate limits be defined per-source in `DataTerms`, or per-agent in delegation scope?

### TIER 3: Nobody's building this yet

**Gap 8: Access Pattern Privacy**
The contribution ledger stores who accessed what. That pattern is competitive intelligence. `getAgentDataFootprint()` reveals an agent's (and its principal's) entire data consumption history.
- Q: Differential privacy on the ledger? Zero-knowledge proofs for settlement? Or is access control sufficient?
- Q: Who should be able to query the ledger — only the source owner, only the agent's principal, or anyone?

**Gap 9: Decision-to-Data Lineage**
When an agent makes a decision that affects a human, the human should ask: "what data influenced this?" We have decision artifacts (Module 37) and data access receipts (36A). No bridge between them. No function takes a decision and traces back through the full data lineage.
- Q: Is this a new module or an extension of the derivation chain (Gap 2)?
- Q: How do we handle the case where the model's training data influenced the decision but the model was trained externally?

**Gap 10: Synthetic Data Laundering**
Agent accesses proprietary data. Generates "statistically equivalent" synthetic data. Registers synthetic data as new source with permissive terms. Original source gets zero compensation. Terms technically not violated.
- Q: Can we detect this? Should we? Is "synthetic data provenance" a tractable problem?
- Q: Should `createDerivation` automatically tag synthetically-derived data as having upstream obligations?

**Gap 11: Data Unions / Collective Bargaining**
100 photographers each have small datasets. Individually, no leverage. Collectively, critical mass. No concept of a "data collective" — unified terms, pooled compensation, internal distribution.
- Q: Protocol primitive (DataCollective type with shared terms and internal revenue split)?
- Q: Or application-layer construct built on top of existing DataTerms?

**Gap 12: Retroactive Terms**
Data was accessed before source registered terms. Now terms exist. Historical access is provable but not compensable under current rules.
- Q: Should `generateSettlement` support a retroactive flag that includes pre-terms access in compensation?
- Q: Legal implications: can a protocol enforce retroactive compensation, or does that create liability?

**Gap 13: Cross-Jurisdiction Term Propagation**
Source C (EU/GDPR) → Agent A (US) → Agent B (China/PIPL). Each hop locally compliant. Aggregate chain violates original intent. `DataTerms` has no concept of jurisdiction that follows the data.
- Q: Add `jurisdiction` and `propagationRules` to DataTerms?
- Q: How does this compose with the delegation chain's existing scope narrowing?

---

## Your task

For each of the 13 gaps, answer:

**A. Protocol-level or application-layer?**
Pick one. If protocol, it becomes a type + function in the SDK. If application, it becomes documentation + best practices.

**B. Build priority (1-5)**
1 = build now, 5 = defer until adoption proves the need.

**C. Minimum shippable primitive**
If protocol-level: what's the smallest type, function, or field that addresses the gap?

**D. What NOT to build**
What's the over-engineered version we should avoid?

**E. Dependencies**
Which gaps depend on other gaps being solved first?

## Constraints
- The protocol already has: Ed25519 identity, scoped delegation, cascade revocation, 4-gate commerce, decision equivalence with boundary profiles, DataTerms with compensation, Merkle-committed settlements, derivation chains with cycle detection
- Total surface area matters. 13 new modules is too many. Group related gaps into coherent primitives.
- Ship running code, not specs. Each primitive needs tests.
- The protocol is language-agnostic (TypeScript + Python). Don't propose anything that requires a specific runtime.

## Output format

Group your answers into recommended build phases:
- **Phase 1**: Build now (this week)
- **Phase 2**: Build next (after Phase 1 ships)
- **Phase 3**: Build when ecosystem demands it
- **Phase 4**: Document as application-layer guidance, don't build

For each phase, name the gaps included, the primitive(s) to build, and estimated test count.

Then: **one paragraph on the single most important thing we'd get wrong if we built all 13 without this review.**
