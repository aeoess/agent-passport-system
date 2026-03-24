# Data Modules — Application-Layer Guidance

These four capabilities were reviewed by a 6-model consilium (2026-03-24)
and unanimously classified as application-layer concerns, not protocol primitives.
The protocol provides the foundation; applications build these on top.

## 1. Data Pricing Discovery (Gap 4)

**Why not protocol-level:** Markets discover prices, not identity protocols.
Baking price discovery into the protocol would make it an exchange, not infrastructure.

**What the protocol provides:**
- `DataTerms.compensation.rate` — posted price per access
- `generateSettlement()` — Merkle-committed compensation records
- `TermsVersionPin` — pinned rate at moment of access
- Settlement history is auditable and queryable

**What applications should build:**
- Order books or posted-price marketplaces using DataTerms
- Dynamic pricing based on access frequency (from `getSourceMetrics()`)
- Recommended pricing based on comparable sources
- Price negotiation protocols between agents and sources

---

## 2. Quality-Weighted Attribution (Gap 5)

**Why not protocol-level:** Quality is subjective, domain-specific,
and gameable. The protocol treats 1 access = 1 contribution unit.

**What the protocol provides:**
- `recordContribution()` — tracks access counts per source per agent
- `generateSettlement()` — computes compensation from counts × rate
- Optional fields on access receipts for application metadata

**What applications should build:**
- External quality scoring services (third-party evaluators)
- Quality multipliers applied at settlement time (app logic, not protocol)
- Feedback loops: consuming agents rate source quality post-access
- Domain-specific scoring (medical data quality ≠ financial data quality)

---

## 3. Data Unions / Collective Bargaining (Gap 11)

**Why not protocol-level:** A data union is an application that pools
resources and splits revenue. The protocol already has the primitives.

**What the protocol provides:**
- `PrincipalIdentity` — a collective can be a principal
- `EntityBinding` — a collective can be a legal entity (e.g. DAO, cooperative)
- `DataTerms` — unified terms set by the collective
- `generateSettlement()` — pooled compensation to collective's address
- Delegation chains — collective delegates to individual members

**What applications should build:**
- Collective entity registration and membership management
- Internal revenue split logic (pro-rata, weighted, equal)
- Collective bargaining interfaces (term negotiation on behalf of members)
- Member onboarding/offboarding flows

---

## 4. Retroactive Terms (Gap 12)

**Why not protocol-level:** Mutating historical access records to enforce
retroactive compensation breaks the immutable ledger principle.
This is a legal problem, not a code problem.

**What the protocol provides:**
- Access receipts prove historical access occurred (immutable evidence)
- `TermsVersionPin` proves what terms existed at access time
- `AccessSnapshot` proves exact state at moment of access (anti-rug-pull)
- `DisputeRecord` with `filedBy`, `evidence`, `status` for contested claims

**What applications should build:**
- Retroactive claim filing using DisputeRecord with `retroactive_claim` evidence
- Settlement generation with `contested` status for pre-terms access
- Mediation interfaces that present both parties' evidence
- Legal counsel integration for jurisdiction-specific retroactivity rules

---

## Summary

The protocol's job is to preserve identity, lineage, obligation state, purpose
context, and explainability across data flows. It does not do price discovery,
quality scoring, collective bargaining, or legal interpretation. Those belong
to the applications, marketplaces, and institutions built on top.

The dividing line: **if it requires cryptographic proof, it's protocol.
If it requires subjective judgment, market dynamics, or legal interpretation,
it's application-layer.**
