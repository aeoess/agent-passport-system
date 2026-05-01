# Full Accountability MVP: Wave 1

**Status:** Draft
**Spec version:** v1
**SDK target:** `agent-passport-system@2.5.0-alpha`
**Authored:** 2026-04-30
**Prior art:** Consilium synthesis at `~/aeoess-private/consilium/2026-04-30-*.md`

---

## What this is

The minimum viable surface for **attribution-grade accountability** of autonomous agent actions. Four signed receipts plus one aggregation envelope, all cryptographically composable, all explicit about what they prove and what they do not.

This is the first delivery of APS's commitment to be the **evidence layer** for autonomous agent actions, not the police, the judge, or the prison. The camera, the license plate, the chain of custody, the format of the ticket.

## Design principle: verbal confessions, not brain scans

Every primitive in this spec captures **what the system declared**, not **what the agent computationally caused**. This is a deliberate epistemological choice. Receipts are admissible evidence in the way a verbal confession is admissible. They are signed, contemporaneous, and attributable. They do not overclaim what they cannot prove. The receipt does not decode model cognition. It records what was visible, what was authorized, what was emitted, and who held the evidence afterward.

Every receipt in this spec carries an explicit `scope_of_claim` field that names what it does NOT assert. Honest scope is mandatory, not optional. A receipt that hides its limits is weaker evidence than one that states them.

## Mission frame

> Observability tells the operator what happened.
> APS receipts let affected parties contest what happened.

Every observability vendor today is operator-facing. The accountability surface APS ships here is the first cryptographic format designed for parties without operator access: harmed individuals, regulators, insurers, courts, internal audit functions, external watchdogs.

## The four primitives

### 1. ActionReceipt: `aps:action:v1`

Records that an action was emitted by an agent under an authority chain.

**Cryptographically asserts:** an agent with this DID, under this delegation chain, emitted this payload to this target at this time.

**Does not assert:** that the action caused any specific outcome, that the principal explicitly approved this exact action (delegation chain authorizes a class of action; this is one instance), that no side effects beyond the listed classes occurred, that the action was lawful or wise.

**Composes with:** existing IntentReceipt and PolicyDecisionReceipt via `intent_ref` and `policy_ref` fields. Forward composition: AuthorityBoundary, Custody, and Contestability receipts reference an ActionReceipt's `receipt_id`.

**Side effect taxonomy** (six classes, extensible namespace): `financial`, `data_modification`, `external_message`, `irreversible`, `subject_affecting`, `internal_only`.

**Optional integrity upgrades:** RFC 3161 timestamp attestation, transparency log inclusion (Rekor-compatible). Without these, evidentiary weight is strictly party-attested.

### 2. AuthorityBoundaryReceipt: `aps:authority_boundary:v1`

Records whether a specific action was inside or outside the authority delegated to the acting agent. This is APS's monotonic-narrowing wedge expressed as a first-class receipt.

**Cryptographically asserts:** at named time, this action was evaluated against the delegation chain rooted at this hash, and the comparison result was inside/outside/indeterminate.

**Does not assert:** that the policy allowed the action (separate concern, captured in PolicyDecisionReceipt), that all upstream delegation links are signed by uncompromised keys, that the chain captures every authority path that could have produced the action.

**Composes with:** ActionReceipt via `action_id`. The verifier signing this receipt is typically the gateway, but may be any independently-running authority comparator.

**Why this is a separate receipt:** "policy allowed it" and "principal authorized it" are distinct claims with distinct implications in litigation. A policy can be overpermissive; authority cannot exceed delegation. Conflating these in a single receipt collapses an evidentiary distinction that matters.

### 3. CustodyReceipt: `aps:custody:v1`

Records a custody event in the lifecycle of one or more receipts: creation, sealing, transfer, disclosure, redaction, erasure, expiry, verification.

**Cryptographically asserts:** at named time, named custodian performed the named custody event against the named receipt batch (Merkle-rooted), for the named purpose.

**Does not assert:** that the custodian's claim is factually accurate (the protocol records the claim; truth is rebuttable), that data was preserved or destroyed in fact (other receipts may corroborate), that the receiving custodian honored their handoff obligations.

**Custody event taxonomy:** `created`, `sealed`, `transferred`, `disclosed`, `redacted`, `erased`, `expired`, `verified`.

**Purpose taxonomy:** `internal_audit`, `regulator_disclosure`, `subject_access`, `litigation_discovery`, `vendor_handoff`, `archival`, `incident_response`.

**RTBF reconciliation:** `erased` events preserve the original `receipt_id` and content hash while declaring the content destroyed. This is the cryptographic-erasure pattern: the chain remains verifiable; the content is mathematically irrecoverable. Salt destruction is the recommended implementation mechanism but is intentionally outside protocol scope (operational detail).

### 4. ContestabilityReceipt: `aps:contestability:v1`

Records that a contestation was filed against an action by a contestant with claimed standing, with named grounds and a named requested remedy. Optionally records the controller's response.

**Cryptographically asserts:** a contestant identified by DID or pseudonym hash filed a challenge against the named action at the named time, with the named grounds and remedy. If a controller response is present, asserts the controller acknowledged the contestation with the named status at the named time.

**Does not assert:** that the contestation is meritorious, that standing is legally valid (standing is determined externally, not by protocol), that the controller's response is correct or final.

**Standing basis taxonomy:** `data_subject`, `third_party`, `regulator`, `court`, `internal_audit`, `insurer`, `principal`.

**Requested remedy taxonomy:** `rollback`, `review`, `explanation`, `compensation`, `erasure`, `modification`.

**Contest status lifecycle:** `filed → under_review → {upheld, rejected, remedied, expired, abandoned}`.

**Why this is the wedge primitive:** every observability vendor in the market today is operator-facing. ContestabilityReceipt makes APS the first cryptographic format designed for **standing**: the right of an affected party to challenge an automated decision and force a tracked response. This is what Article 22 GDPR and Article 14 EU AI Act demand operationally, with no current standardized format.

## The bundle envelope

### APSBundle: `aps:bundle:v1`

A signed aggregation envelope over a set of receipts within a defined time period and scope. The unit of value most consumers actually want.

**Why bundles, not raw receipts:** auditors, insurers, regulators, and discovery requests are bounded by time period or subject. Without a standard aggregation format, every consumer re-implements aggregation. Fragmenting aggregation fragments the protocol.

**Asserts:** the receipts named by Merkle root were aggregated by the named bundler at the named time, scoped to the named period and subjects, conforming to the named profile list.

**Does not assert:** that all receipts in the period were included (omission is undetectable from the bundle alone; completeness verification requires external transparency log cross-check), that the included receipts are valid (each receipt's signature must be independently verified).

## Conformance profiles

Profiles are documents (not code) that name which subset of primitives is required for a regulatory or commercial use case. Wave 1 ships with three profile drafts:

- **`aps:profile/mva-v1`**: Minimum Viable Accountability. Action + AuthorityBoundary + Custody. Sufficient for SOC 2 audit substrate, internal governance, baseline insurance underwriting.
- **`aps:profile/eu-aiact-art12-v1`**: EU AI Act Article 12 record-keeping. Adds Custody Erasure + retention floor declarations, requires `transparency_log_inclusion` on Action receipts.
- **`aps:profile/gdpr-art22-v1`**: GDPR Article 22 right to contest. Adds Contestability + Disclosure references, requires controller-response signature within statutory deadline.

Additional profiles ship as separate documents in `specs/profiles/`.

## What is explicitly NOT in Wave 1

These primitives were considered and deferred. They are not banned from future waves; they are deferred because Wave 1 must be small enough to ship cleanly across the 8 byte-match implementations.

- **Knowledge Surface Receipt**: extends IPR with RAG retrievals, tool results, prior turns. Wave 2.
- **Disclosure Manifest**: formal Article 12-14 / Article 50 disclosure with display evidence. Wave 2.
- **Override Receipt**: first-class human oversight capture. Wave 2 (Article 14 EU AI Act).
- **Outcome Reference + Outcome Observation**: the agent cannot honestly sign its own outcomes. Independent observer signs. Optional, post-Wave-2 once counterparty integrations land.
- **Behavioral Fingerprint**: exists today in v2; under review for redesign with encrypted-to-principal default before being formally exposed in the accountability surface.
- **Reputation / trust scoring**: explicitly NOT a protocol primitive. Methodologically contested. Stays in product layer.
- **Causation receipt**: the agent cannot prove causation from a receipt. This is reconstruction work, not protocol work. Stays in product.
- **Compliance pass/fail receipt**: APS records evidence; the protocol does not render legal judgments.

## Composition graph

```
Principal (Ed25519 keypair)
    ↓ signs
Delegation Chain (V2Delegation, monotonic narrowing)
    ↓ referenced by
IntentReceipt → PolicyDecisionReceipt → ActionReceipt
                                              ↓
                            ┌─────────────────┼─────────────────┐
                            ↓                 ↓                 ↓
                AuthorityBoundary     CustodyReceipt    ContestabilityReceipt
                                              ↓
                                    (custody chain extends
                                     across transfers)
                                              ↓
                                       APSBundle
                                  (aggregation envelope,
                                   per period + scope)
```

## Cryptographic baseline

- **Signatures:** Ed25519 over JCS-canonicalized (RFC 8785) bytes.
- **Receipt identity:** `receipt_id = sha256(jcs(receipt excluding signature))`. Content-addressed.
- **Bundle Merkle:** balanced binary tree over sorted `receipt_id` bytes, SHA-256.
- **Timestamps:** ISO 8601 UTC with millisecond precision, ending `Z`. Optional RFC 3161 TSA attestation per receipt.

## Evidentiary weight tiers

Every primitive in Wave 1 supports three evidentiary weight tiers via the `scope_of_claim.capture_mode` field:

| Tier | capture_mode | What it means |
|---|---|---|
| 1 | `self_attested` | Agent signed alone. Weakest. |
| 2 | `gateway_observed` | Independent attester (gateway) co-signed. |
| 3 | `runtime_attested` | TEE or hardware-rooted attestation. Strongest. |

Receipts gracefully degrade. A `self_attested` receipt is still admissible; it is just downgraded in evidentiary weight. Honest declaration of capture mode is mandatory.

## Cross-implementation byte-match commitment

Every primitive in Wave 1 ships with a deterministic JSON fixture (privateKey hex `"11"` repeated, timestamp `2026-04-30T00:00:00.000Z`) that other byte-match implementations can validate against. APS commits to maintaining the fixture set as the canonical reference.

## What ships next

Wave 2 (Q4 2026) extends with: Knowledge Surface, Disclosure Manifest, Override Receipt. Conformance profiles for: EU AI Act Article 14, HIPAA 164.312, SOC 2 trust services, FRE 902(13)/(14) court admissibility, insurance underwriting actuarial inputs.

Wave 3 and beyond is a strategic decision dependent on Wave 1+2 adoption signals.

## Strategic posture

APS is not a product. APS is the open receipt grammar that lets observability tools, compliance vendors, regulators, insurers, and courts coordinate around a common evidence format without licensing capture. The commercial layer (gateway, dashboards, conformance certification) is separate and proprietary.

The strongest single line for outside audiences:

> Observability shows the operator what happened. APS receipts give affected parties standing to contest what happened.

The accountability frame, sharpened:

> Receipts are verbal confessions, not brain scans. They prove what the system declared, not what the agent computationally caused. That honesty is the source of their evidentiary weight.

---

**End of MVP-1 spec.**
