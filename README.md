# Agent Passport System

[![npm version](https://img.shields.io/npm/v/agent-passport-system)](https://www.npmjs.com/package/agent-passport-system)
[![license](https://img.shields.io/npm/l/agent-passport-system)](https://github.com/aeoess/agent-passport-system/blob/main/LICENSE)
[![tests](https://img.shields.io/badge/tests-4098%20passing-brightgreen)](https://github.com/aeoess/agent-passport-system)
[![DOI](https://zenodo.org/badge/DOI/10.5281/zenodo.18749779.svg)](https://doi.org/10.5281/zenodo.18749779)
[![OpenSSF Best Practices](https://www.bestpractices.dev/projects/13536/badge)](https://www.bestpractices.dev/projects/13536)
[![OpenSSF Baseline](https://www.bestpractices.dev/projects/13536/baseline)](https://www.bestpractices.dev/projects/13536)
[![REUSE status](https://api.reuse.software/badge/github.com/aeoess/agent-passport-system)](https://api.reuse.software/info/github.com/aeoess/agent-passport-system)
[![coverage](https://img.shields.io/badge/coverage-97%25%20lines%20%7C%2089%25%20branches-brightgreen)](https://github.com/aeoess/agent-passport-system/blob/main/CONTRIBUTING.md#running-tests)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/aeoess/agent-passport-system/badge)](https://scorecard.dev/viewer/?uri=github.com/aeoess/agent-passport-system)
[![APS conformance](https://img.shields.io/endpoint?url=https%3A%2F%2Fgateway.aeoess.com%2Fapi%2Fv1%2Fpublic%2Fconformance%2Fbadge)](https://github.com/aeoess/aps-conformance-suite)

Verify any receipt or evidence bundle in the browser: https://agent-passport.org/verify.html (per-axis claim-state report; runs locally, nothing is uploaded).

> **For AI agents:** visit [agent-passport.org/llms.txt](https://agent-passport.org/llms.txt) for machine-readable docs.

> **Valid signature. Hijacked intent. Denied by APS.**

**Enforcement and accountability layer for AI agents. Bring your own identity.**

Accepts did:key, did:web, SPIFFE SVIDs, OAuth tokens, and native did:aps. Authority can only decrease at each transfer point. The gateway is both judge and executor. Every action produces a signed receipt. Gateway evaluation under 2ms.

The narrowing invariant:

```mermaid
flowchart LR
    P["Principal<br/>full authority"] -->|"scope: payments<br/>limit: $500, 30 days"| A["Agent A<br/>payments, $500"]
    A -->|"scope: refunds only<br/>limit: $100, 7 days"| B["Agent B<br/>refunds, $100"]
    B -.->|"$200 request:<br/>exceeds chain authority"| X["denied + signed receipt"]
```

```bash
npm install agent-passport-system
```

Also implemented in [Python](https://pypi.org/project/agent-passport-system/) and [Go](https://pkg.go.dev/github.com/aeoess/agent-passport-go), byte-parity-checked against this TypeScript reference.

## Quick Start

Lead with the curated essentials. `agent-passport-system/core` exposes the 24 functions that 90% of integrations need: identity, delegation, enforcement, commerce, reputation, key management. The full `agent-passport-system` root import is unchanged and backward compatible: pull from it when Core does not cover your case.

```typescript
import {
  createPassport, createDelegation,
  evaluateIntent, commercePreflight, generateKeyPair
} from 'agent-passport-system/core'

// Full 925-export API still available. Use when Core does not cover your case.
// import { ... } from 'agent-passport-system'
```

## Status labels

Every primitive in this README carries one of three labels so you know how much weight it can bear today.

- **Canonical** -- stable, signed-bytes frozen, covered by conformance fixtures. Breaking these would break cross-implementation verification. Build on them.
- **Production-Extension** -- shipped and tested, optional, additive to the canonical core. Safe in production; the surface may still grow.
- **Experimental** -- published for review and tested, but the shape may change. Pin a version before depending on it.

Where enforcement sits:

```mermaid
flowchart LR
    AG[Agent] -->|signed intent| GW{"Gateway<br/>scope / spend / revocation / values floor"}
    GW -->|permit| ACT[Action executes]
    GW -->|deny| STOP[Blocked]
    GW --> RC[("Signed receipt<br/>every outcome, both verdicts")]
```

## Core Protocol

*Status: Canonical.*

What ships in every deployment.

**Identity** -- Ed25519 passports, passport grades 0-3, key rotation, did:aps identifiers.

**Delegation** -- Scoped authority with monotonic narrowing. Sub-delegation can only reduce scope. Cascade revocation propagates through the full chain. `subDelegateAdvisor` implements the bounded-escalation delegation pattern used in multi-model agent workflows where a lower-cost executor escalates to a higher-capability advisor at decision points -- the advisor delegation is count-bounded, cannot execute tools, and cascade-revokes with its parent.

**Enforcement** -- 3-signature action chain: agent signs intent, policy engine signs evaluation, agent signs execution receipt. The agent cannot skip the check.

**Commerce** -- 5-gate preflight: valid passport, scope check, spend limit, merchant allowlist, idempotency. Human approval thresholds for high-value transactions.

**Reputation** -- Bayesian trust scoring across 5 tiers. Authority is earned per-scope, not global. Passport grades compound with behavioral history.

## Receipt graph

APS receipts are graph-composable. Each claim links to the authority, policy, action, observation, or evidence it depends on, so a verifier can walk from any receipt back to its supporting facts and stop at the boundary it cares about. This is documentation of existing structure, not a new primitive. The linkage already lives in the existing receipt envelopes (`delegation_chain_root`, `policy_ref`, `action_ref`, `evidence_id`, `bound_to`); the graph view is just how those edges compose.

## Receipt semantics: what each receipt proves

Every APS receipt is a signed declaration about what the system observed. It is not a causal proof of agent cognition, and it is not a proof that an off-protocol side effect actually happened. Each receipt type carries an explicit `scope_of_claim` with `asserts` and `does_not_assert` fields, so the boundary travels with the receipt. The boxes below state that boundary in one place. The same shape is enforced in code by the `ScopeOfClaim` type (`src/v2/accountability/types/base.ts`), re-exported from the package root.

**ActionReceipt** (`aps:action:v1`)
- Proves: the gateway observed the agent issue this action under the cited delegation chain, and the signed body has not changed since signing.
- Does not prove: that the side effect completed, that the agent understood the consequences, or that the business outcome was correct.

**AuthorityBoundaryReceipt** (`aps:authority_boundary:v1`)
- Proves: an authority check ran and returned this verdict against this scope at this time.
- Does not prove: that the scope itself was correctly configured, or that no other path around the boundary exists.

**CustodyReceipt** (`aps:custody:v1`)
- Proves: custody of the named artifact passed from one holder to another, signed by the releasing party.
- Does not prove: that the artifact contents are correct, or that the receiving party will handle it well.

**ContestabilityReceipt** (`aps:contestability:v1`)
- Proves: a contest was opened or resolved against a prior receipt, with the cited grounds.
- Does not prove: that the contest is meritorious, only that it was raised and recorded.

**APSBundle** (`aps:bundle:v1`)
- Proves: the bundled receipts were collected together and each member verifies on its own.
- Does not prove: anything the member receipts do not already prove. A bundle is an envelope, not a new claim.

**PaymentReceipt** (`aps:payment_receipt:v1`)
- Proves: a payment instruction was authorized on the named rail for this amount, currency, and recipient, under the cited delegation.
- Does not prove: that the goods or services were delivered, or that the recipient address was the intended one beyond what the matched intent declared.

Across all of them: a `self_attested` receipt (where the agent signed without independent attestation) carries lower evidentiary weight than a `gateway_observed` or `runtime_attested` one. A verifier should treat the `capture_mode` and `self_attested` fields as part of the claim, not metadata.

## Receipt misuse: what a verifier must reject

A valid signature is not a valid claim. The cases below are receipts that are cryptographically sound yet must still be refused, because they are being used outside the envelope they were issued for. The conformance package under [`tests/conformance/`](tests/conformance/README.md) ships a golden fixture for each one, and a test asserts the rejection reason.

- **Valid receipt, wrong claim.** A sound `aps:action:v1` receipt presented as proof of payment. The signature checks out; the receipt simply does not make that claim. Reject (`WRONG_CLAIM`).
- **Expired delegation.** A receipt issued after its delegation chain expired. The body verifies; the authority behind it had already lapsed. Reject (`DELEGATION_EXPIRED`).
- **Stale revocation.** A receipt whose delegation root was revoked. A verifier that does not consult current revocation state would wrongly accept it. Reject (`DELEGATION_REVOKED`).
- **Unverified external evidence.** A self-attested oracle read presented as gateway-observed evidence. `self_attested` evidence must not be promoted to observed evidence. Reject (`WRONG_CLAIM`).
- **Replayed receipt.** A previously accepted receipt re-submitted. The verifier must reject a `receipt_id` it has already honored in the window. Reject (`REPLAYED`).
- **Policy evaluated but execution never happened.** A policy decision exists with no execution attestation. A permit is not a proof that the action ran. Reject (`POLICY_NOT_EXECUTED`).

A conformant verifier runs the crypto layer first (claim type, `receipt_id` match, signature) and then the context layer (delegation state, budget, principal, policy version, replay window). A receipt that fails either layer is not authoritative.

> **Proof box.** These docs and fixtures specify what each receipt proves and the negatives a conformant verifier must reject. They do not change protocol behavior. No signing path, canonical preimage, or `action_ref` computation is altered by anything in this section.

## Wallet Binding

*Status: Production-Extension.* Optional and additive: passports without `bound_wallets` canonicalize unchanged, and actions without a `walletRef` skip the gate.

Two layers, designed to compose.

**Structural (agent-attested).** The agent's own passport private key signs `{ passport_id, chain, address, bound_at }` and appends the result to the passport's `bound_wallets` field. Verifiable offline with just the passport public key. Chain-agnostic: Nano is the native APS wallet, but the primitive accepts any chain identifier with an address.

```typescript
import { bindWallet, verifyBoundWallet } from 'agent-passport-system'

const bound = bindWallet({
  passport: signedPassport,
  privateKey: agentPrivateKey,
  chain: 'nano',
  address: 'nano_3jb1...',
})

verifyBoundWallet(bound, 'nano', 'nano_3jb1...') // true
```

**Behavioral (issuer-attested).** Independent issuers (the [insumer-examples](https://github.com/douglasborthwick-crypto/insumer-examples) ecosystem and friends, skyemeta/skyeprofile and 8 others) sign attestations about wallet behavior, sybil signals, and on-chain history. Their signatures stand alone.

The two layers compose: a verifier accepting both gets cryptographic proof that **this passport holder controls this address** (structural) **and** that **this address has these behavioral properties** (behavioral). Neither layer claims what the other proves. Multi-attestation envelopes carry both.

`commercePreflight()` enforces the structural layer at gate 5: when the action references a `walletRef`, the gate denies with `WALLET_NOT_BOUND` unless the wallet is currently bound to the acting passport. The check is opt-in. Actions without a `walletRef` skip it, so existing 5-gate flows are unaffected.

`unbindWallet()` produces a separately signed unbind event so the bind/unbind history can be reconstructed independent of the passport's current `bound_wallets` snapshot.

## Credential Check Policy

*Status: Production-Extension.* Delegations without an explicit `credentialCheckPolicy` keep the existing recheck-on-execute behavior unchanged.

A credential needs to declare WHEN it should be re-verified. Different credential types have different trust decay profiles. APS lets the issuer set this on the delegation itself via `credentialCheckPolicy`.

```typescript
import { createDelegation } from 'agent-passport-system'

const delegation = createDelegation({
  delegatedTo: agentPublicKey,
  delegatedBy: principalPublicKey,
  scope: ['payments:wire'],
  spendLimit: 1_000_000,
  expiresInHours: 24,
  privateKey: principalPrivateKey,
  credentialCheckPolicy: {
    mode: 'both',              // 'on-accept' | 'on-process' | 'both'
    max_acceptance_age: 3600,  // optional, seconds
  },
})
```

Three modes:

**`on-accept`** -- verify once at credential acceptance time, trust the snapshot afterward. Cheap. Use for long-lived session credentials where the live revocation cost is prohibitive and brief staleness is acceptable. Live revocation between accept and process will not be caught.

**`on-process`** -- verify on every action evaluation. The default. Catches live revocation. This matches the existing APS recheck-on-execute behavior, so delegations without an explicit `credentialCheckPolicy` continue to work unchanged.

**`both`** -- verify at acceptance AND at process time. Use for high-stakes actions (large spend, irreversible operations, cross-org transactions) where you want both the snapshot integrity check AND the live state check.

Denial codes specific to this gate: `CREDENTIAL_NOT_ACCEPTED` (policy is `on-accept`/`both` but no acceptance stamp), `CREDENTIAL_ACCEPT_STALE` (stamp older than `max_acceptance_age`), `PROCESS_TIME_INVALID` (live state failed), `ACCEPT_TIME_INVALID` (acceptance check failed).

Proposed by [@piiiico](https://github.com/piiiico) on the a2aproject/A2A governance metadata thread.

## Extended Modules

*Status: Production-Extension.*

Pick what you need. `import from 'agent-passport-system'` for the full API.

Coordination (task lifecycle with 9-state machine), EU AI Act mapping support through signed evidence packets for accountability and audit workflows, framework adapters (CrewAI, LangChain, Google ADK, A2A, MCP), bilateral receipts, execution attestation, DID resolution, data lifecycle (access receipts, derivation tracking, consent revocation).

## Research Primitives

*Status: Experimental*, except where noted. The Wave 1 accountability primitives below are **Canonical**: their signed bytes are frozen and pinned by the conformance fixtures.

Forward-looking governance. Published, tested, available.

23 v2 constitutional modules: approval fatigue detection, epistemic isolation, blind evaluation, separation of powers, affected-party standing, circuit breakers, constitutional amendment, authority laundering audit, emergence detection.

Wave 1 accountability primitives: Ed25519 ActionReceipt, AuthorityBoundaryReceipt, CustodyReceipt, ContestabilityReceipt, APSBundle. RFC 8785 JCS canonicalization for cross-implementation receipts and conformance fixtures, content-addressed, byte-match across implementations.

Institutional governance: charters, offices, federation, reserves, multi-party approvals.

## MCP Server

```bash
npx agent-passport-system-mcp
```

20 essential tools by default. Set `APS_PROFILE=full` for all 150 tools. Profiles: essential, identity, governance, coordination, commerce, data, gateway, comms, minimal, full.

## Project codebases

The Agent Passport System spans these repositories:

- [agent-passport-system](https://github.com/aeoess/agent-passport-system): protocol and TypeScript reference implementation (this repo)
- [agent-passport-python](https://github.com/aeoess/agent-passport-python): Python SDK
- [agent-passport-mcp](https://github.com/aeoess/agent-passport-mcp): MCP server binding
- [aps-conformance-suite](https://github.com/aeoess/aps-conformance-suite): cross-implementation conformance fixtures
- [agent-governance-vocabulary](https://github.com/aeoess/agent-governance-vocabulary): open vocabulary registry and crosswalks
- [aps-web](https://github.com/agent-passport-system/aps-web): the agent-passport.org website

## Ecosystem composition

APS ships its own identity layer (`src/core/key-rotation.ts`, `src/types/did.ts`) plus the full delegation, enforcement, governance, commerce, data, coordination, and composition stack. Where independent implementations exist for the same primitives, vocabulary crosswalks track the mapping in [agent-governance-vocabulary](https://github.com/aeoess/agent-governance-vocabulary):

- **[Agent-DID](https://github.com/edisonduran/agent-did)** is an independent identity-layer implementation. Crosswalk: [`crosswalk/agent-did.yaml`](https://github.com/aeoess/agent-governance-vocabulary/blob/main/crosswalk/agent-did.yaml). Co-drafted A2A composition contract: [a2aproject/A2A#1742](https://github.com/a2aproject/A2A/issues/1742).

The composition contract specifies how a verifier MUST cross-check per-request signature key material against published Agent Card key material under the rotation state machine. APS implements the verifier-side rules in `src/core/key-rotation.ts`; Agent-DID's `IdentityCompositionError` is the typed error shape used by both implementations.

## Numbers

4,098 tests. 8 protocol layers. Framework adapters for CrewAI, LangChain, ADK, A2A, MCP, OpenShell, IBAC, Gonka. Gateway evaluation under 2ms. Zero heavy dependencies. Apache-2.0.

The test count is one number derived from the suite, not three guesses. The badge above, this section, and the `package.json` description all carry the same `4,026`, which is the `tests` total reported by `npm test`. When the suite grows, re-run `npm test`, read the `tests` line, and update all three to match.

## Papers

- [The Agent Social Contract](https://doi.org/10.5281/zenodo.18749779)
- [Monotonic Narrowing](https://doi.org/10.5281/zenodo.18932404)
- [Faceted Authority Attenuation](https://doi.org/10.5281/zenodo.19260073)
- [Behavioral Derivation Rights](https://doi.org/10.5281/zenodo.19476002)
- [Physics-Enforced Delegation](https://doi.org/10.5281/zenodo.19478584)
- [Governance in the Medium](https://doi.org/10.5281/zenodo.19582550)
- [Cognitive Attestation](https://doi.org/10.5281/zenodo.19646276)
- [The Evidence-Safety Gap](https://doi.org/10.5281/zenodo.19914628)
- IETF Internet-Draft: `draft-pidlisnyi-aps-01`

## Security and conformance

- [Threat model](/THREAT_MODEL.md) -- actors, assets, trust boundaries, what APS prevents and what it does not, verifier responsibilities.
- [Conformance fixtures](tests/conformance/README.md) -- golden valid and negative receipt fixtures every verifier must agree on.
- [Payment Safety Profile](docs/PAYMENT-SAFETY-PROFILE.md) -- the mandatory profile for agent-initiated payments.

## Contributing

- [Contribution path](/CONTRIBUTION_PATH.md)
- [Open problems](/OPEN_PROBLEMS.md)
- [Governance surfaces](/GOVERNANCE_SURFACES.md)

## Links

- [aeoess.com](https://agent-passport.org) -- Protocol home
- [llms-full.txt](https://aeoess.com/llms-full.txt) -- Complete reference for AI agents
- [Dev log](https://aeoess.com/blog.html) -- Day-by-day build record
- [npm](https://www.npmjs.com/package/agent-passport-system) · [PyPI](https://pypi.org/project/agent-passport-system/) · [MCP](https://www.npmjs.com/package/agent-passport-system-mcp)

Copyright 2026 Tymofii Pidlisnyi. Apache-2.0.
