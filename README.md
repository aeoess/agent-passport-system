# Agent Passport System

[![npm version](https://img.shields.io/npm/v/agent-passport-system)](https://www.npmjs.com/package/agent-passport-system)
[![license](https://img.shields.io/npm/l/agent-passport-system)](https://github.com/aeoess/agent-passport-system/blob/main/LICENSE)
[![tests](https://img.shields.io/badge/tests-2764%20passing-brightgreen)](https://github.com/aeoess/agent-passport-system)
[![DOI](https://zenodo.org/badge/DOI/10.5281/zenodo.18749779.svg)](https://doi.org/10.5281/zenodo.18749779)

> **For AI agents:** visit [aeoess.com/llms.txt](https://aeoess.com/llms.txt) for machine-readable docs.

**Enforcement and accountability layer for AI agents. Bring your own identity.**

Accepts did:key, did:web, SPIFFE SVIDs, OAuth tokens, and native did:aps. Authority can only decrease at each transfer point. The gateway is both judge and executor. Every action produces a signed receipt. Gateway evaluation under 2ms.

```bash
npm install agent-passport-system
```

## Quick Start

Lead with the curated essentials. `agent-passport-system/core` exposes the ~25 functions that 90% of integrations need — identity, delegation, enforcement, commerce, reputation, key management. The full `agent-passport-system` root import is unchanged and backward compatible: pull from it when Core does not cover your case.

```typescript
import {
  createPassport, createDelegation,
  evaluateIntent, commercePreflight, generateKeyPair
} from 'agent-passport-system/core'

// Full 936-export API still available — use when Core does not cover your case.
// import { ... } from 'agent-passport-system'
```

## Core Protocol

What ships in every deployment.

**Identity** -- Ed25519 passports, passport grades 0-3, key rotation, did:aps identifiers.

**Delegation** -- Scoped authority with monotonic narrowing. Sub-delegation can only reduce scope. Cascade revocation propagates through the full chain. `subDelegateAdvisor` implements the bounded-escalation delegation pattern used in multi-model agent workflows where a lower-cost executor escalates to a higher-capability advisor at decision points -- the advisor delegation is count-bounded, cannot execute tools, and cascade-revokes with its parent.

**Enforcement** -- 3-signature action chain: agent signs intent, policy engine signs evaluation, agent signs execution receipt. The agent cannot skip the check.

**Commerce** -- 5-gate preflight: valid passport, scope check, spend limit, merchant allowlist, idempotency. Human approval thresholds for high-value transactions.

**Reputation** -- Bayesian trust scoring across 5 tiers. Authority is earned per-scope, not global. Passport grades compound with behavioral history.

## Wallet Binding

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

**Behavioral (issuer-attested).** Independent issuers (the [insumer-examples](https://github.com/insumerapi/insumer-examples) ecosystem and friends — skyemeta/skyeprofile and 8 others) sign attestations about wallet behavior, sybil signals, and on-chain history. Their signatures stand alone.

The two layers compose: a verifier accepting both gets cryptographic proof that **this passport holder controls this address** (structural) **and** that **this address has these behavioral properties** (behavioral). Neither layer claims what the other proves. Multi-attestation envelopes carry both.

`commercePreflight()` enforces the structural layer at gate 5: when the action references a `walletRef`, the gate denies with `WALLET_NOT_BOUND` unless the wallet is currently bound to the acting passport. The check is opt-in — actions without a `walletRef` skip it, so existing 5-gate flows are unaffected.

`unbindWallet()` produces a separately signed unbind event so the bind/unbind history can be reconstructed independent of the passport's current `bound_wallets` snapshot.

## Credential Check Policy

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

Pick what you need. `import from 'agent-passport-system'` for the full API.

Coordination (task lifecycle with 9-state machine), EU AI Act compliance (signed evidence packets), framework adapters (CrewAI, LangChain, Google ADK, A2A, MCP), bilateral receipts, execution attestation, DID resolution, data lifecycle (access receipts, derivation tracking, consent revocation).

## Research Primitives

Forward-looking governance. Published, tested, available.

32 v2 constitutional modules: approval fatigue detection, epistemic isolation, blind evaluation, separation of powers, affected-party standing, circuit breakers, constitutional amendment, authority laundering audit, emergence detection.

Institutional governance: charters, offices, federation, reserves, multi-party approvals.

## MCP Server

```bash
npx agent-passport-system-mcp
```

20 essential tools by default. Set `APS_PROFILE=full` for all 132 tools. Profiles: essential, identity, governance, coordination, commerce, data, gateway, comms, minimal, full.

## Numbers

2,763 tests. 8 protocol layers. 11 framework adapters. Gateway evaluation under 2ms. Zero heavy dependencies. Apache-2.0.

## Papers

- [The Agent Social Contract](https://doi.org/10.5281/zenodo.18749779)
- [Faceted Authority Attenuation](https://doi.org/10.5281/zenodo.19260073)
- [Behavioral Derivation Rights](https://doi.org/10.5281/zenodo.19365841)
- [Physics-Enforced Delegation](https://doi.org/10.5281/zenodo.19478584)
- IETF Internet-Draft: draft-pidlisnyi-aps-00

## Links

- [aeoess.com](https://aeoess.com) -- Protocol home
- [llms-full.txt](https://aeoess.com/llms-full.txt) -- Complete reference for AI agents
- [Dev log](https://aeoess.com/blog.html) -- Day-by-day build record
- [npm](https://www.npmjs.com/package/agent-passport-system) · [PyPI](https://pypi.org/project/agent-passport-system/) · [MCP](https://www.npmjs.com/package/agent-passport-system-mcp)

Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0.
