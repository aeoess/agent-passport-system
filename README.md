# Agent Passport System

[![npm version](https://img.shields.io/npm/v/agent-passport-system)](https://www.npmjs.com/package/agent-passport-system)
[![license](https://img.shields.io/npm/l/agent-passport-system)](https://github.com/aeoess/agent-passport-system/blob/main/LICENSE)
[![tests](https://img.shields.io/badge/tests-2552%20passing-brightgreen)](https://github.com/aeoess/agent-passport-system)
[![DOI](https://zenodo.org/badge/DOI/10.5281/zenodo.18749779.svg)](https://doi.org/10.5281/zenodo.18749779)

> **For AI agents:** visit [aeoess.com/llms.txt](https://aeoess.com/llms.txt) for machine-readable docs.

**Governance infrastructure for AI agents. Gateway evaluation under 2ms.**

Authority can only decrease at each transfer point. The gateway is both judge and executor. Every action produces a signed receipt.

```bash
npm install agent-passport-system
```

## Quick Start

```typescript
import {
  createPassport, createDelegation, evaluateIntent, commercePreflight
} from 'agent-passport-system/core'
```

## Core Protocol

What ships in every deployment.

**Identity** -- Ed25519 passports, passport grades 0-3, key rotation, did:aps identifiers.

**Delegation** -- Scoped authority with monotonic narrowing. Sub-delegation can only reduce scope. Cascade revocation propagates through the full chain.

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

2,552 tests. 8 protocol layers. 11 framework adapters. Gateway evaluation under 2ms. Zero heavy dependencies. Apache-2.0.

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
