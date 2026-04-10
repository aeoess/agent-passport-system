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
