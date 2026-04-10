# CC Build Spec: Product Restructure — Essential Profile + Subpath Exports + Tiered README

## Context

The protocol has 103 modules and 132 MCP tools. The protocol is complete. The problem is that new users hit a wall: 132 tools in a flat MCP list, 925 SDK exports, and a README that lists everything equally. Every GitHub conversation this week was about ~15 core modules. Nobody asked about the other 88.

This spec makes the first experience clean without deleting anything. No breaking changes. No removed exports. No removed tools. Additive only.

## Pre-Build Checks

Before writing any code:
1. Read `src/index.ts` — understand all current exports
2. Read `src/core/commerce.ts` — verify commercePreflight is the correct function name
3. Run `npm test` — record baseline test count (should be 2552)
4. Run `npm run build` — confirm clean build

## Part 1: SDK — Core Subpath Export

### 1A. Create `src/core-exports.ts`

A curated subset of ~25 essential functions. This is what 90% of users need.

```typescript
// src/core-exports.ts
// Curated essential exports — import from 'agent-passport-system/core'
// Full API still available at 'agent-passport-system'

// Identity
export {
  generateKeyPair,
  createPassport,
  verifyPassport,
  issuePassport,
} from './core/passport.js'

// Delegation
export {
  createDelegation,
  verifyDelegation,
  revokeDelegation,
  subDelegate,
  cascadeRevoke,
  scopeAuthorizes,
} from './core/delegation.js'

// Policy & Enforcement
export {
  createActionIntent,
  evaluateIntent,
  completeAction,
} from './core/policy.js'

export {
  createAgentContext,
  executeWithContext,
} from './core/context.js'

// Values Floor
export {
  loadValuesFloor,
  attestToFloor,
} from './core/values.js'

// Commerce
export {
  commercePreflight,
  createCommerceDelegation,
  getSpendSummary,
  requestHumanApproval,
} from './core/commerce.js'

// Reputation
export {
  resolveAuthorityTier,
  checkTierForIntent,
} from './core/reputation-authority.js'

// Key Management
export { rotateKey } from './core/key-rotation.js'

// Content-Addressed Identity
export { computeActionRef } from './core/action-ref.js'
export { computeIdempotencyKey } from './core/idempotency.js'

// Compliance
export { generateComplianceReport } from './core/euaiact.js'

// Re-export essential types
export type {
  SignedPassport,
  AgentPassport,
  PassportGrade,
} from './types/passport.js'

export type {
  SignedDelegation,
  DelegationScope,
} from './types/passport.js'

export type {
  ActionIntent,
  PolicyReceipt,
} from './types/policy.js'

export type {
  CommercePreflightResult,
  CommerceDelegation,
  IdempotencyStore,
} from './types/commerce.js'
```

**IMPORTANT:** Check each import path compiles. Some functions may be exported from different files than expected. Read the actual source files and adjust import paths accordingly. The function names above are correct — the file paths may need adjustment.

### 1B. Update `package.json` — Add exports field

Add this AFTER the existing "main" field:

```json
"exports": {
  ".": "./dist/src/index.js",
  "./core": "./dist/src/core-exports.js"
},
```

Keep the existing "main" field unchanged for backward compatibility.

### 1C. Verify

After building:
- `import { createPassport } from 'agent-passport-system'` still works (full API)
- `import { createPassport } from 'agent-passport-system/core'` works (curated subset)
- Both resolve without errors

## Part 2: SDK README Rewrite

Replace the existing README.md content. Keep the badges at the top. Replace everything below them.

The new structure:

```markdown
# Agent Passport System

[badges stay as-is]

> **For AI agents:** visit [aeoess.com/llms.txt](https://aeoess.com/llms.txt) for machine-readable docs.

**Governance infrastructure for AI agents. Gateway evaluation under 2ms.**

Authority can only decrease at each transfer point. The gateway is both judge and executor. Every action produces a signed receipt.

\`\`\`bash
npm install agent-passport-system
\`\`\`

## Quick Start

\`\`\`typescript
import {
  createPassport, createDelegation, evaluateIntent, commercePreflight
} from 'agent-passport-system/core'
\`\`\`

## Core Protocol

What ships in every deployment.

**Identity** — Ed25519 passports, passport grades 0-3, key rotation, did:aps identifiers.

**Delegation** — Scoped authority with monotonic narrowing. Sub-delegation can only reduce scope. Cascade revocation propagates through the full chain.

**Enforcement** — 3-signature action chain: agent signs intent, policy engine signs evaluation, agent signs execution receipt. The agent cannot skip the check.

**Commerce** — 5-gate preflight: valid passport, scope check, spend limit, merchant allowlist, idempotency. Human approval thresholds for high-value transactions.

**Reputation** — Bayesian trust scoring across 5 tiers. Authority is earned per-scope, not global. Passport grades compound with behavioral history.

## Extended Modules

Pick what you need. `import from 'agent-passport-system'` for the full API.

Coordination (task lifecycle with 9-state machine), EU AI Act compliance (signed evidence packets), framework adapters (CrewAI, LangChain, Google ADK, A2A, MCP), bilateral receipts, execution attestation, DID resolution, data lifecycle (access receipts, derivation tracking, consent revocation).

## Research Primitives

Forward-looking governance. Published, tested, available.

32 v2 constitutional modules: approval fatigue detection, epistemic isolation, blind evaluation, separation of powers, affected-party standing, circuit breakers, constitutional amendment, authority laundering audit, emergence detection.

Institutional governance: charters, offices, federation, reserves, multi-party approvals.

## MCP Server

\`\`\`bash
npx agent-passport-system-mcp
\`\`\`

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

- [aeoess.com](https://aeoess.com) — Protocol home
- [llms-full.txt](https://aeoess.com/llms-full.txt) — Complete reference for AI agents
- [Dev log](https://aeoess.com/blog.html) — Day-by-day build record
- [npm](https://www.npmjs.com/package/agent-passport-system) · [PyPI](https://pypi.org/project/agent-passport-system/) · [MCP](https://www.npmjs.com/package/agent-passport-system-mcp)

Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0.
```

## Part 3: MCP Server — Essential Profile

This is in the agent-passport-mcp repo at `~/agent-passport-mcp`.

### 3A. Add "essential" profile

In `src/index.ts`, find the `TOOL_PROFILES` object. Add this entry:

```typescript
essential: new Set([
  'generate_keys', 'issue_passport', 'get_passport_grade',
  'create_delegation', 'verify_delegation', 'revoke_delegation', 'sub_delegate',
  'load_values_floor', 'attest_to_floor',
  'create_intent', 'evaluate_intent', 'complete_action',
  'create_agent_context', 'execute_with_context',
  'commerce_preflight', 'get_commerce_spend', 'request_human_approval',
  'resolve_authority', 'check_tier', 'rotate_key',
]),
```

### 3B. Update the list_profiles tool output

Find the `list_profiles` tool handler. Update the tool count in the string that says "122 tools" or "132 tools" to reflect the actual current count. Also update it to mention the essential profile prominently.

### 3C. Update the MCP README.md

Rewrite the opening of the MCP README to lead with the essential profile:

```markdown
# Agent Passport System — MCP Server

20 essential tools for AI agent governance. Identity, delegation, enforcement, commerce, reputation.

\`\`\`bash
npx agent-passport-system-mcp
\`\`\`

Set `APS_PROFILE=essential` for 20 core tools (recommended).
Set `APS_PROFILE=full` for all 132 tools.

Available profiles: essential, identity, governance, coordination, commerce, data, gateway, comms, minimal, full.
```

## What NOT To Do

- Do NOT remove any exports from `src/index.ts`
- Do NOT remove any MCP tools
- Do NOT delete any files
- Do NOT rename any functions or tools
- Do NOT change the default MCP profile from `full` to `essential` (that's a deployment config change, not a code change — we'll do it on Railway separately)
- Do NOT bump versions or publish — Tima reviews the diff first
- Do NOT touch the website or llms.txt — that's a separate propagation step

## Tests

After all changes:
1. `npm test` in agent-passport-system — all 2552 tests pass
2. `npm run build` in agent-passport-system — clean build
3. `npm run build` in agent-passport-mcp — clean build
4. Verify: `node -e "const c = require('./dist/src/core-exports.js'); console.log(Object.keys(c).length)"` — should show ~25 exports
5. Verify: `node -e "const f = require('./dist/src/index.js'); console.log(Object.keys(f).length)"` — should still show 925 (unchanged)

## Verification Checklist

- [ ] `core-exports.ts` compiles and exports ~25 functions
- [ ] `package.json` has `"exports"` field with `.` and `./core`
- [ ] SDK README rewritten with tiered structure
- [ ] MCP `essential` profile added with 20 tools
- [ ] MCP README updated to lead with essential profile
- [ ] All existing tests pass unchanged
- [ ] Both repos build clean
- [ ] `git diff --stat` reviewed for both repos
- [ ] NO exports removed, NO tools removed, NO files deleted
