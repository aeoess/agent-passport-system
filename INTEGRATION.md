# Building on APS — Integration Guide

Stop rebuilding identity, delegation, and receipts. Build your application on shared infrastructure.

## The Problem

Every project in the agent governance space is independently implementing:
- Ed25519 key generation and signing
- Delegation scope checking
- Spend limit enforcement
- Receipt/proof schemas
- Canonical JSON serialization (RFC 8785)
- Revocation propagation

This creates fragmentation: 10 projects, 10 incompatible identity layers, 10 receipt formats, 10 delegation models.

## The Alternative

Use tested, cross-verified primitives as your foundation. Build your domain-specific logic on top.

APS has been cross-tested against:
- **AgentID** — 7/7 cross-protocol tests passing (compound digest, action_ref, constraint mapping, receipt interop, Ed25519 dual signing, context continuity, daemon agents)
- **MolTrust AAE** — 5/5 delegation narrowing vectors passing (scope subset, temporal narrowing, self-issuance, spend limits, expired credentials)
- **Kanoniv** — delegation chain signatures cross-verified (Python ↔ TypeScript)

## How Projects Compose with APS

### Transport Signing (Signet, MCPS)
You handle transport integrity. APS handles identity and policy.
```typescript
import { joinSocialContract, createDelegation } from 'agent-passport-system'
// Your agent gets an APS passport (identity)
const agent = joinSocialContract({ name: 'my-agent', ... })
// Your transport layer signs with the same Ed25519 key
// APS delegation chain travels inside your signed envelope
```

### External Anchoring (ArkForge, Rekor)
You handle tamper-evidence. APS produces the receipts you anchor.
```typescript
import { createExecutionAttestation } from 'agent-passport-system'
// APS produces a signed ExecutionAttestation after tool execution
const attestation = createExecutionAttestation({ ... })
// Your anchoring layer submits the attestation hash to Rekor/your log
// The attestation schema is standardized — any anchor backend works
```

### Spend Enforcement (AgentPay)
You handle payment rails. APS handles delegation-scoped spend limits.
```typescript
import { createDelegation } from 'agent-passport-system'
// Delegation includes spendLimit — authority to spend up to $X
const delegation = createDelegation({ spendLimit: 10000, scope: ['commerce'], ... })
// Your payment system checks: is this transaction within the delegation's spend limit?
// APS tracks spentAmount across calls. Cascade revocation kills all downstream authority.
```

### Trust Scoring (AgentID)
You handle CA-issued certificates. APS handles self-sovereign identity. Both work.
```typescript
// APS passport grades (0-3) map to AgentID trust levels (L1-L4)
// Grade 0 = 0-25, Grade 1 = 26-50, Grade 2 = 51-75, Grade 3 = 76-100
// Cross-tested: 7/7 vectors passing
```

### Constraint Evaluation (MolTrust AAE, Guardian)
You handle domain-specific constraints. APS handles the structural invariants.
```typescript
// Your AAE MANDATE maps to APS delegation.scope
// Your CONSTRAINTS map to APS delegation.spendLimit + expiresAt
// Your VALIDITY maps to APS delegation.notBefore/expiresAt
// Cross-tested: 5/5 delegation narrowing vectors passing
```

### MCP Interceptor (SEP-1763)
```typescript
// validate() — pre-execution policy gate (scope, spend, expiry)
// certify()  — post-execution attestation (what actually ran)
// agree()    — bilateral receipt (both parties sign outcome)
// enforce()  — all three in one atomic call
```

## Quick Start

```bash
npm install agent-passport-system
```

```typescript
import { joinSocialContract, createDelegation, verifyDelegation } from 'agent-passport-system'

// 1. Identity — your agent gets a passport
const agent = joinSocialContract({ name: 'my-agent', mission: '...', owner: 'you', capabilities: ['read', 'write'], platform: 'node', models: ['gpt-4'] })

// 2. Delegation — scoped authority with monotonic narrowing
const delegation = createDelegation({ delegatedBy: principal.publicKey, delegatedTo: agent.keyPair.publicKey, scope: ['read'], spendLimit: 1000, maxDepth: 2, privateKey: principal.privateKey, expiresInHours: 24 })

// 3. Verification — any party can verify
const valid = verifyDelegation(delegation, principal.publicKey)
```

103 modules. 2,180 tests. 125 MCP tools. Apache-2.0.

Build your thing on top. Don't rebuild what's underneath.
