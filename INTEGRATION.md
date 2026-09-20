# Building on APS: Integration Guide

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
- **AgentID**: 7/7 cross-protocol tests passing (compound digest, action_ref, constraint mapping, receipt interop, Ed25519 dual signing, context continuity, daemon agents)
- **MolTrust AAE**: 5/5 delegation narrowing vectors passing (scope subset, temporal narrowing, self-issuance, spend limits, expired credentials)
- **Kanoniv**: delegation chain signatures cross-verified (Python ↔ TypeScript)

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
// The attestation schema is standardized: any anchor backend works
```

### Spend Enforcement (AgentPay)
You handle payment rails. APS handles delegation-scoped spend limits.
```typescript
import { createDelegation } from 'agent-passport-system'
// Delegation includes spendLimit: authority to spend up to $X
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
// validate(): pre-execution policy gate (scope, spend, expiry)
// certify() : post-execution attestation (what actually ran)
// agree()   : bilateral receipt (both parties sign outcome)
// enforce() : all three in one atomic call
```

## Quick Start

```bash
npm install agent-passport-system
```

```typescript
import { joinSocialContract, createDelegation, verifyDelegation } from 'agent-passport-system'

// 1. Identity: your agent gets a passport
const agent = joinSocialContract({ name: 'my-agent', mission: '...', owner: 'you', capabilities: ['read', 'write'], platform: 'node', models: ['gpt-4'] })

// 2. Delegation: scoped authority with monotonic narrowing
const delegation = createDelegation({ delegatedBy: principal.publicKey, delegatedTo: agent.keyPair.publicKey, scope: ['read'], spendLimit: 1000, maxDepth: 2, privateKey: principal.privateKey, expiresInHours: 24 })

// 3. Verification: any party can verify
const valid = verifyDelegation(delegation, principal.publicKey)
```

Apache-2.0.

Build your thing on top. Don't rebuild what's underneath.

### Physical-World Enforcement (SINT Protocol)
You handle digital-world constraints. SINT handles physical-world enforcement.
```typescript
import { apsScopeToSintMapping, sintTokenToApsProjection } from '@sint/bridge-a2a'

// APS delegation → SINT capability token (with physical constraints)
const mapping = apsScopeToSintMapping(delegation.scope, delegation.spendLimit)
// mapping.resource: "ros2:///cmd_vel" | "mcp://filesystem/writeFile" | ...
// mapping.physicalConstraints: { maxVelocityMps, maxForceNewtons, geofence }
// mapping.tierDelta: 0 | +1 (attestationGrade < 2 raises effective tier)

// SINT capability token → APS attestation projection
const projection = sintTokenToApsProjection(sintToken)
// projection.attestationGrade: 2 (always: physical constraints imply strong verification)
// projection.dataAccessTerms: { "sint:maxVelocityMps": 0.5, "sint:geofence": {...} }
```

**Cross-verified: 9/9 tests passing, zero code changes on either side.**

```
SINT keyToDid(pubkeyHex) === motebit publicKeyToDidKey(pubkeyBytes)  // did:key:z6Mk...
SINT keyToDid(pubkeyHex) === APS toDIDKey(publicKey)                 // did:key:z6Mk...
```

The physical constraint layer is the dimension missing from all other integrations. Force limits, velocity caps, and geofence boundaries follow the same monotonic narrowing invariant as digital scope: they can tighten at each delegation hop, never loosen. An APS delegation with `spendLimit: 5000` delegating to a SINT robot token automatically constrains the robot to the narrowed physical envelope.

See: [`packages/bridge-a2a/src/aps-mapping.ts`](https://github.com/sint-ai/sint-protocol/tree/main/packages/bridge-a2a/src/aps-mapping.ts), 38 tests
See: [`packages/capability-tokens/__tests__/aps-crossverify.test.ts`](https://github.com/sint-ai/sint-protocol/tree/main/packages/capability-tokens/__tests__/aps-crossverify.test.ts), 9 tests

### Exact-Call Execution Evidence (PriorSeal)
You handle the authorization and execution evidence for one exact EVM call. APS handles the policy decision that call was admitted under.

This is a sibling adapter. It lives in the PriorSeal repository and is maintained there, with two separate trust roots. It imports only the `agent-passport-system@6.0.1` package root.

```typescript
import {
  verifyReceiptV1Serialized,
  verifyReceiptWithDecisionV1,
  verifyAuthorityDelegationChain,
} from 'agent-passport-system'

// 1. Verify the aps:policy-decision:v1 receipt from its serialized bytes, then
//    verify that its decision_ref binds the supplied DecisionEvidenceV1.
// 2. Check currency at a fixed reference time. The composite verifier only
//    establishes valid_until > issued_at, so this check belongs to the adapter.
// 3. Verify the delegation chain against a separately pinned principal key.
// 4. Carry decision_ref as an opaque context commitment inside a
//    principal-signed PriorSeal exact-call authorization.
```

The APS side is a committed input set: `permit`, `narrow`, `deny` and `expired`, each an action-intent receipt, a policy-decision receipt and its decision evidence, built at the v6.0.1 tag. In 6.0.1 a `deny` binds and still returns `valid: false`, and `expired` returns `valid: true` and fails only the adapter's reference time check. Both stop before the authorization callback.

What the composition claims: an execution correlated to a principal-signed authorization and to an APS decision. What it does not claim: single use of a decision, live revocation state, currency of the APS decision at chain time, or an independently observed chain execution. `action_ref` is not recomputed, because 6.0.1 does not export that function from the package root. All keys and executions are test material.

Checked on 2026-09-20 at PriorSeal `a9288dc2`: the APS inputs there are byte-identical to APS commit `948f99b8`, the unmodified APS consumer script passes, and the adapter suite passes 24 of 24.

See: [`fixtures/priorseal-decision-binding`](https://github.com/aeoess/agent-passport-system/tree/948f99b85343bef2c6fa677c8543965caacfc087/fixtures/priorseal-decision-binding), the APS inputs
See: [`examples/aps-priorseal-decision-binding-v1`](https://github.com/imokokok/PriorSeal/tree/a9288dc22eff0804492112c7319d9b8510001e02/examples/aps-priorseal-decision-binding-v1), the adapter, its tests and run report
