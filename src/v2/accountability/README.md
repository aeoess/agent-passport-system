# Accountability MVP: Wave 1

TypeScript primitives for **attribution-grade accountability** of autonomous
agent actions. Five signed receipts plus one aggregation envelope. Part of
APS v2.5.0-alpha.

- **Spec:** [`specs/full-accountability-mvp.md`](../../../specs/full-accountability-mvp.md)
- **Design principle:** *Verbal confessions, not brain scans.* Every receipt
  declares what it cryptographically asserts and what it does NOT prove.
  Honest scope is mandatory.
- **Frame:** Observability tells the operator what happened. APS receipts
  let affected parties contest what happened.

## What this module ships

| Capability | Function |
|---|---|
| ActionReceipt construction | `createActionReceipt` |
| ActionReceipt verification | `verifyActionReceipt` |
| AuthorityBoundaryReceipt construction | `createAuthorityBoundaryReceipt` |
| AuthorityBoundaryReceipt verification | `verifyAuthorityBoundaryReceipt` |
| CustodyReceipt construction (8 event types, 7 purposes) | `createCustodyReceipt` |
| CustodyReceipt verification | `verifyCustodyReceipt` |
| ContestabilityReceipt construction | `createContestabilityReceipt` |
| Controller-response signing on contestation | `attachControllerResponse` |
| ContestabilityReceipt verification (both signatures) | `verifyContestabilityReceipt` |
| APSBundle aggregation with balanced Merkle commitment | `createAPSBundle` |
| APSBundle verification | `verifyAPSBundle` |
| Merkle root helper (sorted, balanced, sha256) | `computeMerkleRoot` |

All construction routines use RFC 8785 JCS canonicalization and Ed25519
signatures. All receipts are content-addressed (`receipt_id = sha256(jcs(receipt − signature))`).

> **Type-name note**: at the top-level `agent-passport-system` package, the
> new accountability `ActionReceipt` type is re-exported as
> `AccountabilityActionReceipt` to avoid collision with a legacy v1
> `ActionReceipt` interface (commerce-flavored, unrelated). The unaliased
> name `ActionReceipt` is available when importing directly from
> `agent-passport-system/v2/accountability` or from the `v2` index.
> Function names (`createActionReceipt`, `verifyActionReceipt`) are
> unaffected.

## What this module does NOT ship (product intelligence: gateway only)

- Replay engines or decision-equivalence reports
- Transparency-log publishing of receipts (Rekor inclusion is referenced
  in `transparency_log_inclusion`, not generated here)
- Drift detection across receipts or behavioral fingerprints
- Cross-tenant correlation, dashboards, alerting
- Compliance pass/fail report rendering
- Smart-revocation or cascading invalidation across bundles
- Bulk regulator-disclosure preparation

Those belong in the private `@aeoess/gateway` module. The protocol records
evidence; products render judgment.

## Minimal example

```ts
import {
  createActionReceipt,
  verifyActionReceipt,
  createAuthorityBoundaryReceipt,
  verifyAuthorityBoundaryReceipt,
  createAPSBundle,
  verifyAPSBundle,
  generateKeyPair,
} from 'agent-passport-system'

const agentKeys = generateKeyPair()
const gatewayKeys = generateKeyPair()
const bundlerKeys = generateKeyPair()

// 1. Agent emits an action and signs the receipt.
const action = createActionReceipt(
  {
    agent_did: 'did:aps:agent-001',
    delegation_chain_root: 'a'.repeat(64),
    action: {
      kind: 'http_request',
      target: 'https://api.example.com/v1/users',
    },
    side_effect_classes: ['external_message', 'data_modification'],
    scope_of_claim: {
      asserts: 'Agent emitted this HTTP request at this time under this delegation chain.',
      does_not_assert: [
        'That the request succeeded',
        'That the user record was actually modified',
        'That the delegation chain is uncompromised at root',
      ],
      capture_mode: 'self_attested',
      completeness: 'complete',
      self_attested: true,
    },
  },
  agentKeys.privateKeyHex,
)

// 2. Gateway evaluates whether the action was inside delegated authority.
const boundary = createAuthorityBoundaryReceipt(
  {
    action_id: action.receipt_id,
    evaluator_did: 'did:aps:gateway-prod',
    delegation_chain_root: 'a'.repeat(64),
    result: 'inside',
    scope_of_claim: {
      asserts: 'At evaluation time, this action was inside delegated authority.',
      does_not_assert: [
        'That the policy at the gateway allowed this action (separate concern)',
        'That all upstream delegation links are signed by uncompromised keys',
      ],
      capture_mode: 'gateway_observed',
      completeness: 'complete',
      self_attested: false,
    },
  },
  gatewayKeys.privateKeyHex,
)

// 3. Bundle both receipts into an aggregation envelope.
const bundle = createAPSBundle(
  {
    bundler_did: 'did:aps:bundler-prod',
    period_start: '2026-04-30T00:00:00.000Z',
    period_end: '2026-05-01T00:00:00.000Z',
    receipts: [
      { receipt_id: action.receipt_id, claim_type: action.claim_type },
      { receipt_id: boundary.receipt_id, claim_type: boundary.claim_type },
    ],
    profile_conformance: ['aps:profile/mva-v1'],
    scope_of_claim: {
      asserts: 'These two receipts were aggregated by this bundler in this period.',
      does_not_assert: [
        'That all receipts in the period are included (omission undetectable from bundle alone)',
        'That the included receipts are individually valid (verify each separately)',
      ],
      capture_mode: 'gateway_observed',
      completeness: 'partial',
      self_attested: false,
    },
  },
  bundlerKeys.privateKeyHex,
)

// 4. Verify each layer independently. No party trusts another.
console.log(verifyActionReceipt(action))            // { valid: true }
console.log(verifyAuthorityBoundaryReceipt(boundary)) // { valid: true }
console.log(verifyAPSBundle(bundle))                 // { valid: true }
```

## Cross-implementation byte-match commitment

Every receipt type ships with a deterministic JSON fixture in `fixtures/`,
constructed with fixed private keys (hex `'11'`, `'22'`, `'33'`, `'44'`, `'55'`
each repeated 64 times) and a fixed timestamp `'2026-04-30T00:00:00.000Z'`.

Other byte-match implementations (AgentGraph, AgentID, Nobulex, Foxbook,
HiveTrust, ArkForge, msaleme clean-room, etc.) validate against these
fixtures. APS commits to keeping fixtures stable across patch and minor
releases; breakage requires a major version bump.

To run the byte-match check yourself:

```bash
npx tsx --test src/v2/accountability/__tests__/fixtures.test.ts
```

## Scope-of-claim discipline

`scope_of_claim.does_not_assert` is **not optional** and is **not a comment
field**. It is part of the cryptographic integrity surface; modifying it
after signing invalidates the receipt. Every primitive validates that
`does_not_assert` is a non-empty array of non-empty strings.

A receipt that hides its limits is weaker evidence than one that states them.
Honesty is the source of evidentiary weight.

## Conformance profiles

Profiles are documents, not code. They name which subset of primitives is
required for a regulatory or commercial use case. Wave 1 references three
profile drafts in the spec:

- `aps:profile/mva-v1`: Minimum Viable Accountability (Action + AuthorityBoundary + Custody)
- `aps:profile/eu-aiact-art12-v1`: EU AI Act Article 12 record-keeping
- `aps:profile/gdpr-art22-v1`: GDPR Article 22 right to contest

Profiles are referenced from the `profile_conformance` field on `APSBundle`.

## Wave 2 (deferred)

Knowledge Surface Receipt, Disclosure Manifest, Override Receipt. See spec.

## License

Apache 2.0. Copyright 2024-2026 Tymofii Pidlisnyi.
