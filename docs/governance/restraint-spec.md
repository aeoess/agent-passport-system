# Restraint Spec — Refusal Capability Layer

This document declares which SDK module implements the structured
refusal capability that `agent-governance-check@1.0.0` looks for under
"Can your agent refuse?". The goal is FOUND against an enforced policy
engine, not PARTIAL against a `must.?not` string in CLAUDE.md.

## What the layer provides

In APS, refusal is not advisory. The policy engine is a gate that
sits between the agent and every action. The agent does not get to
decide whether to honor a refusal — refusal is the policy engine's
job, and the agent never sees the action go through if the engine
denies it. Three properties matter:

- **Fail-closed.** Unknown verdicts deny. Validator errors deny. The
  default is refusal, not permission.
- **Cryptographic.** Every refusal is a signed `PolicyDecision` with
  a verdict, a reason, and an evaluation method. A third party can
  verify offline that the gateway actually refused.
- **Pre-execution.** Refusal happens before the agent reaches the
  tool, not after. The 3-signature chain (intent → decision →
  receipt) makes "the agent did the thing anyway" impossible to
  forge: there is no signed receipt for a denied decision.

## Module

### `src/core/policy.ts` — policy engine and refusal protocol

Source: [`src/core/policy.ts`](../../src/core/policy.ts)
Tests: [`tests/policy.test.ts`](../../tests/policy.test.ts), [`tests/intent.test.ts`](../../tests/intent.test.ts), [`tests/policy-conflict.test.ts`](../../tests/policy-conflict.test.ts)

The policy engine implements the refusal capability through a small
set of signed object types and a validator interface that the
gateway invokes on every action.

Canonical types and functions exported from `src/core/policy.ts`:

- `createActionIntent(opts)` → `ActionIntent` — the agent's
  signature 1 of 3, declaring what it intends to do BEFORE doing it.
  An intent without a paired evaluation cannot produce an executed
  action.
- `verifyActionIntent(intent)` — verifies the intent signature and
  required fields. Used at the policy engine boundary to refuse
  malformed or unsigned intents.
- `evaluateIntent(opts)` → `PolicyDecision` — runs the configured
  `PolicyValidator` and produces signature 2 of 3. The verdict is
  one of `'permit' | 'deny'` and is signed by the evaluator's key,
  not the agent's. Tests:
  [`tests/policy.test.ts`](../../tests/policy.test.ts).
- `verifyPolicyDecision(decision)` — verifies the decision
  signature, expiry, and that the decision links to a real intent.
- `createPolicyReceipt(opts)` → `PolicyReceipt` — signature 3 of 3.
  Refuses to construct a receipt for a denied decision: `if
  (decision.verdict === 'deny') throw`. There is structurally no
  way to create a receipt that contradicts the refusal.
- `verifyPolicyReceipt(receipt, key)` — verifies the full chain.
- `FloorValidatorV1` — the reference validator. Implements the
  Values Floor (8 principles) and the standard delegation,
  expiration, scope, and revocation checks. Fail-closed by
  construction: any predicate the validator cannot evaluate denies.
- `requestAction(opts)` — convenience wrapper that runs the full
  3-signature chain. Returns `{ permitted: false, reason }` on
  refusal, never a partial result.
- `computeCompoundDigest(opts)` — content-addressable identity for
  the entire decision so that two evaluators of the same intent
  produce the same digest, enabling cross-engine verdict comparison.
- `detectRoutingDivergence(opts)` — refuses an action if the
  routing context observed at execution diverges from the routing
  context declared in the intent. Closes the "approve A, execute B"
  attack window.

### Policy chain (append-only constraint history)

The same module exports the policy chain types that record every
decision in an append-only chain. This is what makes refusal
auditable across time:

- `PolicyChain`, `PolicyChainEntry`, `PolicyConstraintSnapshot`
- `createPolicyChain(agentId)` and `appendPolicyChainEntry(...)` —
  every decision is appended to the agent's chain with the
  constraint snapshot at the moment of evaluation.
- `verifyPolicyChain(chain)` — verifies the entire chain end to end.
- `detectConstraintDrift(chain)` — surfaces cases where the
  constraints under which the agent operates have weakened over time.
  This is the input the drift monitoring layer reads.

## What the agent must refuse

The protocol enforces refusal in these cases (all of them produce a
denied `PolicyDecision`, which `createPolicyReceipt` then refuses to
turn into a receipt):

1. **Scope outside the delegation.** `FloorValidatorV1` checks the
   intent's `actionType` and `scopeRequired` against the active
   delegation's `scope` array using `scopeAuthorizes()`. Anything
   outside the delegated scope denies. Tests:
   `tests/policy.test.ts → "denies action outside delegated scope"`.

2. **Spend over the cap.** Cumulative `spentAmount` plus the
   intent's `spend` is checked against `spendLimit`. Over-cap
   denies. Tests:
   `tests/policy.test.ts → "spend limit denial path"`.

3. **Expired or revoked delegation.** The validator checks
   `expiresAt`, `notBefore`, and the gateway revocation registry.
   Any of these denies. Tests:
   `tests/cascade.test.ts → "cascade revocation triggers denial"`.

4. **Floor violation.** A failed floor principle (F-001 through
   F-008) denies. Tests: `tests/values.test.ts`.

5. **Routing divergence.** `detectRoutingDivergence` denies when the
   captured routing context at execution does not match the routing
   context the intent declared.

6. **Policy conflict.** `tests/policy-conflict.test.ts` covers DFS
   cycle detection on policy dependency graphs. A circular policy
   that cannot resolve denies — fail-closed, never permit.

7. **Validator errors.** Any thrown error inside the validator is
   treated as a deny verdict, not propagated to the caller as a
   permit. The fail-closed default is structural: there is no code
   path in `evaluateIntent` that returns `permit` without a clean
   evaluator result.

## Refusal categories (red lines)

These are the categories the protocol treats as non-negotiable
refusals, mapped to the enforcement primitive that implements them:

| Category                              | Enforcement primitive                      |
|---------------------------------------|--------------------------------------------|
| Acting outside delegated scope        | `scopeAuthorizes` (delegation.ts)          |
| Acting after delegation revocation    | gateway revocation recheck                 |
| Acting after delegation expiry        | `verifyDelegation.expired`                 |
| Spending over the cumulative cap      | spend gate in `FloorValidatorV1`           |
| Acting under a forged intent          | `verifyActionIntent`                       |
| Acting against a denied decision      | `createPolicyReceipt` throws on `deny`     |
| Acting on a circular policy graph     | `policy-conflict` cycle detection          |
| Acting after routing diverged         | `detectRoutingDivergence`                  |
| Acting on a credential whose check    | v2 `evaluateCredentialCheck` denial codes  |
| policy says "no live state"           |                                            |

## Runnable example

```typescript
import {
  createDelegation, createActionIntent, evaluateIntent,
  createPolicyReceipt, FloorValidatorV1, loadFloor,
  generateKeyPair,
} from 'agent-passport-system'

const principal = generateKeyPair()
const agent = generateKeyPair()
const evaluator = generateKeyPair()

// 1. A narrowly scoped delegation: read-only research, $0 spend
const delegation = createDelegation({
  delegatedTo: agent.publicKey,
  delegatedBy: principal.publicKey,
  scope: ['research:read'],
  spendLimit: 0,
  expiresInHours: 1,
  privateKey: principal.privateKey,
})

const validator = new FloorValidatorV1({
  floor: loadFloor('values/floor.yaml'),
  delegations: [delegation],
})

// 2. Intent OUTSIDE the delegated scope
const intent = createActionIntent({
  agentId: 'agent-1',
  agentPublicKey: agent.publicKey,
  agentPrivateKey: agent.privateKey,
  action: {
    type: 'commerce:checkout',     // not in scope
    scopeRequired: 'commerce:checkout',
    target: 'https://shop.example/checkout',
  },
  spend: { amount: 5000, currency: 'usd' },
})

// 3. The policy engine refuses
const decision = evaluateIntent({
  intent,
  validator,
  validationContext: { floorVersion: '1.2.0', delegation },
  evaluatorId: 'gateway',
  evaluatorPublicKey: evaluator.publicKey,
  evaluatorPrivateKey: evaluator.privateKey,
})

console.log(decision.verdict)  // 'deny'
console.log(decision.reason)   // 'No valid delegation covers scope "commerce:checkout"'

// 4. The protocol refuses to manufacture a receipt for a denied decision.
//    There is no code path that produces a signed receipt here.
try {
  createPolicyReceipt({
    intent,
    decision,
    receipt: { /* would need to exist */ } as any,
    verifierPrivateKey: evaluator.privateKey,
  })
} catch (e: any) {
  console.log('Refused:', e.message)  // "Cannot create receipt for denied intent"
}
```

The agent does not need to be cooperative for refusal to work. The
chain it would need to forge — a permit verdict signed by the
evaluator's private key and a receipt signed by the executor's
private key — is structurally unavailable to it.

This is the difference between "the agent has been told not to" and
"the agent cannot." Restraint is a property of the protocol, not of
the agent's restraint.
