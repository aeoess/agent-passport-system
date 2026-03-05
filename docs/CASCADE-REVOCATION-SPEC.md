# Cascade Revocation for Agent Identity Protocols

**Version:** 0.1.0
**Author:** Tymofii Pidlisnyi (@aeoess)
**Date:** March 2026
**Status:** Draft Proposal
**Reference Implementation:** [agent-passport-system](https://github.com/aeoess/agent-passport-system) (Apache-2.0)

---

## 1. Problem

When AI agents delegate authority to other agents, revocation must propagate. If Agent A delegates to Agent B, and Agent B sub-delegates to Agent C, revoking A's delegation to B must also invalidate C's authority. Without cascade revocation, revoking a compromised agent leaves its downstream delegations active.

This is not a theoretical concern. In multi-agent systems where agents autonomously sub-delegate to specialists, a single compromised delegation can create an unbounded tree of active permissions that the human principal cannot recall.

No current agent identity protocol specifies how revocation propagates through delegation chains.

## 2. Data Structures

### 2.1 Delegation

```typescript
interface Delegation {
  delegationId: string        // Unique identifier (UUID v4)
  delegatorId: string         // Agent granting authority
  delegateId: string          // Agent receiving authority
  scope: string[]             // Permitted action scopes
  spendLimit?: number         // Maximum spend in delegation currency
  maxDepth: number            // Maximum sub-delegation depth allowed
  currentDepth: number        // Current depth in the chain (0 = root)
  expiresAt: string           // ISO 8601 expiration timestamp
  createdAt: string           // ISO 8601 creation timestamp
  parentDelegationId?: string // ID of parent delegation (null for root)
  revoked: boolean            // Revocation status
  revokedAt?: string          // ISO 8601 revocation timestamp
  revokedReason?: string      // Human-readable revocation reason
  signature: string           // Ed25519 signature by delegator
}
```

### 2.2 Revocation Record

```typescript
interface RevocationRecord {
  delegationId: string        // Delegation being revoked
  revokedBy: string           // Agent performing the revocation
  revokedAt: string           // ISO 8601 timestamp
  reason: string              // Revocation reason
  cascadeCount: number        // Number of downstream delegations also revoked
  signature: string           // Ed25519 signature by revoker
}
```

### 2.3 Chain Registry

The chain registry tracks parent-child relationships between delegations. It MUST be populated at delegation creation time, not reconstructed at revocation time.

```typescript
interface ChainRegistry {
  // Maps delegationId -> list of child delegationIds
  children: Map<string, string[]>
  // Maps delegationId -> parent delegationId
  parents: Map<string, string>
}
```

**Rationale:** Reconstructing the tree at revocation time requires scanning all delegations, which is O(n) in the total number of delegations. The registry makes cascade O(k) where k is the number of descendants.

## 3. Algorithm

### 3.1 Cascade Revocation

When a delegation is revoked, all downstream delegations MUST be revoked synchronously.

```
function cascadeRevoke(delegationId, reason, revokerKey):
  1. Look up delegation in store
  2. If already revoked, return (idempotent, no error)
  3. Mark delegation as revoked (set revoked=true, revokedAt, reason)
  4. Sign revocation record with revokerKey
  5. Get all children from chain registry
  6. For each child:
     a. Recursively call cascadeRevoke(child.delegationId, reason, revokerKey)
  7. Emit revocation event
  8. Return RevocationRecord with cascadeCount
```

**Properties:**
- **Synchronous:** All descendants are revoked in the same operation. No eventual consistency.
- **Deterministic:** Same input always produces the same result.
- **Idempotent:** Revoking an already-revoked delegation is a no-op, not an error.
- **Total:** There is no partial cascade. Either all descendants are revoked or the operation fails atomically.

### 3.2 Batch Revocation by Agent

Revoke all delegations granted TO a specific agent, with cascade.

```
function batchRevokeByAgent(agentId, reason, revokerKey):
  1. Find all delegations where delegateId == agentId
  2. For each delegation:
     a. Call cascadeRevoke(delegation.delegationId, reason, revokerKey)
  3. Return list of RevocationRecords
```

**Use case:** An agent is compromised. The human principal revokes everything granted to that agent. All sub-delegations that agent created also die.

### 3.3 Chain Validation

Before any action is permitted, the entire delegation chain from the acting agent back to the human principal MUST be validated.

```
function validateChain(delegationIds[]):
  1. For each delegation in chain:
     a. If revoked: return {valid: false, error: "revoked link"}
     b. If expired: return {valid: false, error: "expired link"}
     c. If not found in registry: return {valid: false, error: "unknown delegation"}
  2. For each adjacent pair (parent, child):
     a. If parent.delegateId != child.delegatorId: return {valid: false, error: "chain break"}
  3. Return {valid: true}
```

## 4. Sub-delegation Constraints

When an agent sub-delegates, the child delegation MUST be strictly narrower than the parent:

- **Scope:** Child scope MUST be a subset of parent scope. scopeCovers(parentScope, childScope) must be true for every scope in the child.
- **Spend limit:** Child spend limit MUST NOT exceed parent spend limit.
- **Depth:** Child currentDepth MUST equal parent currentDepth + 1. Child currentDepth MUST NOT exceed parent maxDepth.
- **Expiry:** Child expiration MUST NOT exceed parent expiration.

Violation of any constraint MUST cause sub-delegation to fail. This ensures that cascade revocation is always safe: revoking a parent can never leave a child with more authority than the parent had.

## 5. Security Properties

### 5.1 No Orphan Delegations

Every non-root delegation MUST have a traceable parent in the chain registry. If a parent delegation is deleted (not just revoked), all children MUST be cascade-revoked first.

### 5.2 No Double-Revoke Side Effects

Revoking an already-revoked delegation MUST be idempotent. It MUST NOT re-emit events, re-sign records, or increment cascade counts. Implementations SHOULD check revocation status before traversing children.

### 5.3 Revocation is Irreversible

A revoked delegation CANNOT be un-revoked. If the same authority is needed again, a new delegation MUST be created. This prevents time-of-check/time-of-use attacks where a revoked delegation is temporarily reinstated.

### 5.4 Branching Chains

A single delegation MAY have multiple children (Agent A delegates to both Agent B and Agent C). Cascade revocation MUST traverse all branches. The traversal order is not specified, but all branches MUST be revoked before the operation returns.

### 5.5 Event Propagation

Implementations SHOULD support revocation event subscriptions so that dependent systems (task schedulers, commerce gateways, policy engines) can react to revocations in real time.

```typescript
interface RevocationEvent {
  delegationId: string
  cascadeDepth: number        // 0 for the directly revoked delegation
  totalCascaded: number       // Running count of all revoked in this cascade
}
```

## 6. Integration with Policy Engines

Cascade revocation is an identity-layer primitive. Policy engines (such as AIP's AgentPolicy) SHOULD reference delegation chain validity as a precondition for policy evaluation.

Suggested integration pattern:

```
1. Agent presents action request with delegationId
2. Policy engine calls validateChain() on the delegation chain
3. If chain is invalid (any link revoked/expired), deny immediately
4. If chain is valid, proceed to policy evaluation (scope, rate limits, etc.)
```

This ensures that revocation takes effect immediately without requiring policy engines to maintain their own revocation state.

## 7. Adversarial Scenarios

The following attacks MUST be mitigated by any conforming implementation:

| Attack | Mitigation |
|--------|-----------|
| Replay revoked delegation | Chain validation checks revoked flag before any action |
| Sub-delegate after revocation | createReceipt/subDelegate checks delegation validity |
| Scope escalation via sub-delegation | Sub-delegation enforces strict scope narrowing |
| Spend limit escalation | Child spend limit capped at parent spend limit |
| Depth bomb (unbounded sub-delegation) | maxDepth enforced at sub-delegation time |
| Double-revoke event spam | Idempotent revocation, no re-emit on already-revoked |
| Orphan delegation after parent delete | Cascade revocation before deletion |

## 8. Reference Implementation

The Agent Passport System SDK implements this specification:

- **npm:** agent-passport-system (v1.9.2)
- **Source:** [github.com/aeoess/agent-passport-system](https://github.com/aeoess/agent-passport-system)
- **File:** src/core/delegation.ts (~520 lines)
- **Tests:** 276 tests, 73 suites, including 23 adversarial scenarios
- **License:** Apache-2.0

Key functions: cascadeRevoke(), batchRevokeByAgent(), validateChain(), getDescendants(), onRevocation()

---

## Appendix A: Scope Resolution

Cascade revocation depends on correct scope matching for sub-delegation validation. The reference implementation uses a single scopeCovers(granted, required) function:

- Exact match: code covers code
- Hierarchical: code covers code:deploy (parent covers child)
- Universal wildcard: * covers everything
- Prefix wildcard: commerce:* covers commerce and commerce:checkout
- No reverse: code:deploy does NOT cover code

All scope checks across the protocol (delegation, policy evaluation, context enforcement, commerce validation) MUST use the same matching function to prevent inconsistencies.
