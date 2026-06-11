# Agent Passport Protocol v1.1 — Action Receipts & Delegation Revocation

**Status:** DRAFT  
**Author:** aeoess-001 (on behalf of tima)  
**Created:** 2026-02-20  
**Extends:** Agent Passport Protocol v1.0  
**Dependencies:** Ed25519 (existing), no new external dependencies  

---

## Abstract

Agent Passport v1.0 answers: *"What is this agent authorized to do?"*

v1.1 answers: *"What did this agent actually do, and can we stop it?"*

This extension adds three primitives to complete the accountability chain:

1. **Action Receipts** — cryptographic proof of execution
2. **Delegation Revocation** — real-time permission kill switch
3. **Delegation Depth Limits** — controlled sub-delegation chains

All three use the existing Ed25519 key infrastructure. No blockchain. No smart contracts. No new dependencies.

---

## Motivation

v1.0 creates a trust chain: Principal → Agent → Delegated Agent, with scoped
permissions and spend limits. But once a delegation is issued, there is no
standard way to:

- Prove what the agent *actually did* with that delegation
- Revoke the delegation before it expires
- Limit how deep sub-delegation chains can go

Google AP2 (60+ partners) solves this for payments with "Mandates." The DeepMind
authenticated delegation paper calls for "auditable receipts." The EU EUDI Wallet
architecture requires "cryptographically verifiable audit trails."

We solve it at the infrastructure layer — for all agent actions, not just payments.

---

## 1. Action Receipts

An Action Receipt is a signed record created by an agent after executing a
delegated task. It binds the action to the delegation that authorized it.

### 1.1 Schema

```json
{
  "receipt_id": "rcpt_a1b2c3d4e5f6",
  "version": "1.1",
  "timestamp": "2026-02-20T15:30:00Z",
  "agent_id": "agent_abc123",
  "delegation_id": "del_xyz789",
  "action": {
    "type": "api_call",
    "target": "booking-service.example.com",
    "method": "POST /reservations",
    "scope_used": "book_flights",
    "spend": { "amount": 450, "currency": "USD" }
  },
  "result": {
    "status": "success",
    "summary": "Booked LAX→JFK on 2026-03-15, confirmation #BK9921"
  },
  "delegation_chain": ["principal_key_fingerprint", "agent_abc123"],
  "signature": "<Ed25519 signature over all fields above>"
}
```

#### Third-party namespaces

Note that `action.type` is a generic category and specific services appear only as `target` values; this split is normative. Contributor deployments are credited as named targets inside generic categories; they are not granted top-level namespaces. The schema names canonical properties; implementers are targets, not owners. This applies regardless of technical merit.

### 1.2 Signing Rules

- The agent that performed the action MUST sign the receipt with its Ed25519 key
- The `delegation_id` MUST reference a valid, non-revoked delegation
- The `scope_used` MUST fall within the delegation's authorized scopes
- The `spend` MUST NOT exceed the delegation's remaining spend limit
- Receipts are append-only — once signed, they cannot be modified

### 1.3 Verification

Any party holding the agent's public key can verify:
1. The receipt was signed by the claimed agent
2. The delegation chain is valid (trace back to principal)
3. The action was within authorized scope
4. The spend was within limits

### 1.4 Storage

Receipts MAY be stored locally, published to a shared registry, or exchanged
directly between parties. The protocol does not mandate a specific storage
backend — receipts are self-verifying regardless of where they live.

---

## 2. Delegation Revocation

### 2.1 Overview

A delegator MUST be able to revoke a delegation before its `expires_at` time.
This is the kill switch — if an agent misbehaves or a key is compromised,
the delegator can immediately invalidate the permission.

### 2.2 Revocation Record

```json
{
  "revocation_id": "rev_m1n2o3p4",
  "delegation_id": "del_xyz789",
  "revoked_by": "principal_key_fingerprint",
  "revoked_at": "2026-02-20T16:00:00Z",
  "reason": "agent_compromised",
  "signature": "<Ed25519 signature by the original delegator>"
}
```

### 2.3 Rules

- Only the entity that CREATED the delegation can revoke it
- Revocation is signed with the delegator's key (same key that signed the
  original delegation)
- Revocation is immediate — verifiers MUST check revocation status before
  accepting any delegation
- Revoking a delegation at depth N automatically invalidates all
  sub-delegations at depth N+1, N+2, etc (cascade revocation)

### 2.4 Revocation Registry

Verifiers need a way to check if a delegation has been revoked. Two approaches
are supported (implementers choose):

**Option A: Inline Revocation List (lightweight)**
- The delegator publishes a signed list of revoked delegation IDs at a known URL
- Verifiers fetch and cache the list (with TTL)
- No infrastructure dependency

**Option B: Challenge-Response (real-time)**
- Verifier sends a challenge to the delegator's endpoint
- Delegator responds with current delegation status + signature
- Higher latency, but guarantees real-time accuracy

Both options use Ed25519 signatures. No certificate authorities. No blockchain.

---

## 3. Delegation Depth Limits

### 3.1 Overview

v1.0 delegations can be sub-delegated without limit. Agent A delegates to B,
B delegates to C, C delegates to D — each hop adds risk and reduces
accountability clarity.

v1.1 adds a `max_depth` field to delegations.

### 3.2 Schema Extension

```json
{
  "delegation_id": "del_xyz789",
  "delegator": "principal_key_fingerprint",
  "delegate": "agent_abc123",
  "scope": ["book_flights", "search_hotels"],
  "spend_limit": { "amount": 1000, "currency": "USD" },
  "max_depth": 2,
  "current_depth": 0,
  "expires_at": "2026-03-20T00:00:00Z",
  "signature": "<Ed25519 signature>"
}
```

### 3.3 Rules

- `max_depth: 0` means NO sub-delegation allowed (terminal delegation)
- `max_depth: 1` means one hop of sub-delegation permitted
- When sub-delegating, `current_depth` increments by 1
- Sub-delegation MUST be refused if `current_depth >= max_depth`
- Sub-delegations inherit the parent's `max_depth` ceiling — they cannot
  increase it
- Sub-delegation scope MUST be equal to or narrower than parent scope
- Sub-delegation spend limit MUST be equal to or less than parent's remaining

### 3.4 Default

If `max_depth` is omitted, implementations MUST default to `max_depth: 1`
(one level of sub-delegation). This is a safe default that enables basic
agent-to-agent collaboration while preventing unbounded chains.

---

## 4. Implementation Notes

### 4.1 Backward Compatibility

All v1.1 additions are backward-compatible with v1.0:

- Action Receipts are a NEW artifact type — v1.0 deployments simply don't
  generate them. No breaking change.
- Revocation is additive — v1.0 delegations without revocation checking
  continue to work. Verifiers that support v1.1 gain revocation checking.
- `max_depth` defaults to unlimited if absent, preserving v1.0 behavior.
  v1.1 verifiers enforce depth limits when the field is present.

### 4.2 Reference Implementation

The reference implementation extends the existing TypeScript SDK:

```typescript
// Generate an action receipt
const receipt = await passport.createReceipt({
  delegationId: 'del_xyz789',
  action: {
    type: 'api_call',
    target: 'booking-service.example.com',
    method: 'POST /reservations',
    scopeUsed: 'book_flights',
    spend: { amount: 450, currency: 'USD' }
  },
  result: {
    status: 'success',
    summary: 'Booked LAX→JFK, confirmation #BK9921'
  }
});

// Verify a receipt
const valid = await passport.verifyReceipt(receipt);
// Returns: { valid: true, delegationValid: true, scopeValid: true, spendValid: true }

// Revoke a delegation
const revocation = await passport.revokeDelegation({
  delegationId: 'del_xyz789',
  reason: 'agent_compromised'
});

// Check if a delegation is revoked
const status = await passport.checkDelegation('del_xyz789');
// Returns: { valid: true, revoked: false, depth: 0, maxDepth: 2 }

// Create a depth-limited delegation
const delegation = await passport.delegate({
  to: 'agent_def456',
  scope: ['search_hotels'],
  spendLimit: { amount: 200, currency: 'USD' },
  maxDepth: 1,  // Can sub-delegate once more
  expiresIn: '24h'
});
```

### 4.3 Alignment with Industry Standards

| Feature | Agent Passport v1.1 | Google AP2 | DeepMind Auth. Delegation | EU EUDI |
|---------|---------------------|------------|---------------------------|---------|
| Signed receipts | ✅ Action Receipts | ✅ Mandates | ✅ Auditable receipts | ✅ Verifiable logs |
| Revocation | ✅ Inline + Challenge | ✅ Via credential provider | ✅ Implied | ✅ Revocation registries |
| Depth limits | ✅ max_depth field | ❌ Single-hop only | ✅ Cascading scopes | ✅ Multi-hop delegation |
| Crypto primitive | Ed25519 | W3C VC / JWS | OAuth 2.0 + extensions | eIDAS qualified sigs |
| Scope | All agent actions | Payments only | Auth flows | Identity + credentials |
| Dependencies | None (self-contained) | W3C, OAuth ecosystem | OAuth 2.0, OIDC | EU trust services |

### 4.4 What This Does NOT Cover

- **Legal liability assignment** — this protocol provides the cryptographic
  evidence. Courts and contracts determine liability. Not our layer.
- **Payment processing** — use AP2 or similar for financial transactions.
  Action Receipts prove what happened; payment protocols move money.
- **Smart contracts** — not needed. Ed25519 signatures are sufficient for
  non-repudiable proof. Adding blockchain adds latency, cost, and
  dependency without improving the cryptographic guarantees.

---

## 5. Security Considerations

- **Receipt forgery:** Impossible without the agent's private key. Ed25519
  signatures are computationally infeasible to forge.
- **Replay attacks:** Receipt IDs are unique. Verifiers MUST reject duplicate
  receipt IDs.
- **Revocation race conditions:** Between revocation publication and verifier
  cache refresh, a revoked delegation might briefly appear valid. The inline
  revocation list TTL SHOULD be ≤ 60 seconds for high-security contexts.
- **Depth bypass:** Agents MUST NOT accept delegations where
  `current_depth >= max_depth`. Verifiers MUST independently verify depth.

---

## License

Apache 2.0 — same as Agent Passport v1.0
