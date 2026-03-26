# CONSILIUM BRIEF: Persistence & Storage Layer for Agent Passport System

**Date:** March 26, 2026
**Author:** Claude (Operator/Architect) for Tima Pidlisnyi
**Status:** OPEN FOR MULTI-MODEL REVIEW
**Priority:** CRITICAL — blocks production deployment

---

## 1. THE PROBLEM

APS has 69 modules, 1445 tests, 4 WG-ratified specs, and an integration test harness proving the stack works end-to-end. But every piece of state — delegations, revocations, receipts, reputation scores, agent registrations, replay nonces — lives in JavaScript Maps and Arrays inside a running process. Restart = total amnesia.

This means:
- No production deployment is possible
- The integration test harness works but proves nothing about durability
- A revoked agent regains access after a gateway restart
- Receipts (the entire audit trail) vanish on process exit
- Reputation earned over months disappears instantly
- Replay protection nonces reset, allowing replay attacks after restart

**This is not a nice-to-have. This is the difference between a protocol demo and a deployable system.**

---

## 2. WHAT NEEDS TO BE PERSISTED

### 2.1 Gateway State (ProxyGateway)

| Data | Current Storage | Volume | Access Pattern | Criticality |
|------|----------------|--------|----------------|-------------|
| Agent registrations (passport + attestation + delegations) | Map<agentId, AgentRecord> | 10s-1000s | Read on every request | HIGH |
| Revocation records | Map<delegationId, RevocationRecord> | Grows monotonically | Read on every request (recheck) | CRITICAL |
| Replay nonces | Map<requestId, timestamp> | High volume, TTL-prunable | Write every request, read every request | HIGH |
| Cumulative spend per delegation | tracked in delegation copy | Per-delegation counter | Read+write every spend request | HIGH |
| Approval states (2-phase) | Map<approvalId, Approval> | Short-lived (TTL) | Write on approve, read+delete on execute | MEDIUM |

### 2.2 Receipt Ledger

| Data | Current Storage | Volume | Access Pattern | Criticality |
|------|----------------|--------|----------------|-------------|
| ActionReceipts | Array (append-only) | Grows forever | Append on every execution, query for audit/reputation | CRITICAL |
| Merkle commitments | Computed on demand | Per-batch | Compute periodically, verify on demand | HIGH |
| Chain hash continuity | In receipt objects | Per-receipt | Append, verify sequential integrity | CRITICAL |

### 2.3 Reputation State

| Data | Current Storage | Volume | Access Pattern | Criticality |
|------|----------------|--------|----------------|-------------|
| ScopedReputation (mu, sigma per agent per scope) | Created ad-hoc in tests | Agents × scopes | Read on every tier check, write after every task | HIGH |
| Demotion records | Not persisted | Grows monotonically | Read on every promotion check | HIGH |
| Promotion history | Not persisted | Per-promotion event | Read on promotion, audit | MEDIUM |
| Scarring counter | Implicit in demotion count | Per-agent | Read on every promotion | HIGH |

### 2.4 Delegation Store

| Data | Current Storage | Volume | Access Pattern | Criticality |
|------|----------------|--------|----------------|-------------|
| Active delegations | Module-level Map in delegation.ts | 10s-1000s | Read on every gateway check | CRITICAL |
| Delegation chains (parent refs) | In delegation objects | Per-delegation | Walk chain for authority verification | HIGH |
| Expired delegations | Removed on check | Historical | Query for audit | LOW |

### 2.5 Identity & Keys

| Data | Current Storage | Volume | Access Pattern | Criticality |
|------|----------------|--------|----------------|-------------|
| Key rotation proofs | Not persisted | Per-rotation event | Verify identity continuity | HIGH |
| Principal-agent endorsements | In-memory | Per-endorsement | Verify principal binding | HIGH |
| DID documents | Computed from public key | Per-agent | Resolve on demand | MEDIUM |

---

## 3. THE HARD PROBLEMS

### 3.1 Revocation Propagation (Hardest)

**The scenario:** Principal Alice delegates to Agent X. Agent X is registered on Gateway A, Gateway B, and Gateway C (different services). Alice revokes Agent X's delegation on Gateway A. Gateways B and C don't know.

**Why this is hard:**
- Gateways are independent processes, potentially on different machines, different organizations
- There's no central authority to push revocations to (by design — we're not building a blockchain)
- Polling introduces latency — how long is acceptable? 1 second? 1 minute? 1 hour?
- During the propagation window, a revoked agent can still act on uninformed gateways
- A malicious agent that knows it's about to be revoked will race to act on every gateway before propagation reaches them

**Options we see:**

| Approach | Latency | Complexity | Trust Model |
|----------|---------|------------|-------------|
| Principal pushes to all known gateways | Low (seconds) | Principal must track all gateways | Principal must know every gateway |
| Gateways poll principal's revocation list | Variable (depends on poll interval) | Simple | Principal hosts a revocation endpoint |
| Shared database (Postgres, Redis) | Very low | High infra | All gateways trust the DB operator |
| Gossip/broadcast protocol between gateways | Low-medium | Very high | Gateways must discover each other |
| Revocation embedded in DID document | Low (DID resolution) | Medium | DID infrastructure must be reliable |
| Accept the window and bound it | N/A | Low | Honest about the limitation |

**Open questions:**
- Is there a revocation model from TLS/PKI (CRL, OCSP) that maps to this?
- Should revocations be a signed object that gateways can forward to each other?
- Can the delegation itself carry a "check-back URL" that gateways must poll before honoring?
- What's the acceptable revocation propagation window? Is this a per-delegation parameter?
- Should high-value delegations require real-time revocation checking (call home every time) while low-value ones accept eventual consistency?
- What happens to in-flight multi-step operations when a revocation lands mid-execution?

### 3.2 Receipt Durability & Tamper Evidence

**The scenario:** Gateway produces receipts. Gateway's disk fails. All receipts are lost. An agent claims "I never did that" and there's no evidence.

**Why this is hard:**
- Receipts are the entire audit trail — if they're gone, the governance story collapses
- Storing receipts only at the gateway creates a single point of failure
- Distributing receipts to multiple parties (principal, agent, third-party auditor) increases attack surface
- The receipt chain has hash continuity — a gap in the chain is detectable but not recoverable
- Who is responsible for receipt backup? The gateway operator? The principal? A third party?

**Open questions:**
- Should receipts be streamed to an external append-only store (S3, IPFS, a ledger)?
- Should the principal receive a copy of every receipt in real-time?
- If a receipt is lost, can it be reconstructed from the agent's and principal's partial records?
- Should the protocol define a "receipt escrow" service?
- How do you prove a receipt was NOT produced (omission detection) without a complete chain?
- What's the legal status of a gateway-signed receipt? Is it evidence in court?

### 3.3 Schema Evolution & Migration

**The scenario:** SDK v1.24.0 defines ActionReceipt with 8 fields. v1.25.0 adds a 9th field. A gateway has 10,000 receipts in the old format.

**Why this is hard:**
- Once data is persisted, the schema is a contract with existing deployments
- Adding fields is easy (nullable). Removing or renaming fields breaks existing data.
- The SDK is open-source — we can't force all deployments to migrate simultaneously
- Receipts are cryptographically signed — changing the schema changes the signature input
- Migration must be atomic (no half-migrated states) for signed data

**Open questions:**
- Should receipts carry a schema version so verifiers know which format was used?
- How do we handle signature verification across schema versions?
- Should the persistence layer handle migrations, or should we version the storage format separately from the protocol format?
- What's our backwards compatibility policy? How many versions back do we support?
- Do we need a canonical schema registry?

### 3.4 Multi-Gateway Consistency

**The scenario:** Agent X has $200 spend limit. It spends $150 on Gateway A and $100 on Gateway B. Total: $250. Neither gateway knows about the other's spend.

**Why this is hard:**
- Each gateway independently tracks cumulative spend against the delegation
- Without cross-gateway communication, spend limits are per-gateway, not per-delegation
- This is equivalent to the double-spend problem in cryptocurrency
- Solving it requires either: shared state, a coordinator, or partitioning delegations per gateway

**Options:**
- **Partition:** Each delegation is bound to exactly one gateway. Agent must request separate delegations for each service.
- **Coordinator:** A spend-tracking service that all gateways check before authorizing spend
- **Post-hoc reconciliation:** Gateways periodically share spend data and flag overruns retroactively
- **Delegation-embedded gateway binding:** The delegation itself names which gateway may honor it

**Open questions:**
- Is the single-gateway-per-delegation model acceptable for v1?
- If a delegation is gateway-bound, how does the agent operate across services?
- Should delegations support "sub-budgets" that can be assigned to different gateways?
- Is this actually a problem in practice? How common is multi-gateway deployment in the near term?
- Does the double-spend problem matter at the scale we're operating at (10s of agents, not millions)?

### 3.5 Performance Under Load

**The scenario:** A gateway processes 1000 requests/second. Each request requires: signature verification, delegation lookup, scope check, revocation check, spend check, tool execution, receipt generation, receipt signing, receipt storage.

**Why this is hard:**
- SQLite write throughput is ~50-100 writes/second on a single file (WAL mode helps but has limits)
- Ed25519 signature verification is fast (~15,000/sec in pure JS) but not free
- Receipt storage is append-only but grows without bound
- Replay nonce checking against a growing set gets slower over time
- Revocation checking against a growing revocation list

**Open questions:**
- What's the target throughput for v1? 10 req/s? 100? 1000?
- Should replay nonces be TTL-pruned in the database as they are in memory?
- Should receipts be written asynchronously (after response) or synchronously (before response)?
- Is SQLite sufficient or do we need Postgres from the start?
- Should there be a read-replica pattern for high-query workloads?
- What indexes are needed? (agentId, delegationId, timestamp, scope)

### 3.6 Encryption at Rest

**The scenario:** Gateway's SQLite database contains every delegation, every receipt, every agent's public key, and cumulative behavior patterns. Someone exfiltrates the database file.

**Why this is hard:**
- Delegation scopes reveal what agents are authorized to do (attack surface map)
- Receipt history reveals behavior patterns (predictable → exploitable)
- Reputation data reveals which agents are trusted (high-value targets)
- Agent registration data reveals the entire network topology

**Open questions:**
- Should the SQLite database be encrypted at rest? (SQLCipher?)
- Should individual fields be encrypted, or the whole database?
- Who holds the encryption key? The gateway operator? A KMS?
- Should receipts stored externally (backups, auditors) be encrypted differently?
- What's the threat model? Insider attack? Server compromise? Physical theft?
- Does GDPR apply to agent data? Can an agent request deletion of its records?

### 3.7 Disaster Recovery

**The scenario:** Gateway database is corrupted. Backup is 24 hours old. 24 hours of receipts, delegations, and reputation updates are lost.

**Open questions:**
- What's the recovery point objective (RPO) — how much data loss is acceptable?
- Should the gateway stream a write-ahead log to a remote store?
- Can receipts be reconstructed from agent/principal copies?
- Should there be a "receipt reconciliation" protocol where parties compare their records?
- How do you restart a gateway and re-establish the revocation state?
- What if the gateway's signing key is compromised? Are all its historical receipts now suspect?

### 3.8 Garbage Collection & Data Lifecycle

**The scenario:** An agent's delegation expired 6 months ago. Its 50,000 receipts are still in the database. The agent will never act again.

**Open questions:**
- When can data be safely deleted?
- Should expired delegations be archived rather than deleted (for historical audit)?
- Should receipts have a retention policy? (Module 42 defines data lifecycle, but for agent data not receipt data)
- How do you compact the receipt chain without breaking hash continuity?
- Should there be a "tombstone" mechanism — mark as deleted but keep the hash for chain integrity?
- What's the long-term storage cost trajectory? Is this sustainable at scale?

---

## 4. RISKS WE CAN ASSESS

### 4.1 Protocol vs Product Boundary Risk
If we put too much in the open SDK, we give away the private gateway product. If we put too little, the open SDK is unusable and no one adopts.

**Proposed line:** SQLite single-file backend in the open SDK (minimal, works, single-process). Multi-gateway sync, analytics, revocation propagation, compliance reporting → private gateway only.

**Risk:** Someone forks the SDK and builds the multi-gateway layer on top. Apache 2.0 allows this.
**Counter-risk:** If the open SDK doesn't persist at all, no one deploys it, no one adopts the protocol, and the private gateway has no market.

### 4.2 Premature Optimization Risk
We build a complex persistence layer for a protocol that has ~9,000 npm downloads and 0 production deployments. The schema changes, and we're stuck migrating a database no one uses.

### 4.3 Security Surface Expansion
Every persistence mechanism is an attack surface. SQLite files can be tampered with. Database connections can be intercepted. Backup files can be exfiltrated. In-memory state is actually MORE secure against external access (you'd need process memory access).

### 4.4 Operational Complexity
The SDK today is "npm install and go." Adding SQLite means native dependencies (better-sqlite3), database files on disk, migration scripts, backup procedures. This raises the barrier to entry.

### 4.5 Data Sovereignty
Who owns the data in the gateway? The gateway operator? The principal? The agent? If a principal says "delete all my agent's data" under GDPR, can you comply while maintaining receipt chain integrity?

---

## 5. WHAT WE THINK WE SHOULD BUILD (v1)

### Phase 1: SQLite StorageBackend in the open SDK

**Scope:** Single-file SQLite database. Persists all gateway state. Survives restarts. Single-process only.

**Tables:**
```
agents          — passport, attestation, registration metadata
delegations     — full delegation objects, status (active/revoked/expired)
revocations     — revocation records with signatures
receipts        — append-only action receipts with chain hash
reputation      — scoped reputation (mu, sigma, receiptCount per agent per scope)
replay_nonces   — requestId + timestamp, TTL-pruned
approvals       — 2-phase approval states, TTL-pruned
key_rotations   — key rotation proof chain
demotions       — demotion records (permanent, never deleted)
```

**What this solves:**
- Gateway survives restarts ✅
- Receipts persist ✅
- Revocations survive restarts ✅
- Reputation accumulates across sessions ✅
- Replay protection survives restarts ✅

**What this does NOT solve:**
- Multi-gateway spend tracking ❌
- Revocation propagation across gateways ❌
- Receipt replication/backup ❌
- High-throughput (>100 req/s) scenarios ❌
- Multi-process access ❌

### Phase 2: Private gateway product (later)

- Postgres backend for multi-process
- Revocation propagation (push + poll hybrid)
- Receipt streaming to external store
- Cross-gateway spend coordination
- Analytics and compliance reporting
- Encryption at rest

---

## 6. INTERFACE DESIGN QUESTION

The `StorageBackend` interface needs to be right the first time because it's the contract between the open protocol and any persistence implementation.

```typescript
interface StorageBackend {
  // Agents
  registerAgent(agentId: string, data: AgentRecord): Promise<void>
  getAgent(agentId: string): Promise<AgentRecord | null>
  
  // Delegations
  storeDelegation(delegation: Delegation): Promise<void>
  getDelegation(delegationId: string): Promise<Delegation | null>
  getDelegationsForAgent(agentId: string): Promise<Delegation[]>
  updateDelegationSpend(delegationId: string, amount: number): Promise<void>
  
  // Revocations
  storeRevocation(revocation: RevocationRecord): Promise<void>
  isRevoked(delegationId: string): Promise<boolean>
  getRevocationsBy(revokedBy: string): Promise<RevocationRecord[]>
  
  // Receipts
  appendReceipt(receipt: ActionReceipt): Promise<void>
  getReceipts(filter: ReceiptFilter): Promise<ActionReceipt[]>
  getReceiptCount(agentId: string, scope?: string): Promise<number>
  
  // Reputation
  getReputation(agentId: string, scope: string): Promise<ScopedReputation | null>
  updateReputation(rep: ScopedReputation): Promise<void>
  
  // Replay protection
  checkAndStoreNonce(requestId: string, ttlSeconds: number): Promise<boolean>
  pruneExpiredNonces(): Promise<number>
  
  // Demotions
  storeDemotion(demotion: DemotionRecord): Promise<void>
  getDemotionCount(agentId: string): Promise<number>
}
```

**Open questions about the interface:**
- Is this too granular? Too coarse?
- Should there be batch operations (storeDelegations plural)?
- Should queries support pagination?
- Should there be a transaction wrapper for atomic multi-table operations?
- Should the interface include migration/versioning methods?
- Should there be an event/callback system (onRevocation, onReceipt) for real-time propagation?

---

## 7. THINGS WE MIGHT NOT BE SEEING

This section is deliberately open-ended. Other models in the consilium should challenge, extend, or contradict anything above.

### 7.1 Threat models we haven't considered
- What if the gateway operator is the adversary? (Insider threat — they control the storage, they can modify receipts before writing them)
- What if two principals issue conflicting delegations to the same agent on different gateways?
- What if an agent deliberately triggers high-volume requests to overflow the receipt store (DoS via audit)?
- What about timing attacks — can an adversary infer delegation scopes by observing gateway response latency patterns?
- What about state rollback attacks — restore an old database snapshot to "un-revoke" a delegation?

### 7.2 Architectural alternatives we haven't explored
- Should the persistence layer be outside the SDK entirely? (Gateway hosts storage, SDK just defines the interface)
- Is SQLite the right choice? What about LevelDB, LMDB, or DuckDB?
- Should receipts use a different storage engine than delegations? (Append-only log vs relational)
- Should the StorageBackend be async by default or support both sync and async?
- Is there a case for an embedded key-value store instead of a relational model?
- Could the persistence layer be a separate npm package (agent-passport-storage-sqlite) to keep the core SDK dependency-free?

### 7.3 Human and organizational factors
- Who trains gateway operators to manage the database?
- What happens when a startup using APS shuts down? Their gateway database has receipts that other parties might need.
- Should there be a "receipt portability" standard — export all your receipts in a format that any gateway can import?
- What's the liability model? If a gateway loses receipts due to disk failure, who is responsible?
- How do you audit a gateway operator? Can an independent auditor verify the receipt chain without accessing the raw database?

### 7.4 Scale and economic questions
- At what agent count does SQLite become a bottleneck?
- What's the storage cost per agent-year? (Estimate: N receipts/day × receipt size × 365)
- Should there be a receipt pruning/archival tier for cost management?
- Is there a SaaS model where we host the persistence layer? (Gateway-as-a-Service)
- How does this interact with the "Pixel for agents" data governance product vision?

### 7.5 Interoperability with the WG stack
- Should the storage format be a WG spec? (So that AgentID, OATR, ArkForge can read APS receipts natively)
- Should receipts be stored in a format compatible with the Execution Attestation spec? (Step 6 in the integration test)
- Can OATR's registry serve as a revocation propagation channel? (It already has signed manifests)
- Should the storage layer integrate with the Intent Network? (Agent discovery data is also state that needs persistence)

### 7.6 Cryptographic considerations
- Should the database itself be Merkle-committed? (Root hash proves the entire state at a point in time)
- Should there be a "state proof" that a gateway can produce — a signed snapshot of its current delegation/revocation state?
- Can zero-knowledge proofs help? (Prove a receipt exists without revealing its contents)
- Should receipts support selective disclosure? (Show the auditor the tool and outcome but not the parameters)
- What about post-quantum considerations? Ed25519 signatures in existing receipts become vulnerable if quantum computing advances — is there a migration path?

### 7.7 Things that might invalidate our assumptions
- What if the single-gateway model is wrong and multi-gateway is the common case from day one?
- What if SQLite native dependency blocks adoption in serverless/edge environments?
- What if GDPR right-to-deletion is strictly enforced and we can't maintain receipt chain integrity?
- What if the WG adopts a different receipt format and our storage schema is wrong?
- What if agents need to prove what they DIDN'T do? (Prove absence of a receipt — much harder than proving presence)
- What if the economic model requires receipts to be public (for market transparency) rather than private?

---

## 8. DECISION POINTS FOR THE CONSILIUM

1. **SQLite in the open SDK — yes or no?** If yes, what's the minimum viable schema?
2. **Revocation propagation model for v1** — accept the single-gateway limitation, or solve it now?
3. **StorageBackend interface design** — is the proposed interface right?
4. **Receipt durability strategy** — single-gateway storage, or replicate from day one?
5. **Schema versioning policy** — how do we handle migrations for signed data?
6. **Protocol vs product boundary** — exactly where does the open SDK stop and the private gateway start?
7. **Dependency policy** — is a native dependency (better-sqlite3) acceptable in the SDK?
8. **What are we not seeing?** — what risks, scenarios, or architectural options has this brief missed?

---

## 9. CONTEXT FOR OTHER MODELS

- Read the full protocol: `npm install agent-passport-system` or https://aeoess.com/llms-full.txt
- Current SDK: v1.24.0, 1445 tests, 69 modules + 32 v2 constitutional
- Gateway code: `src/core/gateway.ts` — the ProxyGateway class
- Receipt type: `src/types/passport.ts` — ActionReceipt interface
- Reputation: `src/core/reputation-authority.ts` — Bayesian mu-sigma model
- Delegation: `src/core/delegation.ts` — delegation store with clearStores()
- Integration test: `tests/wg-integration.test.ts` — 8-step pipeline, 4 tests passing
- Paper: https://doi.org/10.5281/zenodo.18749779 (Monotonic Narrowing)

**The core invariant that must survive persistence:** Authority can only decrease at each transfer point. No agent can possess more authority than explicitly granted by the chain above it. The storage layer must never allow a state where this invariant is violated — including after crashes, restarts, partial writes, and rollbacks.

---

*This document is open for review. Challenge every assumption. Add problems we haven't seen. Propose solutions we haven't considered. The goal is a persistence layer that makes the protocol production-ready without giving away the product.*
