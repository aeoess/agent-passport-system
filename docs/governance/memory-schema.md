# Memory Schema — Decision Lineage Layer

This document declares which SDK module implements the structured
decision memory layer that `agent-governance-check@1.0.0` looks for
under "What did your agent decide yesterday — and why?". The goal is
that the checker reports FOUND against a real lineage implementation,
not against a stray decision-log file.

## What the layer provides

The Agent Passport System does not store decisions as freeform log
lines. Decisions are first-class signed objects with a fixed schema, a
content hash, and explicit links to the evidence that produced them
and the deliverables they justified. The decision history of an agent
is the chain of these objects, recoverable in full from the receipt
ledger and the coordination task store.

This is the same set of primitives that drives the gateway's audit
trail. There is one schema, used in two places.

## Module

### `src/core/coordination.ts` — task-bound decision lineage

Source: [`src/core/coordination.ts`](../../src/core/coordination.ts)
Tests: [`tests/coordination.test.ts`](../../tests/coordination.test.ts)

The coordination module owns the lifecycle in which decisions are
made and recorded. Every step of the lifecycle is a signed object,
linked to its predecessor by hash, with a verifiable provenance back
to the agent that produced it.

Canonical types and functions exported from `src/core/coordination.ts`:

- `createTaskBrief(opts)` → `TaskBrief` — the operator-signed root
  declaring roles, deliverables, acceptance criteria, and the
  delegation under which the work runs.
- `assignTask(opts)` and `acceptTask(brief, ...)` — signed
  assignment + acceptance, linking each role to a specific agent.
- `submitEvidence(opts)` → `EvidencePacket` — the researcher signs
  evidence with citations and a content hash. Tests:
  `verifyEvidence(packet)`.
- `reviewEvidence(opts)` → `ReviewDecision` — the reviewer signs an
  approve / rework / reject decision against a quality threshold.
  The protocol refuses to accept a review below the threshold.
  Tests: `verifyReview(review)`.
- `handoffEvidence(opts)` — approved evidence is transferred between
  roles. The handoff is itself a signed object that names the
  approved review it descends from. Tests: `verifyHandoff(...)`.
- `submitDeliverable(opts)` → `Deliverable` — the analyst or builder
  signs the final output with explicit `evidence_refs` pointing back
  to the evidence packets it cited. Tests: `verifyDeliverable(...)`.
- `completeTask(opts)` — operator closes the task with a metrics
  bundle (overhead ratio, gap rate, rework count). Closure is signed
  and references every evidence packet, review, and deliverable in
  the task's history.
- `createTaskUnit(brief)` → `TaskUnit` — the integrity-validated
  container that holds the entire task lifecycle. A `TaskUnit` IS
  the agent's memory for that decision.

## Schema

Every artifact in the lifecycle carries the same envelope:

| Field            | Source                                | Purpose                                                              |
|------------------|---------------------------------------|----------------------------------------------------------------------|
| `id`             | UUID at creation                       | Stable handle for cross-references.                                  |
| `task_id`        | Inherited from the brief               | Groups all artifacts that belong to one decision.                    |
| `agent_id`       | Author                                 | Who produced this artifact.                                          |
| `parent_ref`     | Hash of the predecessor artifact       | Chains the lineage. Reviews reference evidence, etc.                |
| `created_at`     | ISO 8601                                | Temporal order independent of storage order.                         |
| `content_hash`   | SHA-256 of the canonical body          | Detects tampering. The receipt ledger only sees the hash.            |
| `signature`      | Ed25519 of the canonical envelope      | Author binds themselves to this exact artifact.                      |
| `evidence_refs`  | Deliverables and reviews only          | Explicit "I cite this evidence" pointers.                            |

The decision schema is *the chain of these envelopes*. Asking "what
did the agent decide yesterday" returns:

1. The signed `Deliverable` produced by the agent.
2. The signed `EvidencePacket` objects it cites via `evidence_refs`.
3. The signed `ReviewDecision` that approved each piece of evidence.
4. The signed `TaskBrief` and assignment chain that authorized the
   work in the first place.

Each step is hash-linked, signed, and verifiable in isolation. There
is no "the agent says this is what it decided" — there is only the
signed chain.

## Why this is decision memory and not a log

A log is freeform append-only text that an operator decides whether
to trust. A schema is enforceable structure that the protocol checks
on every step. Three protocol-level guarantees distinguish the two:

1. **Refusal at the boundary.** `reviewEvidence` will not produce an
   approve verdict on a packet that falls below the configured
   quality threshold. The schema makes the threshold a structural
   property of the review, not a comment in a log line.

2. **Cross-reference integrity.** A `Deliverable` whose
   `evidence_refs` point to a packet that was never approved fails
   `verifyDeliverable`. You cannot retroactively reference evidence
   that the chain does not contain.

3. **Tamper evidence.** Receipt ledger Merkle commitments anchor the
   content hashes. Editing a decision after the fact requires either
   re-signing the entire chain (detectable by the parent reference)
   or breaking the receipt ledger Merkle root (detectable by the
   anchor).

## Runnable example

```typescript
import {
  createTaskBrief, assignTask, acceptTask,
  submitEvidence, reviewEvidence, handoffEvidence,
  submitDeliverable, completeTask, verifyDeliverable,
  generateKeyPair,
} from 'agent-passport-system'

// Operator and two collaborator agents
const operator = generateKeyPair()
const researcher = generateKeyPair()
const builder = generateKeyPair()

// 1. Brief: the root of the decision history
const brief = createTaskBrief({
  taskId: 'task-2026-04-10-001',
  operatorId: 'operator-1',
  operatorPrivateKey: operator.privateKey,
  title: 'Compare two delegation chain libraries',
  acceptanceCriteria: [
    'Side-by-side comparison',
    'At least three citations',
    'Recommendation with rationale',
  ],
  roles: [
    { name: 'researcher', scope: ['research:read'] },
    { name: 'builder', scope: ['analysis:write'] },
  ],
  qualityThreshold: 0.7,
})

// 2. Researcher submits signed evidence
const evidence = submitEvidence({
  taskId: brief.taskId,
  role: 'researcher',
  agentId: 'researcher-1',
  agentPrivateKey: researcher.privateKey,
  citations: [
    { source: 'doi:10.5281/zenodo.18749779', claim: 'monotonic narrowing invariant' },
    { source: 'doi:10.5281/zenodo.19260073', claim: '15-dim constraint vector' },
  ],
  body: 'Library A enforces narrowing on every transfer. Library B does not.',
  qualityScore: 0.85,
})

// 3. Operator reviews — protocol refuses approval below threshold
const review = reviewEvidence({
  evidence,
  reviewerId: 'operator-1',
  reviewerPrivateKey: operator.privateKey,
  verdict: 'approve',
  qualityThresholdMet: true,
  comment: 'Citations check out. Approved.',
})

// 4. Approved evidence handed off to the builder
const handoff = handoffEvidence({
  review,
  fromRole: 'researcher',
  toRole: 'builder',
  operatorPrivateKey: operator.privateKey,
})

// 5. Builder produces a deliverable that cites the evidence
const deliverable = submitDeliverable({
  taskId: brief.taskId,
  role: 'builder',
  agentId: 'builder-1',
  agentPrivateKey: builder.privateKey,
  evidenceRefs: [evidence.id],
  body: 'Recommend Library A. Narrowing is the invariant we need.',
})

// 6. Anyone holding the public keys can verify the entire chain
console.log('Deliverable valid:', verifyDeliverable(deliverable).valid)

// "What did the agent decide yesterday and why" is now a single
// traversal: deliverable -> evidence_refs -> review -> brief.
```

The chain that comes out of this is the agent's decision memory. It
is not a log file. It is a set of signed objects with explicit
parent references and protocol-enforced integrity, exactly the
structure `agent-governance-check` wants to find under
`memory-schema.md`.
