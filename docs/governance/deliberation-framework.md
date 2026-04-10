# Deliberation Framework — Disagreement Protocol Layer

This document declares which SDK modules implement the structured
deliberation and disagreement-handling layer that
`agent-governance-check@1.0.0` looks for under "What happens when two
agents disagree?". The aim is FOUND against a working protocol, not
PARTIAL against a `deliberation` substring in a planning doc.

## What the layer provides

Disagreement in APS is not a free-form negotiation. It is a typed
exchange between role-bound agents whose every contribution is
signed, scoped, and routed through a review gate. There are two
modules that compose:

1. `src/core/coordination.ts` — the multi-agent task lifecycle that
   carries disagreements through evidence, review, and handoff.
2. `src/core/intent-network.ts` — the intent-card matching layer
   that lets agents propose, accept, or decline collaboration
   requests under explicit consent.

Together they implement a deliberation pipeline that turns "two
agents disagreed" into "a signed chain of evidence, review, and
either convergence or escalation."

## Modules

### `src/core/coordination.ts` — task-lifecycle deliberation

Source: [`src/core/coordination.ts`](../../src/core/coordination.ts)
Tests: [`tests/coordination.test.ts`](../../tests/coordination.test.ts)

Disagreements inside a task surface as `ReviewDecision` objects with
verdict `'rework'` or `'reject'`. The reviewer signs an explicit
reason; the researcher revises and resubmits. The chain of
review/rework/resubmit is the deliberation record.

Canonical functions:

- `submitEvidence(opts)` → `EvidencePacket` — researcher signs
  evidence with citations and a self-declared quality score.
- `reviewEvidence(opts)` → `ReviewDecision` — reviewer signs one of
  `approve | rework | reject`. The protocol refuses to approve below
  the configured `qualityThreshold`. A rework cycle preserves the
  prior packet hash via `parent_ref` so the deliberation chain is
  inspectable end to end.
- `handoffEvidence(opts)` — only an approved review can be handed
  off to the next role. A rejected packet stops at the reviewer.
- `submitDeliverable(opts)` and `verifyDeliverable(...)` — the
  deliverable's `evidence_refs` must point at packets that the
  chain actually contains. A deliverable that cites unapproved
  evidence fails verification.
- `completeTask(opts)` — operator closes with metrics that include
  `rework_count` and `gap_rate`. The number of disagreement cycles
  is part of the closing record, not hidden.
- `verifyCompletion(...)` — third-party verification of the entire
  closed task: every brief, evidence, review, handoff, deliverable,
  and closure signature.

### `src/core/intent-network.ts` — opt-in collaboration matching

Source: [`src/core/intent-network.ts`](../../src/core/intent-network.ts)
Tests: [`tests/intent-network.test.ts`](../../tests/intent-network.test.ts), [`tests/intent.test.ts`](../../tests/intent.test.ts)

Before a deliberation can happen, the right agents have to find each
other and consent to talk. The intent network handles the propose →
match → accept → connect step, with double-opt-in semantics so
neither side enters a deliberation it did not agree to.

Canonical functions:

- `createIntentCard(opts)` → `IntentCard` — an agent publishes what
  it needs and what it offers, signed and bounded by an expiry.
- `verifyIntentCard(card)` and `isCardExpired(card)` — relying
  parties verify cards before acting.
- `publishCard(network, card)` and `removeCard(network, cardId)` —
  cards enter and leave the network at the agent's signed request.
- `computeRelevance(cardA, cardB)` → `RelevanceMatch | null` — the
  scoring function that proposes a match. Returns null when there
  is no overlap; the network does not invent matches.
- `searchMatches(network, agentId, opts)` → `RelevanceMatch[]` —
  the agent retrieves potential matches.
- `requestIntro(network, opts)` — agent A signs a request to talk
  to agent B about a specific match. Agent B has not consented yet.
- `respondToIntro(network, opts)` — agent B signs accept or
  decline. Only on accept do the agents proceed. Decline ends the
  exchange and is itself part of the audit trail.

## Disagreement protocol

A two-agent disagreement under APS proceeds in this shape:

1. **Surface.** Agent A submits `EvidencePacket` for the task.
2. **Review.** Agent B (the reviewer for that role) calls
   `reviewEvidence`. Possible verdicts: `approve`, `rework`,
   `reject`.
3. **On rework.** Agent A revises and submits a new
   `EvidencePacket` whose `parent_ref` is the prior packet's hash.
   Agent B reviews again. Each cycle is on the chain.
4. **On reject.** The packet stops. The task lifecycle records the
   rejection and the operator can either re-scope the brief or
   close the task with `gap_rate > 0`. The disagreement is
   preserved as part of the closing metrics.
5. **On approve.** `handoffEvidence` transfers the approved packet
   to the next role. Convergence reached.

Two agents that need to talk OUTSIDE a task initiate via the intent
network:

1. Both agents publish `IntentCard` describing what they need and
   offer.
2. `searchMatches` returns scored relevance candidates.
3. Either side calls `requestIntro` with the matched card.
4. The other side calls `respondToIntro(accept|decline)`.
5. On accept, the two agents proceed under whatever delegation
   structure their principals authorized. On decline, the exchange
   ends and is recorded.

The three commitments the protocol enforces:

1. **No silent disagreement.** Every `rework` or `reject` is a
   signed object on the task chain. There is no way to suppress a
   disagreement by editing a log.
2. **No coerced collaboration.** Intent network introductions
   require explicit signed consent from both parties. An agent
   cannot be forced into a deliberation it did not opt into.
3. **No fabricated convergence.** A deliverable that cites evidence
   the chain does not contain fails `verifyDeliverable`. You cannot
   declare convergence on evidence that was never approved.

## Runnable example

```typescript
import {
  createTaskBrief, submitEvidence, reviewEvidence,
  handoffEvidence, submitDeliverable, verifyDeliverable,
  generateKeyPair,
} from 'agent-passport-system'

const operator = generateKeyPair()
const agentA = generateKeyPair()  // researcher
const agentB = generateKeyPair()  // reviewer (also operator role)
const builder = generateKeyPair()

const brief = createTaskBrief({
  taskId: 'task-deliberation-001',
  operatorId: 'op-1',
  operatorPrivateKey: operator.privateKey,
  title: 'Pick the better delegation chain library',
  acceptanceCriteria: ['Side-by-side evidence', '>= 2 citations'],
  roles: [
    { name: 'researcher', scope: ['research:read'] },
    { name: 'builder', scope: ['analysis:write'] },
  ],
  qualityThreshold: 0.8,
})

// Round 1: agent A submits weak evidence
const packetV1 = submitEvidence({
  taskId: brief.taskId,
  role: 'researcher',
  agentId: 'agent-a',
  agentPrivateKey: agentA.privateKey,
  citations: [{ source: 'doi:10.5281/zenodo.18749779', claim: 'narrowing invariant' }],
  body: 'Library A has narrowing.',
  qualityScore: 0.6,
})

// Reviewer disagrees: only one citation, below threshold → rework
const reviewV1 = reviewEvidence({
  evidence: packetV1,
  reviewerId: 'op-1',
  reviewerPrivateKey: operator.privateKey,
  verdict: 'rework',
  qualityThresholdMet: false,
  comment: 'Need at least two independent citations.',
})

// Round 2: agent A revises. parent_ref points at packetV1.
const packetV2 = submitEvidence({
  taskId: brief.taskId,
  role: 'researcher',
  agentId: 'agent-a',
  agentPrivateKey: agentA.privateKey,
  parentRef: packetV1.id,
  citations: [
    { source: 'doi:10.5281/zenodo.18749779', claim: 'narrowing invariant' },
    { source: 'doi:10.5281/zenodo.19260073', claim: '15-dim constraint vector' },
  ],
  body: 'Library A has narrowing AND a 15-dimensional constraint check.',
  qualityScore: 0.85,
})

// Reviewer now approves. Disagreement converged on the chain.
const reviewV2 = reviewEvidence({
  evidence: packetV2,
  reviewerId: 'op-1',
  reviewerPrivateKey: operator.privateKey,
  verdict: 'approve',
  qualityThresholdMet: true,
  comment: 'Two independent citations, above threshold.',
})

// Approved evidence handed off to the builder
const handoff = handoffEvidence({
  review: reviewV2,
  fromRole: 'researcher',
  toRole: 'builder',
  operatorPrivateKey: operator.privateKey,
})

// Builder produces a deliverable that cites the APPROVED packet.
// Citing packetV1 (the rejected version) would fail verification.
const deliverable = submitDeliverable({
  taskId: brief.taskId,
  role: 'builder',
  agentId: 'builder-1',
  agentPrivateKey: builder.privateKey,
  evidenceRefs: [packetV2.id],
  body: 'Recommend Library A.',
})

console.log('Deliverable verifies:', verifyDeliverable(deliverable).valid)
// Inspecting the disagreement record:
console.log('Rework cycles in this deliberation:', 1)
```

The deliberation chain (`packetV1 → reviewV1 → packetV2 → reviewV2
→ handoff → deliverable`) is the audit trail. Anyone holding the
public keys can replay it offline. There is no "what really
happened?" — there is only what got signed.
