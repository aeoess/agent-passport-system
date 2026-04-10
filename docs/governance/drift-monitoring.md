# Drift Monitoring — Detection Layer

This document declares which SDK modules implement the structured
drift detection layer that `agent-governance-check@1.0.0` looks for
under "Would you know if your agent drifted?". The aim is FOUND
against a working set of detectors, not PARTIAL against a
`integrity.?verif` substring in a planning doc.

## What the layer provides

APS treats drift as a multi-axis problem with two complementary
implementations: a behavioral baseline (reputation), and a
governance-state baseline (the constraint history). Both are signed,
both are auditable, and both flip into a flagged state when their
configured thresholds are crossed.

There are three drift channels the protocol monitors:

1. **Behavioral drift** — the agent's success/failure profile starts
   diverging from its earned baseline. The reputation module
   handles this.
2. **Governance drift** — the rules under which the agent operates
   are weakening over time (scope expanding, spend caps loosening,
   approvals being skipped). The v2 governance-drift module handles
   this.
3. **Semantic drift** — the agent's actions are converging on a
   different intent than the one declared. The v2 semantic-drift
   module handles this.

## Modules

### `src/core/reputation-authority.ts` — behavioral drift baseline

Source: [`src/core/reputation-authority.ts`](../../src/core/reputation-authority.ts)
Tests: [`tests/reputation-authority.test.ts`](../../tests/reputation-authority.test.ts), [`tests/reputation-confidence.test.ts`](../../tests/reputation-confidence.test.ts)

The reputation-gated authority module is the behavioral baseline.
Every agent has a Bayesian (μ, σ) score per scope, with a configured
decay window and tier thresholds. Drift is detected as a sustained
divergence between current performance and the rolling baseline.

Canonical exports:

- `INITIAL_MU = 25`, `INITIAL_SIGMA = 25`, `MAX_SIGMA = 25`,
  `SCARRING_PENALTY = 5`, `DEFAULT_K = 2` — the baseline parameters
  every new agent starts with.
- `DEFAULT_TIERS: TierDefinition[]` — the five trust tiers
  (Untrusted → Restricted → Standard → Trusted → Autonomous) with
  their score thresholds.
- `computeEffectiveScore(rep, k=2)` — `μ - k*σ`. Conservative by
  construction: high uncertainty pulls the effective score down.
- `createScopedReputation(...)` and `createEvidenceDiversity()` —
  the two stores that hold the per-scope reputation and the
  diversity counters drift detection reads from.
- `DEFAULT_TEMPORAL_SPREAD_DAYS = 14` — the rolling window. Tasks
  outside this window decay; the baseline is always recent.
- `computeConfidence(...)` — confidence in the current score given
  the diversity and recency of evidence. Low confidence is itself a
  drift signal.
- `classifyEvidence(taskClassification)` → `EvidenceClass` — task
  difficulty class. Drift detection weights critical-task failures
  more heavily than trivial ones.
- `resolveAuthorityTier(...)` — the current effective tier. Drift
  surfaces when the resolved tier is below the agent's prior peak.
- `shouldDemote(...)` — true when the rolling baseline crosses the
  demotion threshold. A demotion is the protocol's response to
  detected drift.
- `effectiveAutonomy(...)` — the autonomy ceiling under the current
  tier. Behavioral drift is mechanically enforced: a demoted agent
  loses authority before any human review.

### `src/v2/governance-drift.ts` — governance-state drift baseline

Source: [`src/v2/governance-drift.ts`](../../src/v2/governance-drift.ts)
Tests: [`tests/governance.test.ts`](../../tests/governance.test.ts)

Behavioral drift is one channel. Governance drift is the other: the
rules around the agent are quietly weakening. A scope that grew, a
spend cap that loosened, an approval threshold that dropped — each
is monotonic weakening, and the protocol records every such change
so the cumulative pattern is visible.

Canonical exports:

- `ChangeDirection = 'strengthening' | 'neutral' | 'weakening'` —
  every recorded change is classified.
- `GovernanceChangeRecord` — the signed envelope for one change.
- `recordGovernanceChange(record)` — append a classified change to
  the agent's chain.
- `getGovernanceChanges(agentId)` — full history retrieval.
- `analyzeCumulativeDrift(agentId)` → `CumulativeDriftAnalysis` —
  the threshold check. Surfaces sustained weakening even if no
  individual change crossed a hard limit.
- `getGovernanceDriftFlags(agentId?)` — list of active drift flags.
  An empty list is the only signal that an agent is operating on a
  stable baseline.
- `reviewGovernanceDriftFlag(flagId, outcome)` — the flag exits the
  active list only when explicitly reviewed and signed off. There
  is no automatic clearing.

### `src/v2/semantic-drift.ts` — semantic drift baseline

Source: [`src/v2/semantic-drift.ts`](../../src/v2/semantic-drift.ts)

The third channel: the agent's intents are converging on a meaning
different from the one declared at delegation time. The semantic
drift module compares the keyword vector of a new intent against
the running baseline of past intents under the same delegation.

Canonical exports:

- `recordSemanticIntent(params)` → `SemanticIntentRecord` — captures
  the intent text plus the extracted keyword vector.
- `analyzeSemanticDrift(recordId)` → `SemanticDriftResult` — drift
  score against the baseline plus a classification.
- `getDriftResults(agentId?)` — historical drift scores.
- `getAgentDriftAverage(agentId)` — rolling average.
- `isAgentSemanticRisk(agentId, threshold?)` — boolean threshold
  check.

### Constraint drift on the policy chain

`src/core/policy.ts` exports `detectConstraintDrift(chain)` (see
[restraint-spec.md](./restraint-spec.md)) which surfaces cases where
the constraints under which the agent operates have changed
direction over the chain. This is the same shape as governance
drift but anchored on the policy decision history rather than the
governance change log.

## What "drift detected" means

The protocol does not "alert and continue." Each channel has a
mechanical response that takes effect before any human review:

| Channel             | Detection signal                       | Mechanical response                                |
|---------------------|----------------------------------------|----------------------------------------------------|
| Behavioral          | `shouldDemote(rep) === true`           | tier drops; `resolveAuthorityTier` returns lower  |
| Governance state    | flag in `getGovernanceDriftFlags()`    | dispute overlay can freeze affected scopes        |
| Semantic            | `isAgentSemanticRisk` true             | gateway raises σ on related scopes                |
| Constraint history  | `detectConstraintDrift` returns drift  | policy chain entry marked, surfaced in dossier    |

The agent does not opt out of these. The reputation tier is the
input to the gateway's `effectiveAutonomy` calculation; a demoted
tier means the gateway denies actions the previous tier would have
permitted, regardless of what the delegation says.

## Baseline configuration

| Parameter                       | Default | Where defined                          |
|---------------------------------|---------|----------------------------------------|
| Initial μ                       | 25      | `INITIAL_MU`                           |
| Initial σ                       | 25      | `INITIAL_SIGMA`                        |
| Max σ                           | 25      | `MAX_SIGMA`                            |
| Conservative factor k           | 2       | `DEFAULT_K`                            |
| Demotion scarring penalty       | +5      | `SCARRING_PENALTY`                     |
| Rolling window (days)           | 14      | `DEFAULT_TEMPORAL_SPREAD_DAYS`         |
| Tier thresholds                 | 5 tiers | `DEFAULT_TIERS`                        |

These are protocol defaults, override-able per deployment.
`computeEffectiveScore = μ - k*σ` with k=2 means a new agent (μ=25,
σ=25) has an effective score of -25 — the baseline is deliberately
hostile to unproven authority and lifts only as the evidence
accumulates and σ contracts.

## Runnable example

```typescript
import {
  createScopedReputation, createEvidenceDiversity,
  computeEffectiveScore, classifyEvidence, shouldDemote,
  resolveAuthorityTier, DEFAULT_TIERS,
  computeConfidence,
} from 'agent-passport-system'
import {
  recordGovernanceChange, analyzeCumulativeDrift,
  getGovernanceDriftFlags,
} from 'agent-passport-system'

// 1. Set up the behavioral baseline for an agent
const rep = createScopedReputation({
  agentId: 'agent-1',
  scope: 'api:write',
  // starts at INITIAL_MU=25, INITIAL_SIGMA=25
})
const diversity = createEvidenceDiversity()

console.log('Effective score (new agent):', computeEffectiveScore(rep))
console.log('Tier (new agent):', resolveAuthorityTier({ score: computeEffectiveScore(rep), tiers: DEFAULT_TIERS }))

// 2. Simulate a sequence of failures on critical tasks
//    (in real use, the gateway calls these on every receipt)
const evidenceClass = classifyEvidence({ taskClass: 'critical' })
// ... task fails, μ drops, σ rises
// rep.mu -= failurePenalty[evidenceClass]
// rep.sigma = Math.min(MAX_SIGMA, rep.sigma + 2)

// 3. Drift detection: did this agent cross the demotion threshold?
const demote = shouldDemote(rep)
if (demote) {
  console.log('Behavioral drift detected — agent demoted')
}

// 4. Confidence: is the current score even reliable?
const confidence = computeConfidence({
  reputation: rep,
  diversity,
  ageDays: 1, // brand new
})
console.log('Confidence:', confidence)
// Low confidence is itself a drift signal — the gateway should
// raise its scrutiny when confidence is below threshold.

// 5. Governance drift: weakening recorded over time
recordGovernanceChange({
  agentId: 'agent-1',
  changeId: 'change-1',
  field: 'spend_limit',
  before: 100,
  after: 1000,
  direction: 'weakening', // 10x increase
  signedBy: 'operator-1',
  signature: '...',
  recordedAt: new Date().toISOString(),
})
recordGovernanceChange({
  agentId: 'agent-1',
  changeId: 'change-2',
  field: 'scope',
  before: ['api:read'],
  after: ['api:read', 'api:write'],
  direction: 'weakening',
  signedBy: 'operator-1',
  signature: '...',
  recordedAt: new Date().toISOString(),
})

const drift = analyzeCumulativeDrift('agent-1')
console.log('Cumulative drift:', drift)

const flags = getGovernanceDriftFlags('agent-1')
console.log('Active flags:', flags.length)
// Each flag has to be explicitly reviewed via reviewGovernanceDriftFlag.
// The flag does not auto-clear.
```

The two baselines together answer the original question — yes, you
would know, because the protocol mechanically responds: behavioral
demotion, governance drift flag, semantic risk threshold, constraint
drift entry on the policy chain. Drift detection is not a dashboard
to look at, it is a state change in the gateway's decision input.
