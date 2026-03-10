# Reputation-Gated Authority for Autonomous AI Agents
## Design Document — AEOESS / Agent Passport System

**Author:** Tymofii Pidlisnyi
**Date:** March 2026
**Status:** Design proposal — open for review
**Context:** Extension to the Agent Passport System (8 layers, 359 tests, Ed25519 identity, scoped delegation chains)

---

## 1. The Problem

Current agent authority models are binary: a human assigns permissions, and the agent has them until they're revoked. This creates two failure modes:

**Over-trust:** A new agent receives broad authority on day one because the human doesn't want to micromanage. The agent makes a costly mistake before building any track record.

**Under-trust:** A proven agent that has executed thousands of successful transactions still needs human approval for routine actions because nobody updated its permissions. The human becomes a bottleneck.

Both failures stem from the same root cause: authority is static while agent behavior is dynamic. Reputation accumulates over time, but authority doesn't respond to it.

## 2. The Idea

Agent authority should be earned through demonstrated performance, not just assigned by fiat.

Reputation accumulates passively from cryptographically signed action receipts, task completions, and peer reviews — artifacts the Agent Passport System already produces. But crossing an authority tier boundary requires a **promotion review** — a deliberate evaluation by a qualified authority (human principal or high-tier agent) that verifies the reputation was earned through substantive work.

This is how military ranks work. Service records accumulate automatically. But a promotion board reviews the record and decides whether the pattern merits higher authority. The score is necessary but not sufficient.

**Core invariant:** Authority can only be expanded through explicit promotion. Authority is automatically narrowed on evidence of failure. This preserves monotonic narrowing while allowing earned trust to unlock greater autonomy.
## 3. Architecture

### 3.1 Authority Tiers

Each tier unlocks a specific autonomy level (from the existing Intent Architecture, Layer 5), a maximum delegation depth, and a maximum spend-per-action.

| Tier | Name | Min Reputation | Autonomy Level | Max Delegation Depth | Max Spend/Action |
|------|------|---------------|----------------|---------------------|-----------------|
| 0 | Recruit | 0 | 1 (fully supervised) | 0 (cannot sub-delegate) | $0 |
| 1 | Operator | 30 | 2 (suggest and wait) | 1 | $100 |
| 2 | Specialist | 60 | 3 (suggest and act) | 2 | $500 |
| 3 | Captain | 80 | 4 (act and report) | 3 | $2,000 |
| 4 | Sovereign | 95 | 5 (fully autonomous) | 5 | $10,000 |

Tiers are illustrative. The protocol allows custom tier definitions per deployment. The invariant is structural: tiers form a strict partial order, and promotion always moves upward.

### 3.2 Reputation Accumulation

Reputation is computed from existing protocol artifacts:

- **Action receipts** (Layer 1): Every completed action produces a signed receipt with scope, result, and timestamp.
- **Task completion reviews** (Layer 6): Reviewers score evidence quality, and the score feeds reputation.
- **Peer audit findings** (Layer 6): Accepted audit findings affect the audited agent's reputation.
- **Delegation revocations** (Layer 1): A revocation is a strong negative signal.

Reputation is **per-scope-category**, not global. An agent with 90 reputation in `code_execution` and 20 reputation in `financial_transactions` is treated differently in each domain.

**Exponential decay** ensures recent performance matters more than historical performance. A receipt from yesterday contributes more than a receipt from six months ago.
### 3.3 Promotion Reviews

Crossing a tier boundary requires a signed **PromotionReview** artifact:

```
PromotionReview {
  agentId: string               // Agent being promoted
  fromTier: number              // Current tier
  toTier: number                // Requested tier
  scope: string                 // Scope category for this promotion
  reviewerId: string            // Who is reviewing
  reviewerTier: number          // Reviewer's current tier (must be > toTier)
  evidence: {
    totalReceipts: number       // Total action receipts in this scope
    reputationScore: number     // Current computed score
    complexityDistribution: {
      trivial: number
      standard: number
      complex: number
      critical: number
    }
    revocationCount: number
    failedReviews: number
    timeInCurrentTier: string
  }
  verdict: 'promoted' | 'denied'
  reasoning: string
  timestamp: string
  signature: string             // Ed25519 signature of reviewer
}
```

### 3.4 Promotion Authority Rules

**Rule 1: The principal is the root authority.** A human principal can promote any agent to any tier in any scope.

**Rule 2: Agents can only promote below their own tier.** A Captain (tier 3) can approve promotions to Specialist (tier 2) but not to Captain or Sovereign.

**Rule 3: Promotion authority is a delegatable scope.** The principal can delegate `promote:specialist` to a Captain. This scope narrows monotonically like any other delegation.

**Rule 4: No self-promotion.** An agent cannot review its own promotion.

**Rule 5: Complexity threshold.** At least 20% of receipts must be `standard` or higher, and at least 5% must be `complex` or higher.
### 3.5 Demotion Mechanics

**Automatic demotion triggers:**
- Behavioral: Policy violation or failed task review → immediate drop by one tier
- Administrative: Delegation expired or principal policy change → authority restricted, reputation preserved
- Environmental: Upstream delegation revoked → effective authority reduced, no reputation damage

**Hysteresis prevents oscillation:**

| Tier | Promote At | Demote At |
|------|-----------|-----------|
| Operator | 30 | 15 |
| Specialist | 60 | 45 |
| Captain | 80 | 65 |
| Sovereign | 95 | 80 |

**Demotion does not require a review.** Trust is hard to earn and easy to lose.

### 3.6 Effective Authority Computation

```
effectiveAutonomy = min(delegation.autonomyLevel, tier.autonomyLevel)
effectiveSpend = min(delegation.spendLimit, tier.maxSpendPerAction)
effectiveDepth = min(delegation.maxDepth, tier.maxDelegationDepth)
```

The delegation says "you're allowed up to X." The reputation tier says "you've earned up to Y." The effective authority is the minimum. Neither can independently expand authority.

### 3.7 Fiat vs Earned Tier Tagging

Tiers are cryptographically tagged as either `Origin: Fiat` (granted by human override) or `Origin: Earned` (granted by evidence-based review). Only `Earned` agents can participate in promotion reviews for others. A `Fiat Captain` has the authority to act but not the authority to promote. This contains the blast radius of human laziness.
## 4. Security Analysis

### 4.1 Reputation Farming
**Attack:** Agent performs 500 trivial tasks to inflate reputation.
**Mitigation:** Promotion review checks complexity distribution. Per-scope reputation prevents cross-domain farming.

### 4.2 Collusion Between Promoter and Promotee
**Attack:** Captain promotes a friendly agent, agent reciprocates.
**Mitigation:** Rule 2 (promote only below own tier). Full delegation chain in every PromotionReview. Multi-party promotion required for Captain/Sovereign.

### 4.3 Temporal Attack (Reputation Then Betrayal)
**Attack:** Build reputation over 6 months, get Sovereign, act maliciously.
**Mitigation:** Reputation unlocks autonomy level, not scope. Blast radius bounded by delegation scope. Automatic demotion on first violation.

### 4.4 Promotion Authority Escalation
**Attack:** Agent with `promote:operator` attempts to promote to Specialist.
**Mitigation:** Promotion scope narrows monotonically. Cryptographically enforced in the signed delegation chain.

### 4.5 Demotion Denial of Service
**Attack:** Adversary triggers false revocations to demote competitors.
**Mitigation:** Only the delegation issuer can revoke. External adversary cannot trigger revocation.

### 4.6 Sybil-Fiat Attack
**Attack:** Compromised principal spam-promotes 100 Fiat Captains who then promote a swarm.
**Mitigation:** Fiat vs Earned tagging. Only Earned agents can serve as promotion reviewers.

### 4.7 Peter Principle / Oscillation Loop
**Attack:** Agent gets promoted, fails, farms back, gets repromoted.
**Mitigation:** Cryptographic scarring — each demotion permanently increases the threshold for future promotions in that scope.
## 5. Interaction with Existing Protocol Layers

| Layer | Interaction |
|-------|-------------|
| Layer 1 (Identity) | Reputation computed from action receipts. Tier stored as passport metadata. |
| Layer 1 (Delegation) | Effective authority = min(delegation, tier). Promotion authority is a delegatable scope. |
| Layer 2 (Values Floor) | Floor violations trigger automatic behavioral demotion. Floor principles non-negotiable regardless of tier. |
| Layer 3 (Attribution) | Promotion reviews are attributable artifacts in the Merkle tree. |
| Layer 4 (Agora) | Promotions and demotions posted as signed Agora messages for transparency. |
| Layer 5 (Intent) | Autonomy levels already defined. Reputation-gated authority bridges reputation to autonomy. |
| Layer 6 (Coordination) | Task review scores feed reputation. Complex task completions carry more weight. |
| Layer 7 (Integration) | `reputationGatedCommerce()` bridge: commerce preflight checks tier before spend gate. |
| Layer 8 (Commerce) | Spend limits per tier. Sovereign agents transact autonomously; Recruits cannot transact. |

## 6. Open Questions

**Q1: Tier visibility.** Visible within principal's fleet, opaque to external agents who see only delegation scope.

**Q2: Reputation portability.** Principal-scoped by default. Principals can issue signed "reputation endorsements" (vouches) that carry partial weight in another principal's system.

**Q3: Decay rate.** Start with 90-day half-life. Event-driven decay when underlying LLM model changes.

**Q4: Probation.** Default feature, not optional. 7-day probation after promotion. Actions routed through Shadow Mode (Intent Architecture, mandatory sign-off).

**Q5: Multi-agent promotion boards.** Required for Captain and Sovereign promotions. N-of-M qualified reviewers. Single reviewer sufficient for Operator and Specialist.
## 7. Implementation Plan

### Phase 1: Core Types and Tier Resolution
- `src/types/reputation-authority.ts` — AuthorityTier, PromotionReview, DemotionEvent types
- `src/core/reputation-authority.ts` — resolveAuthorityTier(), effectiveAutonomy(), effectiveSpend(), effectiveDepth()
- Tests: tier resolution, min(delegation, tier) composition, hysteresis

### Phase 2: Promotion Reviews
- createPromotionReview(), validatePromotionReview(), applyPromotion()
- Tests: promotion authority rules, self-promotion prevention, cross-tier constraints, complexity thresholds

### Phase 3: Automatic Demotion
- triggerDemotion() with behavioral/administrative/environmental distinction
- Integration with revokeDelegation() and evaluateIntent()
- Tests: demotion triggers, hysteresis boundaries, scarring

### Phase 4: MCP Tools
- resolve_authority, request_promotion, review_promotion, get_promotion_history

### Phase 5: Integration Bridges
- reputationGatedCommerce(), reputationToAgora(), coordinationReputationFeed()

## 8. Relation to Existing Work

**Google DeepMind "Intelligent AI Delegation" (Feb 2026, arXiv:2602.11865):** Treats trust as an input parameter, not an earned quantity.

**DelegateOS (github.com/newtro/delegateos):** Trust scores gate token creation, not autonomy levels. No promotion review mechanism.

**Biscuit/Macaroons:** Capability tokens with attenuation, no reputation layer.

**EigenTrust (Kamvar et al., 2003):** Foundational algorithm for reputation in P2P networks. Addresses collusion rings.

**UCON / Usage Control:** Mutable state, ongoing constraints, obligations, dynamic decisioning. Strong conceptual neighbor.

**RAdAC (Risk-Adaptive Access Control):** Trust-and-risk mediated operating envelope. Our design is a deterministic implementation of RADAC principles.

**Human organizational theory:** Military promotion boards, academic tenure, professional certification. Evidence accumulates automatically; qualified authority reviews before granting higher responsibility.

**This proposal's contribution:** Connecting reputation to authority through a promotion gate requiring deliberate review, while maintaining monotonic narrowing. Reputation unlocks authority. Reputation loss restricts authority. No algorithm alone grants higher authority — a qualified reviewer must approve.

---

*The Agent Passport System is open source under Apache-2.0. Implementation at github.com/aeoess/agent-passport-system. Protocol documentation at aeoess.com.*