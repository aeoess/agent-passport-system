# Decision Equivalence Gap — Multi-Model Consilium Briefing

## Origin

xsa520 (Guardian project) raised this across 6+ posts on the WG thread (corpollc/qntm#5) and our issue #5. The WG has not fully answered it. desiorac (ArkForge) engaged but didn't close it. We pointed him to Module 37 but he correctly identified the remaining gap.

## What we have (Module 37: Decision Semantics)

1. `ContentHash` with `identityBoundary` — declares which fields define "same decision"
2. `DecisionSemantics` — decomposes verdicts into structural (deterministic) vs trust (engine-specific)
3. `DecisionArtifact` — bundles intent + evaluation + semantics into a verifiable cross-engine object
4. `MINIMUM_IDENTITY_FIELDS` — per-artifact-type minimum boundary
5. `EvaluationMethod` — declares deterministic / probabilistic / model_dependent / hybrid
6. Finding layer tags (`structural` | `trust`) on PrincipleEvaluation — shipped today

## What we DON'T have (the actual gap)

### Gap 1: Cross-system boundary agreement

Two independent systems can choose different `identityBoundary` values. System A might include `[agentId, action, delegationId]` while System B includes `[agentId, action, delegationId, context]`. Their hashes differ even for semantically identical decisions. No protocol for agreeing on a shared boundary.

### Gap 2: Equivalence comparison across boundaries

No function takes two ContentHashes with different boundaries and determines if they're comparable. Today: same hash = same decision, different hash = unknown. We need: different hash but overlapping boundary = comparable with declared divergence points.

### Gap 3: Semantic threshold equivalence

xsa520's example: risk=0.69 → ALLOW vs risk=0.7000001 → DENY. Same policy, same input, opposite outcomes. Our system records both but can't identify them as "same policy evaluation at a threshold boundary condition."

### Gap 4: Boundary profiles for common decision types

No standard named configurations. A commerce decision, a data access decision, and a delegation decision should have default canonical boundaries that conforming systems use unless they explicitly opt out.

## How this connects to our data modules (38-42)

- **Data Enforcement Gate (Module 40)**: makes allow/deny decisions on data access based on registered terms. Two gates with different term interpretation could produce divergent decisions on "same" request.
- **Training Attribution (Module 41)**: computes fractional contribution weights. Two systems using different weight algorithms produce different fractions for the same data lineage.
- **Data Settlement (Module 39)**: Merkle-commits compensation records. If two systems disagree on contribution weights, their settlements diverge.

The data modules enforce terms and compute attribution — but they don't define when two independent computations of the same terms are "equivalent."

## Questions for the consilium

1. **Is the gap real or theoretical?** In practice, do two systems actually need to agree that they made "the same decision"? Or is it enough that each system is internally consistent and auditable?

2. **Boundary profiles**: Should we define canonical boundary profiles per decision type? e.g.:
   - `commerce:preflight` → `[agentId, merchantOrigin, intentName, amount, currency]`
   - `data:access` → `[agentId, sourceId, termsVersion, accessType]`
   - `delegation:evaluate` → `[agentId, delegationId, scopeRequired, action.type]`
   Systems using the same profile produce comparable hashes. Different profiles = explicitly incomparable.

3. **Equivalence function**: Should we build `compareDecisions(a: ContentHash, b: ContentHash)` that:
   - If boundaries identical → compare hashes directly
   - If boundaries overlap → project both to intersection, rehash, compare
   - If boundaries disjoint → declare incomparable
   
4. **Threshold semantics**: xsa520's risk=0.69 vs 0.7000001 case. Is this a problem our protocol should solve, or is it a property of the evaluation engine that's explicitly out of scope? The `EvaluationMethod: 'deterministic' | 'probabilistic'` already flags this — but doesn't resolve it.

5. **What does Guardian actually have?** xsa520 keeps hinting at a "minimal invariant at the decision layer" but hasn't shown code. Are we solving a problem he's already solved? Should we ask to see his spec before building?

6. **Does archedark-ada's "commitment surface" proposal (/.well-known/agent-commitments.json) already cover this?** If agents declare their evaluation invariants upfront, boundary agreement becomes discoverable.

## Recommended approach

Define this as a new primitive: **Decision Equivalence Protocol** — a negotiation layer where two systems agree on boundary profiles before comparing decisions. This sits between Module 37 (decision artifacts) and the coordination layer (Module 6). Small surface area, high protocol value.

But: don't build until the consilium weighs in on whether the gap is real enough to warrant protocol-level solution vs. "document it as an implementation note."
