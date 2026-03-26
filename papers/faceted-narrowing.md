# Faceted Narrowing: Product Lattice Formalization of Authority Attenuation

## Extension to Section 3.2 of "Monotonic Narrowing for Agent Authority"

### For AISec Workshop Submission (~July 2026)

---

## The Generalization

The current INV-1 formalization states three separate narrowing conditions for
delegation chains:

    scope(d_{i+1}) ⊆ scope(d_i)
    spendLimit(d_{i+1}) ≤ spendLimit(d_i)
    depth(d_{i+1}) < depth(d_i)

These are not independent properties. They are instances of a single structural
principle: authority is an element of a product lattice, and delegation is a
monotone function on that lattice.

---

## Formal Definition

### Definition 1: Authority Dimensions

We define an authority space as a product of n ordered sets (lattices),
each representing an independent dimension of agent authority:

    A = D_1 × D_2 × ... × D_n

where each D_k is a partially ordered set (poset) with a meet operation (⊓)
representing the narrowing of authority along that dimension. Each D_k has a
top element ⊤_k (maximum authority in that dimension) and a bottom element
⊥_k (zero authority in that dimension).

For the Agent Passport System, the dimensions are:

| Dimension | Lattice | Ordering | ⊤ | ⊥ |
|-----------|---------|----------|---|---|
| Scope | (P(S), ⊆) | set inclusion over scope labels | S (all scopes) | ∅ (no scope) |
| Spend | (ℝ≥0, ≤) | natural ordering of non-negative reals | ∞ (unlimited) | 0 (none) |
| Depth | (ℕ, ≤) | natural ordering | maxDepth | 0 |
| Time | ([0,∞), ≤) | seconds remaining | ∞ | 0 (expired) |
| Reputation | ([0,100], ≤) | effective score ordering | 100 | 0 |
| Values | (V, ⊆) | floor principles as set inclusion | V (all principles attested) | ∅ |
| Reversibility | ({T,C,I}, ≤) | T ≤ C ≤ I | irreversible | tentative |

### Definition 2: Authority Element

An authority element a ∈ A is a tuple:

    a = (scope, spend, depth, time, reputation, values, reversibility)

where each component a_k ∈ D_k.

### Definition 3: Product Lattice Ordering

The product lattice ordering ≤_A is defined componentwise:

    a ≤_A b  ⟺  ∀k ∈ [1,n]: a_k ≤_k b_k

That is, authority element a is dominated by authority element b if and only
if a is at most as permissive as b in EVERY dimension simultaneously. This is
a partial order: two authority elements may be incomparable if one exceeds the
other in some dimension but not all (e.g., higher spend limit but narrower scope).

The meet (greatest lower bound) of the product lattice is:

    a ⊓_A b = (a_1 ⊓_1 b_1, a_2 ⊓_2 b_2, ..., a_n ⊓_n b_n)

which represents the most permissive authority that is simultaneously consistent
with both a and b. This is the authority intersection.

### Definition 4: Delegation as Monotone Function

A delegation function δ: A → A is monotone if:

    ∀a ∈ A: δ(a) ≤_A a

That is, the output of delegation is always dominated by its input.
Authority can only decrease (narrow) through delegation, never increase.

### Theorem 1: Faceted Monotonic Narrowing

For any delegation chain d_1, d_2, ..., d_k, where δ_i is the delegation
function producing d_{i+1} from d_i:

    auth(d_k) ≤_A auth(d_{k-1}) ≤_A ... ≤_A auth(d_1)

where auth(d_i) extracts the authority element from delegation d_i. Authority
monotonically narrows along the chain in the product lattice ordering.

*Proof sketch.* Each delegation step δ_i is monotone by Definition 4. The
composition of monotone functions on a product lattice is itself monotone
(standard result from order theory). Therefore the transitive closure of
delegation is monotone. □

### Corollary 1: Independent Facet Narrowing

Faceted narrowing implies that each dimension narrows independently:

    ∀k: auth_k(d_{i+1}) ≤_k auth_k(d_i)

This follows directly from the componentwise definition of ≤_A. The original
three-condition INV-1 formulation (scope ⊆, spend ≤, depth <) is a special
case of faceted narrowing with n=3 dimensions.

### Corollary 2: Effective Authority as Meet

The effective authority of an agent with multiple active delegations
(e.g., from different principals) is the meet of all delegation authorities:

    effectiveAuth(agent) = ⊓_{d ∈ delegations(agent)} auth(d)

This is the most permissive authority simultaneously consistent with ALL
of the agent's delegations. An agent cannot claim authority from one
delegation to exceed limits imposed by another.

---

## Connection to Established Theory

### Capability Attenuation (Miller 2006)

Miller's capability attenuation principle states that a reference holder
cannot confer rights to another that the holder does not possess. Faceted
narrowing extends this from a single capability (scope) to a product of
capabilities (scope × spend × depth × time × reputation × values ×
reversibility). The extension is natural: Miller's attenuation is faceted
narrowing with n=1.

### Lattice-Based Access Control (Denning 1976, Sandhu 1993)

LBAC defines security levels as elements of a lattice, with information
flow restricted by the lattice ordering. Our authority space A is exactly
such a lattice, with agent authority replacing security clearance. The
monotone delegation function δ corresponds to the "can-flow" relation
in LBAC: authority can only flow downward in the lattice.

### Abstract Interpretation (Cousot & Cousot 1977)

Constraint checking in the gateway can be formalized as abstract
interpretation over the authority lattice. The concrete domain is the
set of all possible agent actions. The abstract domain is the authority
space A. The abstraction function α maps an action to the minimum
authority element required to perform it. The concretization function γ
maps an authority element to the set of actions it permits.

    α(action) ≤_A auth(agent)  ⟹  action is permitted

This is a Galois connection. The soundness guarantee: if the abstract
check (authority comparison) says "permitted," the concrete action is
within the principal's intended authority.

### Domain Theory (Scott 1970)

Delegations form a directed-complete partial order (dcpo). The authority
of an agent is the infimum (greatest lower bound) of all delegations in
its chain. Monotonic narrowing is the statement that delegation is a
monotone function on this dcpo. This connects the protocol to 50 years
of programming language theory — we are defining the denotational
semantics of agent authority.

---

## Implementation: Constraint Architecture

The faceted narrowing formalization is not just theory. It is directly
implemented in the Agent Passport System's Constraint Architecture
(shipped SDK v1.25.0+).

### ConstraintVector as Authority Evaluation

The ConstraintVector type is the runtime representation of authority
evaluation over the product lattice. Each ConstraintEvaluation corresponds
to one dimension D_k of the authority space:

```typescript
interface ConstraintEvaluation {
  facet: ConstraintFacet     // which dimension D_k
  status: ConstraintStatus   // pass | fail | not_applicable | unknown
  headroom?: number | string // distance from boundary in D_k
  failure?: ConstraintFailure
}
```

The `status` field maps to the lattice comparison:
- `pass`: auth_k(action) ≤_k auth_k(agent) — action is within authority
- `fail`: auth_k(action) >_k auth_k(agent) — action exceeds authority
- `not_applicable`: dimension D_k is not constrained for this delegation
- `unknown`: insufficient evidence to evaluate (Belnap four-valued logic)

### ConstraintFailure as Lattice Violation Report

When a constraint fails, the ConstraintFailure captures:
- `facet`: which dimension of the lattice was violated
- `limit`: the authority element's value in that dimension (the bound)
- `actual`: the action's required value in that dimension (the request)
- `primaryFailure`: the dimension that would have blocked even if all others passed

This is precisely the information needed to reconstruct the lattice
comparison: the failure occurred because actual >_k limit in dimension k.

### AuthorizationWitness as Lattice State Snapshot

The AuthorizationWitness is a signed snapshot of the agent's position in the
authority lattice at execution time. It captures:
- The delegation that anchored the authority element
- The constraint vector (full lattice evaluation)
- The gateway's signature (the lattice comparison was performed by
  the enforcement boundary, not self-reported by the agent)

This creates a cryptographic record of WHERE in the authority lattice the
agent was positioned at the moment of execution — which is exactly what
dispute resolution needs.

---

## Impact on the Paper

### What Changes in Section 3.2

The current INV-1 formulation:

    scope(d_{i+1}) ⊆ scope(d_i)
    spendLimit(d_{i+1}) ≤ spendLimit(d_i)
    depth(d_{i+1}) < depth(d_i)

Becomes the faceted narrowing formulation:

    auth(d_{i+1}) ≤_A auth(d_i)

where ≤_A is the product lattice ordering over all authority dimensions.
The original three conditions are recovered as Corollary 1 (independent
facet narrowing). The generalization is strictly stronger: it covers
dimensions not present in the original formulation (time, reputation,
values, reversibility) and the claim extends to any future dimensions
added to the authority space.

### What This Adds to the Contribution

1. **Mathematical generalization.** The claim moves from "three things
   narrow" to "narrowing is a structural property of the authority space."
   This is more elegant and more general.

2. **Connection to established CS theory.** The product lattice construction
   connects to LBAC, abstract interpretation, and domain theory — three
   well-cited research areas. Reviewers from the formal methods or PL
   communities will recognize the construction immediately.

3. **Implementation evidence.** The ConstraintVector and AuthorizationWitness
   types in the SDK are direct implementations of the lattice evaluation
   and state snapshot. The paper can cite running code, not just definitions.

4. **Future-proofing.** New constraint dimensions (jurisdiction, collaboration
   quorum, rate limits) fit naturally as additional lattice factors without
   changing the formalization. The product lattice is extensible by design.

### What Does NOT Change

- INV-2 (governance attenuation) is unchanged — it operates on a different
  state object (governance artifacts, not authority elements)
- INV-3 (disclosure attenuation) is unchanged — it operates on audit views
- INV-4 (exception attenuation) remains bounded by INV-1, now stated as
  "the escalation ceiling is an element of A that dominates the escalation
  grant's effective authority"
- The composition properties (C1-C5) remain valid — they constrain which
  invariant takes precedence, not the lattice structure

---

## Additional References

- Cousot, P. & Cousot, R. (1977). "Abstract interpretation: a unified
  lattice model for static analysis of programs." ACM POPL.
- Denning, D. (1976). "A lattice model of secure information flow."
  Communications of the ACM.
- Sandhu, R. (1993). "Lattice-based access control models."
  IEEE Computer.
- Scott, D. (1970). "Outline of a mathematical theory of computation."
  Oxford University Computing Laboratory.
- Davey, B.A. & Priestley, H.A. (2002). "Introduction to Lattices and
  Order." Cambridge University Press. [For product lattice construction]
