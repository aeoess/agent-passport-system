# Changelog

## 7.2.0 (2026-09-24)

One conformance fix and seven opt-in experimental modules for the authority lifecycle.

**Existing behaviour is byte identical.** `AuthorityValidationState` is still the same
four values, `AuthorityVectorV1` is still seven facets, and
`verifyAuthorityDelegationChain` returns byte for byte what 7.1.0 returned for every
record. A caller that imports none of the new modules sees exactly 7.1.0 behaviour.
**The conformance suite output is unchanged**: the Agent Authority Conformance suite's own
`npm test` produces byte-identical output under published 7.1.0 and under this build, exit
0 both times, and all 86 of its family runners and probes exit 0 under both.

What did move is how much of that suite this SDK can decide by itself. Across the 29
lifecycle families, 633 vectors and 635 decision units, an SDK call reproduced the
expected result for **50 of 635 units under 7.1.0 and 161 of 635 under this build**: 111
units across 12 families, with **0 fail and 0 regressions**. The remaining 474 units are
`not_supported`, meaning no SDK API decides them and a family's own harness supplies the
deciding step. `not_supported` is not a failure and not a claim the expected answer is
wrong.

### Fixed

- **Chain selection (draft-03 section 3.3).** `src/v2/chain-selection/`, a surface that
  takes the set of chains an agent holds and reports which ONE of them an action was
  decided against. Section 3.3 states the rule: "Each action selects one root-to-leaf
  authority chain.  A verifier MUST NOT union scopes or budgets from multiple chains.
  Cross-principal composition requires a separate profile." Every other authority entry
  point here takes exactly one chain, so the first sentence had no surface: an
  implementation that evaluated an action against three chains and pooled the answers,
  and one that selected a single chain, were indistinguishable through this SDK. They are
  not any more.

  New public surface, all reachable from the package root:
  `selectChainForAction(input)`, `selectWithFallback(input)`, the types `HeldChain`,
  `RequiredSpendV1`, `AuthorityBudgetReserver`, `ChainEvaluation`,
  `ChainEvaluationOutcome`, `ChainSelectionEvaluationCode`, `ChainSelectionFailureCode`,
  `ChainSelectionInput`, `ChainSelectionWithFallbackInput`, `FallbackAuthorizationV0` and
  `SelectionOutcome`, and the constants `CHAIN_SELECTION_EVALUATION_CODES`,
  `CHAIN_SELECTION_FAILURE_CODES` and `HELD_SET_CEILING`.

  **Additive. Nothing existing changed.** `AuthorityValidationState` is still
  the same four values, `AuthorityVectorV1` is untouched, `verifyAuthorityDelegationChain`
  returns exactly what it returned before for every draft-03 record, and a caller that
  never imports this module sees today's behaviour. The new functions are pure and injectable in
  the same way the chain verifier is: `now` and the three resolvers are the caller's, the
  budget reserver is injected, and nothing here reads a clock, a random source or the
  network. Neither entry point throws.

  **No union, held by construction rather than by a check.** One private function judges
  one chain, and it is the only place a chain is judged, so there is no code path on which
  two chains' scope grants or spend ceilings meet in one comparison. A result names one
  `chain_id`, never a set. A held entry that is two or more chains concatenated into one
  array, which is the shape a caller reaches for to have two chains evaluated together, is
  refused by name as `chain_set_presented_as_one` before verification, rather than being
  reported as the broken parent link chain verification would otherwise call it.

  **Selection rule, this implementation's own.** draft-03 states that an action selects one
  chain and does not state how. Candidates are evaluated in held order. The first that
  verifies `valid` and covers every needed scope grant is selected, the action's spend is
  then reserved against that chain and no other, and a spend refusal is that chain's
  refusal and ends the call. Continuing past a spend refusal to a chain with a larger
  ceiling would be a fallback in everything but name, and `selectChainForAction` does not
  do it.

  **Not established is kept apart from refused.** A candidate whose revocation answer is
  unknown, whose facet profile is unsupported, or whose spend could not be checked because
  no ledger was supplied, is `undecided`, never `refuses`, and one undecided candidate
  makes the whole outcome `selection_undecided` rather than "no chain covers the action".
  Section 3.3 forbids collapsing indeterminate or unsupported into valid, and collapsing
  them into a denial reason would be the opposite error.

- **PROPOSED, not draft-03: the fallback surface.** `selectWithFallback`'s `fallback`
  parameter and the `switched_from`, `fallback_ref` and `fallback_considered` members are the
  one part of this module that is not specified. draft-03 says nothing about what an implementation does after the chain it
  selected turns out to be unusable. `fallback: null` reads no held chain other than the
  preferred one, so a refusal cannot hide a switch. An authorization object permits the
  switch and the result then names the chain switched away from. Nothing specified defines
  what makes a fallback explicitly authorized, so `authorization_ref` is an opaque
  reference this SDK records and never interprets, and its presence is not a claim that
  anything authorized anything. Every symbol carrying this half says so in its doc comment.

- **Parity vectors.** `fixtures/chain-selection/chain-selection-vectors-v0.json`, 19 cases
  over three single-hop chains from three roots to one leaf, generated deterministically by
  `fixtures/chain-selection/generate-fixtures.ts` from published seed labels. Every recorded
  outcome is observed: the generator runs the implementation, compares what it returned
  against a declaration written beside each case, and refuses to write the file if they
  disagree. The Python SDK runs a byte-identical vendored copy of the same file, so a
  behaviour difference between the two implementations fails one of them.

### Changed

- **`createToolRegistryEntry` accepts an optional `verifiedAt` override.** Additive and
  optional. Omit it and the behaviour is exactly what it always was, `verifiedAt` stamped
  from the system clock. Supply it and the function becomes reproducible, so calling it
  twice with the same inputs gives the same bytes and the same signature. `createToolManifest`
  has always taken the same override for the same reason; this brings the legacy entry path
  level with it. No new field on `ToolRegistryEntry` and no change on the default path.

### Naming

- **`AttestorRoleResolver` is exported from the package root under two qualified names.**
  `src/v2/activation/` and `src/v2/bounds/` each define a resolver type that was called
  `AttestorRoleResolver`, and the two have incompatible signatures: the activation one
  takes one `role: string` and answers `holds` / `does_not_hold` / `unknown`, the bounds
  one takes a `roles: readonly string[]` set and answers `holds_role` /
  `does_not_hold_role` / `unknown`. Both are exported from the package root as
  `ActivationAttestorRoleResolver` and `BoundAttestorRoleResolver`. Inside
  `./v2/activation/` and `./v2/bounds/` the bare name is unchanged. Neither qualified name
  has shipped before, so no published consumer changes.

### Experimental (proposed, not specified)

Seven opt-in modules and one root re-export, none of which is required by
draft-pidlisnyi-aps-03. **Implemented does not mean specified.** Each module says so in its own doc comment, every new record
type carries a `proposed:` namespace rather than `aps:`, and every reason code is
module-local. These names are a proposal for the schema owner to rule on or replace, not
minted vocabulary. Nothing here is a conformance claim about draft-03, and nothing here
claims that any legal doctrine applies to AI agents.

- **`src/v2/lifecycle-state/`, the lifecycle state vocabulary. PROPOSED and OPT-IN.**
  A second verdict vocabulary, reported alongside chain verification and never merged into
  it. Nothing here is required by draft-pidlisnyi-aps-03, whose section 3.3 says verbatim:
  "Verification returns one of valid, invalid, indeterminate, or unsupported with a stable
  failure code." That enumeration is closed and this change does not touch it.
  `AuthorityValidationState`, `AuthorityValidationResult` and everything
  `verifyAuthorityDelegationChain` and `verifyAuthorityDelegation` return are byte for byte
  what they were, and a caller that does not import the new module sees no change at all.

  The concept source is the aeoess/agent-authority-lifecycle concept document: invariant L8
  (suspension is not revocation) and invariant candidates BROAD-L7 (any current lifecycle
  state claim is established only from an accepted source, within a declared freshness
  bound, over the coverage the claim states), CAND-04 (activation is established, not yet
  effective, or not established) and CAND-05 (suspension and restriction causes compose).
  Each of those is proposed, with no published specification text behind it, and every
  exported symbol says so in its doc comment.

  New public surface:

  - `LIFECYCLE_VERDICTS`, the six artifact verdicts: `valid`, `invalid`, `not_established`,
    `not_yet_effective`, `suspended`, `restricted`. The enumeration is six. "Unexecutable"
    is an execution outcome rather than a seventh verdict, and no module extends the set as
    a side effect.
  - `BOUNDARY_OUTCOMES`, the separate subject: what an enforcement point decides about one
    action at one authorization boundary, `authorized`, `denied` or `not_established`. A
    composition rule that is not satisfied does not make any artifact invalid, it makes the
    action unauthorized at that boundary.
  - `ESTABLISHMENT_GAPS`, the three limbs `source`, `freshness` and `coverage`. A
    `not_established` verdict must name at least one of them, which the constructor
    enforces, because a denial on an unestablished state that does not say what was missing
    is unreadable.
  - `ESTABLISHED_NEGATIVE_SHAPES` and `resolveEstablishedNegative`, the split between the
    two uses of "not established". The evidential sense, where the verifier cannot reach a
    conclusion, keeps the name. An established negative, where the verifier has reached a
    negative conclusion, resolves to `not_yet_effective` for an enabling condition, or to a
    denial at a boundary for an unsatisfied composition rule or a changed pinned referent,
    and never to `not_established`.
  - `LifecycleStateResult`, `OutstandingCause`, `CompositeAuthorityResult`, `lifecycleState`,
    `notEstablished`, `LifecycleStateError` and the four vocabulary predicates.
    `LifecycleStateResult` deliberately carries no `valid` boolean:
    `AuthorityValidationResult` has one and it is correct there, but here `not_established`
    is not a boolean's false branch and a truthiness shortcut invites exactly the collapse
    the vocabulary exists to prevent.
  - `mapAuthorityValidationToLifecycle(result, options?)`, the opt-in read-only view of an
    existing `AuthorityValidationResult` in the new vocabulary. It never mutates its input
    and is never called from the verification path. One reading in it is worth naming: a
    result whose only failure is `NOT_YET_VALID` stays `invalid` by default, because the
    concept document has not decided whether a waiting grant is invalid or not yet
    effective, and a base module several other surfaces build on should not embed a
    contested reading as a default. `notYetValidAsNotYetEffective: true` takes CAND-04's
    reading, under which such a grant is `not_yet_effective`.

  Cross-language parity: `conformance/lifecycle-state/v0/vectors.json`, 38 hand-specified
  cases, is the shared fixture. The Python SDK vendors a byte-identical copy and runs the
  same cases through its own port, and both repositories pin the file's SHA-256 inside their
  own test, so a one-sided edit fails on the side that was edited. Tests live at
  `tests/v2/lifecycle-state.test.ts`.

- **`src/v2/activation/`, activation conditions and condition attestation. PROPOSED and
  OPT-IN.** A grant can be validly issued and still wait on a date or a recorded event. This
  module decides whether such a condition is established for one action at one instant, and
  reports the answer alongside a chain result rather than inside it.

  Nothing here is required by draft-pidlisnyi-aps-03. The published text states no
  activation-condition rule, no attestor role and no attestation-acceptance rule: a
  case-insensitive search of it for `activation`, `attestor` and `contingen` returns nothing.
  Its section 3.2 also says verbatim: "authority contains exactly seven required facets:
  scope, spend, depth, time, reputation, values, and reversibility. A missing facet is
  invalid rather than an implicit unconstrained value." That closes the authority vector, so
  an activation condition can never be a facet, and this module models it as a SEPARATE
  artifact referencing a `delegation_id`. `AuthorityVectorV1`, `AuthorityValidationState`,
  `AuthorityValidationResult` and everything `verifyAuthorityDelegationChain` returns are
  byte for byte what they were, and a caller that does not import the new module sees no
  change at all.

  The concept source is the aeoess/agent-authority-lifecycle concept document, which carries
  "Activation condition" as proposed with no case testing it, and its invariant candidates
  CAND-04 (activation is established, not yet effective, or not established), CAND-13
  (replacement authority may be pre-committed at issuance) and BROAD-L7. All proposed, with
  no published specification text behind them, and every exported symbol says so in its doc
  comment.

  New public surface:

  - `verifyActivation(input)`, which returns `valid`, `not_yet_effective` or
    `not_established` in the `src/v2/lifecycle-state/` vocabulary, and NEVER `invalid`. An
    unmet activation condition does not make a grant invalid, and whether the grant is valid
    at all is chain verification's answer rather than this module's.
  - The split the module exists for. `not_yet_effective` is an established negative: an
    accepted record says the condition had not occurred, or puts its first occurrence after
    the action, and the remedy is to wait. `not_established` is ignorance, names which of
    `source` and `coverage` was missing, and its remedy is a better source. A rejected
    attestation is not evidence in either direction, so a record from a source the model does
    not accept leaves the condition unestablished rather than unmet.
  - No retroactive activation, keyed on the CONDITION's own instant rather than on the
    instant someone wrote the record. A record putting the first occurrence after the action
    leaves that action `not_yet_effective`, and the same record establishes the condition for
    any later action. Learning on Thursday that a condition was met on Monday is the normal
    case for a model built around an after-the-fact determination, and it establishes the
    condition.
  - `composeActivation(chain, activation, options?)`, which returns the chain result
    untouched and asks activation only when the chain is valid. A grant that does not verify
    is not a grant that is waiting on a condition. That ordering is also what keeps invariant
    L1 intact for CAND-13's pre-committed replacement grant: if the pre-committing instrument
    is revoked, the replacement's chain is invalid and no activation evidence can make it
    exercisable.
  - `ActivationConditionV0` in two kinds. A `date` condition needs no evidence at all, so an
    unreached date is always a known negative. A `recorded_event` condition names
    `required_attestor_roles`, which are ROLES and never principals.
  - `AttestorRoleResolver`, a caller-supplied callback returning `holds`, `does_not_hold` or
    `unknown`. Exported from the package root as `ActivationAttestorRoleResolver`; see
    Naming above. Three values, not a boolean: "this registry does not know" is a distinct answer
    from "this party does not hold that role", and collapsing the first into the second turns
    ignorance into a denial. Role standing is resolved OUTSIDE the record, always. An
    attestation's `attestor_role` is the attestor's claim about itself, and the module checks
    that claim against the resolver rather than believing it.
  - `validateActivationCondition`, the canonical-bytes helpers
    (`activationAttestationBody`, `activationAttestationSignatureInput`,
    `computeActivationAttestationId`, `activationConditionSignatureInput`), three distinct
    domain tags that each carry `PROPOSED` so nothing signed under them can be replayed as a
    specified record, and `ActivationError` for shape rules broken at the call site.

  THREE PARAMETERS ARE DELIBERATELY UNDEFAULTED, because the concept text has not decided
  them and a default in an SDK is a ruling made by whoever wrote the SDK. `instant_basis`
  (which instant an occurrence is measured from), `threshold` (how many acceptable
  attestations establish a finding), and role standing (resolved through the caller's
  resolver). Vector `AC-14` is the pair that proves the first is load bearing: one record, one
  action instant, and opposite verdicts under the two readings.

  Cross-language parity: `conformance/activation/v0/vectors.json`, 12 condition-shape cases,
  34 verify cases and 7 composition cases, all hand specified in
  `conformance/activation/v0/generate.mts` and none computed by the code under test. The
  Python SDK vendors a byte-identical copy and runs the same cases through its own port, and
  both repositories pin the file's SHA-256 inside their own test, so a one-sided edit fails on
  the side that was edited. Tests live at `tests/v2/activation.test.ts`.

- **`src/v2/bounds/`, non-time bounds on a grant. PROPOSED and OPT-IN.**
  Purpose, use-count and budget bounds, and the state "this bound has been reached".
  Nothing here is required by draft-pidlisnyi-aps-03 and nothing existing changed. Two of
  that document's sentences constrain the whole module. Section 3.2, verbatim: "authority
  contains exactly seven required facets: scope, spend, depth, time, reputation, values, and
  reversibility.  A missing facet is invalid rather than an implicit unconstrained value."
  The facet set is closed, so a purpose bound or a use-count bound cannot live inside a
  signed `AuthorityDelegationV1`, and this module declares a separate artifact that
  references a delegation by its content address. Section 3.3, verbatim: "Verification
  returns one of valid, invalid, indeterminate, or unsupported with a stable failure code."
  That set is closed too and this change does not touch it: a bound evaluation is reported
  alongside a chain result, in the vocabulary `src/v2/lifecycle-state/` owns. A caller that
  does not import the new module sees no change at all.

  draft-03 has zero occurrences of `exhaust` and zero of `use_count`. It uses "single-use"
  only of an approval in section 4.3, never of a grant. The concept source is the
  aeoess/agent-authority-lifecycle concept document: invariant L10 (expiry is not
  revocation), whose "Expiry or exhaustion" concept entry names a use count, a budget and a
  purpose as bounds whose being reached ends authority, and invariant candidates CAND-01 (an
  external event is authority-changing only when established) and CAND-02 (later evidence
  does not rewrite earlier evidence). All three are proposed, with no published
  specification text behind them, and every exported symbol says so in its doc comment.

  New public surface:

  - `AuthorityBound`, a bound declared on one delegation: a kind, a value, and the
    fulfilment-attestor ROLES who may say it was reached. Roles rather than principals,
    because whoever may attest that a compressor was installed is whoever holds the role now,
    not whoever held it when the grant was signed. The module does not authenticate the bound
    declaration itself and says so: that is the caller's step, by whatever means its authority
    model provides.
  - `AuthorityBoundFulfilment` and `issueAuthorityBoundFulfilment`, a signed attestation that
    a purpose bound was reached. Modelled on what section 3.5.1 requires of a revocation
    record, which is the nearest published shape for "a party with standing recorded that an
    authority artifact's state changed".
  - `assessFulfilment`, which assesses ONE record. Standing is asked BEFORE authenticity, and
    each produces its own reason code, because "authenticated by somebody who may not say
    this" and "not authenticated at all" are different failures. A record from a party with
    standing saying the purpose was NOT met is the one rejection that carries no missing
    limbs: the verifier reached a conclusion, so there is no gap to name.
  - `evaluateBound`, which answers `not_reached`, `exhausted` or `not_established` at an
    instant, alongside the same conclusion in the lifecycle vocabulary and an `ending` field
    that is `exhaustion` or `null` and never `expiry` or `revocation`. An unauthenticated
    fulfilment claim gives `not_established`, never `exhausted` and never `not_reached`. An
    exhaustion that was established is not downgraded by a later claim nobody could
    authenticate, and the verdict does not depend on the order the records arrive in.
  - `issueAuthorityExhaustion` and `verifyAuthorityExhaustion`, the OPTIONAL signed exhaustion
    record, shaped like the section 3.5.1 revocation record so the two endings are comparable
    evidence. It attests the enforcement boundary's own finding and not the state of the
    world, on the model section 5.3.3 uses for an action result, verbatim: "An action-result
    record attests to what the enforcement boundary observed after dispatch.  External
    occurrence or settlement requires separately resolved evidence." Issuance REFUSES for any
    state other than `exhausted`, with no override.
  - `isPurposePermitted` and `purposeCategory`, re-exported unchanged from
    `src/core/data-lifecycle.ts`, which still exports them from their old path. The Python SDK
    had no port of either, and putting the same primitive at two unrelated paths in the two
    languages would become a cross-language annoyance the first time a vector referenced it.
    Purpose membership is not purpose exhaustion: it answers the same for the second purchase
    as for the first, which is why it can never decide exhaustion.
  - The `budget` kind delegates to `InMemoryAuthorityBudgetLedger` and never reimplements it.
    It reads the `{ committed, reserved }` shape `counter()` already returns. draft-03 section
    3.4 already states the rule, verbatim: "Signatures establish static limits; they do not
    establish the current cumulative total."

  Cross-language parity: `conformance/authority-bounds/v0/vectors.json`, 53 cases, is the
  shared fixture. The Python SDK vendors a byte-identical copy and runs the same cases through
  its own port, and both repositories pin the file's SHA-256 inside their own test, so a
  one-sided edit fails on the side that was edited. Every verdict, reason code and refusal
  code in it is hand specified, and the signature and identifier byte values are there so the two
  ports can be shown to emit the same characters. Tests live at `tests/v2/bounds.test.ts`.

- **`src/v2/capability-binding/`, capability pins and identifier binding. PROPOSED and
  OPT-IN.** Whether an action through a named tool is established under a grant that pins
  that tool, and whether an authority path that depends on an off-chain identifier still
  depends on the same party. Nothing here is required by draft-pidlisnyi-aps-03, which
  defines no pin syntax and states no rule pinning a tool to an implementation digest or a
  schema. Its nearest text is the section 4.1 action reference, verbatim: "target is the
  exact resource, tool, or endpoint against which the action will be dispatched; a profile
  MUST define its target string construction." A target carries no digest, so it cannot
  tell two revisions of one tool behind one endpoint apart. Proposed -04 excludes
  capability binding by name.

  `AuthorityValidationState` is unchanged, `verifyAuthorityDelegationChain` returns byte
  for byte what it returned, and `AuthorityVectorV1` gains no eighth facet (section 3.2
  closes it at seven and makes a missing facet invalid). Every result here is a
  `BoundaryOutcome` from the lifecycle state vocabulary, reported alongside a chain result
  and never merged into it. Nothing in this module makes any delegation invalid. A caller
  that does not import it sees exactly today's behaviour.

  The concept source is the aeoess/agent-authority-lifecycle concept document, invariant
  candidate CAND-07 as rewritten, whose statement is a verdict rule: where nothing pins a
  referent, the verdict records that referent continuity was not established rather than
  admitting silently, and where something pins it and the pin does not match, the action is
  denied with a mismatch reason rather than reported as not established. Also the
  `AUTHORITY-LIFECYCLE.md` concepts "Action or capability binding", "Target binding" and
  "Authority path and dependency". All proposed, with no published specification text
  behind them, and every exported symbol says so in its doc comment.

  New public surface:

  - `evaluateCapabilityBinding`, the capability limb. An unpinned grant returns
    `not_established` naming the coverage limb, never a silent admit. A pinned digest
    established not to match returns `denied` with a mismatch reason, which is an
    established negative rather than ignorance. Implementation and declared metadata are
    two axes pinned separately, so an implementation pin does not cover a schema change.
  - `evaluateIdentifierContinuity`, the identity limb. An identifier the grant does not
    declare, a declared identifier with no pinned controller, a lapse, an unresolved
    conflict between two accepted custodian records, an uncovered interval since issuance
    and a retention record from a party without standing each get their own reason code. A
    single accepted holder that is not a pinned controller is `denied`, and the result
    names who holds the identifier now.
  - `capabilityImplementationDigest` and `capabilityMetadataDigest`. The first is byte
    identical to what `createToolRegistryEntry` computes. The second is over
    `domain || 0x00 || JCS(metadata)` with a REQUIRED domain and no default, and it keeps
    null members, which the SDK's legacy `canonicalize` strips.
  - The `scope_grant_v0` pin encoding, `parseCapabilityPinFromScopeGrants` and
    `capabilityPinScopeGrants`, which keeps a pin inside the scope grammar section 3.2
    already defines. The side effect is stated in the module: a pin then narrows across a
    chain by the ordinary covering rule, so a child carrying a different pin fails as scope
    widening rather than as a binding failure.
  - `observeToolAttestation`, which runs the existing `verifyToolIntegrity` and resolves
    the attestor key BY TOOL, never from the `attestorId` the presented entry asserts about
    itself.
  - `identifierRecordSignedBytes`, `referentBindingResult`,
    `projectBoundaryOutcomeToCandidateV0` and the two reason-code enumerations.

  `ReferentBindingResult` carries no `valid` boolean, on the same reasoning as
  `LifecycleStateResult`: `not_established` is not a boolean's false branch.

  `conformance/capability-binding/v0/vectors.json` holds 18 capability cases, 15 identifier
  cases and the digest, scope-grant and canonical-byte known answers. It is the shared
  fixture. The Python SDK vendors a byte-identical copy and runs the same cases, and both
  repositories pin the file's SHA-256 inside their own test.

- **`src/v2/status-coverage/`, multiple trusted status sources with freshness bounds.
  PROPOSED, EXPERIMENTAL and OPT-IN.**
  Decides what one authorization boundary can establish about one `authority_ref` from a SET
  of status answers, each measured against the freshness bound declared for its own source.
  Conflict between accepted sources, or staleness past a declared bound, gives not
  established. An offline verifier holding a snapshot inside a bound it declared in advance
  may admit, and the record names the snapshot and the age it admitted at.

  Nothing here is required by draft-pidlisnyi-aps-03. Section 3.3 rules one revocation
  result per chain member and closes verification at, verbatim: "Verification returns one of
  valid, invalid, indeterminate, or unsupported with a stable failure code." It says nothing
  about two sources answering about the same member, nothing about a per-source freshness
  bound, nothing about coverage over a declared source set, and nothing about an offline
  admission on a snapshot. `AuthorityValidationResult`, `verifyAuthorityDelegationChain` and
  the whole of `src/v2/revocation-enforcement/`, including `FreshnessPolicy`,
  `decideFreshness` and `RevocationObservation`, are unchanged. This decision is reported
  alongside a chain result, never merged into it, and a caller that does not import the new
  module sees no change at all.

  The concept source is the aeoess/agent-authority-lifecycle concept document: invariant L7
  (unknown revocation state is not active), which is the published-text half, and invariant
  candidate BROAD-L7, all three limbs, which broadens L7 to any current lifecycle state
  claim. BROAD-L7 is proposed, and every exported symbol says so in its doc comment.

  New public surface:

  - `decideMultiSourceStatus(input)`, the decision. Pure: no clock, no network, no crypto.
    It returns a `MultiSourceStatusDecision` carrying two subjects kept apart, the boundary
    `outcome` and the artifact `lifecycle` verdict in the `src/v2/lifecycle-state/`
    vocabulary, plus a module-local `reason_code` and a `basis` block.
  - `StatusTrustPolicy`, `RequiredSourceSet`, `DeclaredStatusSource` and `SnapshotSource`:
    what the relying party accepts, with a freshness bound declared PER SOURCE rather than
    globally, and, in offline mode, a snapshot source with the maximum age it declared in
    advance that it would admit on. The declared bound is required, so admitting on a
    snapshot with no declared bound is unreachable rather than merely discouraged.
  - `MultiSourceStatusBasis`, the audit half, and it is not optional. Every answer gets a
    line carrying its age, the bound it was measured against, whether it was within that
    bound, whether it was used, and a `StatusUseBasis` saying why. An admission on a
    snapshot additionally records the snapshot and the age it admitted at, so the admission
    can be recomputed from the record alone.
  - `ConflictPolicy` and `StaleAnswerPolicy`, both REQUIRED PARAMETERS WITH NO DEFAULTS.
    That is unusual for an SDK and it is deliberate. What a conflict returns, and whether an
    answer past its own bound still counts, each have two defensible readings of the
    proposed text, and the two readings give opposite verdicts on the deployment-relevant
    case. A default on either would be this SDK making a specification decision in code.
    `RequiredSourceSet.silence_is` is required for the same reason.
  - `StatusCoverage`, coverage over the DECLARED required-source set. This is NOT a
    completeness claim. It reports whether every member of a set the relying party declared
    produced a usable determinate answer, and nothing more. Invariant L12 is open, and a
    `complete: true` block must not be read as a statement that the declared set was every
    source that mattered.

  Two further readings the module fixes rather than parameterises, both recorded in the
  basis so a reader can see them: an answer dated after the boundary instant is refused as
  skew rather than read as fresh, and an answer from a source the trust policy does not name
  is recorded and ignored rather than used.

  Cross-language parity: `conformance/status-coverage/v0/vectors.json`, 24 hand-specified
  decision cases and 16 refusal cases, is the shared fixture. The Python SDK vendors a
  byte-identical copy and runs the same cases through its own port, and both repositories
  pin the file's SHA-256 inside their own test. Tests live at
  `tests/v2/status-coverage.test.ts`.

- **`src/v2/authority-state/`, authority state markers, write fencing, and revocation
  withdrawal. PROPOSED and OPT-IN.**
  Three surfaces the authority-lifecycle work needs and draft-pidlisnyi-aps-03 does not
  contain. The published text has no occurrence of `epoch`, `fencing`, `snapshot`, `replica`
  or `restore`, and defines no record for withdrawing a revocation. What draft-03 does fix
  stays fixed: section 3.5, "Revocation is irreversible", and section 3.3's four-value
  result. `AuthorityValidationState`, `AuthorityValidationResult`, `AuthorityRevocationStore`,
  `AuthorityChainVerificationOptions` and `createAuthorityRevocationResolver` are unchanged,
  no store gains a removal method, and a caller that does not import the new module sees no
  change at all.

  The concept source is the aeoess/agent-authority-lifecycle concept document: the
  `Authority epoch` concept, invariants L3, L7 and L11, the `Authority rollback` open
  question, and invariant candidates CAND-08 (no silent restoration from rollback or stale
  state) and CAND-02 (later evidence does not rewrite earlier evidence). The open question
  is open, the candidates are proposed, and every exported symbol says so in its doc comment.

  New public surface:

  - `StateMarker` and `stateMarker`, an opaque comparable supplied by the caller: a
    canonical unsigned decimal value as a string, and a scope of `global`, `per_delegation`,
    `per_principal` or `per_store`. Nothing is signed and nothing is a wire field. The
    proposed text says an authority epoch is "where a system uses generations" and stops, so
    this SDK defines only the comparison.
  - `compareStateMarker` and `advanceHighWaterMark`. Equal is `forward`, behind is
    `regressed`, and a first read or a cross-scope comparison is `unplaceable`, which is
    deliberately not a verdict. The mark only ever moves forward.
  - `RetainedAuthorityState` and `resolveUnderRetainedState`. The retained record set and the
    high-water mark are two inputs, not one "epoch", because a verifier that kept the
    epoch-N revocation records and one that kept only the number give different answers about
    the same restored view. A retained record set answers `revoked` or `unknown` and never
    `active`.
  - `createMonotonicRevocationResolver`, which composes a presented view, a mark and a
    retained set into the one-argument resolver `verifyAuthorityDelegationChain` already
    takes. `onUnplaceable` is required with no default, because choosing between reading a
    first-contact view and refusing it is a question the concept source records as undecided.
  - `FencedAuthorityStateLog`, the fencing gate on an authority-state write. A token that
    went backwards is refused, an equal token is accepted and idempotent, and a refused write
    changes neither the published payload nor the highest token.
  - `RevocationWithdrawalV0`, `evaluateRevocationWithdrawal`, `correctedRevocationView` and
    the injected `WithdrawalStandingResolver`. A withdrawal references a revocation and never
    removes it: no path in the module deletes a revocation from a store, and the chain
    verdict after an accepted withdrawal is byte for byte what it was. Standing is resolved
    outside the record, and a standing question the resolver could not answer is reported as
    not established rather than as a denial.
  - `authorityStateReport` and `reportAuthorityState`, which carry a chain result, a
    lifecycle verdict, the monotonicity finding and any correction records together without
    any of them rewriting another.

  `conformance/authority-state/v0/vectors.json` holds 49 hand-specified cases and is the
  shared fixture. The Python SDK vendors a byte-identical copy and runs the same cases, and
  both repositories pin the file's SHA-256 inside their own test.

- **`src/v2/suspension/`, suspension and restriction as a SET OF CAUSES. PROPOSED and OPT-IN.**
  Nothing here is required by draft-pidlisnyi-aps-03. The published draft states no
  suspension rule, no restriction rule, no release rule and no lifecycle-standing rule: a
  case-insensitive search of its plain text returns zero occurrences of `suspend` and
  `suspension`, and the only status answer the protocol has is the revocation resolver's
  closed set `'active' | 'revoked' | 'unknown'`. There is nowhere in that type to put one
  cause, let alone three. Section 3.2 closes the authority vector at seven facets and calls
  a missing facet invalid, so no cause can ride inside a signed `AuthorityDelegationV1`
  either. `AuthorityValidationState`, `AuthorityValidationResult`, `RevocationResolution`
  and everything `verifyAuthorityDelegationChain` and `verifyAuthorityDelegation` return are
  byte for byte what they were, and a caller that does not import the new module sees no
  change at all.

  The concept source is the aeoess/agent-authority-lifecycle concept document: invariant L8
  (suspension is not revocation, which says nothing about ARITY, so an implementation
  holding exactly one suspension at a time conforms to every word of it and is still wrong)
  and invariant candidate CAND-05 (suspension and restriction causes compose), with the
  `OPEN-QUESTIONS.md` entry "Release from suspension" as the paragraph that names the gap:
  lifting one suspension should not clear another or bypass a revocation that happened while
  the agent was suspended, causes probably need to compose with each released separately,
  and none of it is specified. CAND-05 states that composition is forced by the corpus and
  externally unsourced. Every exported symbol says so in its doc comment.

  New public surface:

  - `SuspensionCause`, a lifecycle cause as a SEPARATE SIGNED ARTIFACT referencing a
    `delegation_id`, carrying its `kind` (`suspension` or `restriction`, the two invariant
    L8 separates), who imposed it, when, and a stable reason code.
  - `SuspensionRelease`, a record naming every cause it claims to clear. One release may
    clear several causes, which CAND-05 explicitly does not forbid. What is forbidden is
    releasing cause A having the side effect of clearing cause B, so each named cause is
    decided independently and a record with standing over two of three clears exactly those
    two. A release record is not a list of assertions a verifier accepts wholesale.
  - `evaluatePauseState(input)`, returning a `LifecycleStateResult` whose `outstanding`
    member is the remaining cause set. NEVER A COUNT AND NEVER A BOOLEAN: that member being
    a list is the whole of CAND-05 in one field.
  - `explainPauseState(input)`, the same computation with the per-record and per-cause
    audit trail, for a caller that has to record why each record did or did not move the
    answer.
  - `composeChainAndPause(chain, pause)`, the rule that A RELEASE NEVER CLEARS A REVOCATION
    THAT HAPPENED MEANWHILE. When the chain result is anything other than `valid` it is
    returned unchanged and the pause state is not reported; draft-03 section 3.5 says
    verbatim "Revocation is irreversible" and a release record is a later record about the
    causes, not about the chain.
  - `SUSPENSION_CAUSE_TYPE`, `SUSPENSION_RELEASE_TYPE`, `PAUSE_KINDS`, `RELEASE_STANDINGS`,
    `SUSPENSION_REASON_CODES`, `suspensionRecordPreimage`, `SuspensionCauseError` and the
    disposition and resolver types.

  Three design positions worth naming, each of them a reading rather than a rule:

  - **Standing is resolved outside the record, always.** `resolveReleaseStanding` is a
    caller-supplied callback and the module never reads standing from the artifact asserting
    it. A cause may carry an advisory `release_authority`, and the evaluator does not consult
    it; a negative-control test sets that member to the releasing party and asserts the
    release is still ineffective when the resolver says `no_standing`. Standing is also not
    authorship: CAND-05 says a source may hold standing over a cause it did not impose, and
    an implementer who reads "standing over that cause" as "the source that imposed it" gets
    the superior-authority case wrong.
  - **An unverified claim does not become a lifecycle state.** A cause record whose signature
    does not verify, or whose verification method is not bound to the imposer it names, holds
    nothing. Reporting `suspended` on it would convert an unauthenticated assertion into a
    pause the artifact never carried.
  - **A standing answer of `unknown` gives `not_established`, not `suspended`.** Failing to
    establish that a cause was released is not establishing that it still holds. The other
    reading is available and the proposed text settles neither.

  Three things this module deliberately does not decide, all recorded rather than papered
  over: no precedence order among causes, because CAND-05 defines none and says so; what
  wins in the reverse ordering, a revoked chain with causes still outstanding, where
  `composeChainAndPause` reports the chain as a choice of what to report first rather than a
  claim that the causes stopped mattering; and where standing comes from, which no published
  or proposed text answers and which the parity fixture supplies as a fixture object.

  Cross-language parity: `conformance/suspension-causes/v0/vectors.json`, 29 evaluation
  cases, 6 composition cases and 6 malformed-input cases, is the shared fixture. Records are
  minted deterministically from published seed labels, so the file carries no secret material
  and regenerates byte for byte. The Python SDK vendors a byte-identical copy and runs the
  same cases through its own port, and both repositories pin the file's SHA-256 inside their
  own test, so a one-sided edit fails on the side that was edited. Tests live at
  `tests/v2/suspension.test.ts`.

- **The tool manifest and namespace-claim layer is reachable from the package root.**
  EXPERIMENTAL. `createToolManifest`, `verifyToolManifest`, `reviseToolManifest`,
  `reapproveToolManifest`, `createNamespaceClaim` and `verifyNamespaceClaim` have shipped
  in `src/core/tool-integrity.ts` with full declarations and their own tests for several
  releases, and only `createToolRegistryEntry` and `verifyToolIntegrity` were re-exported
  from the root, so a consumer installing the package could not reach them at all. They are
  now re-exported, along with `ToolManifest`, `ToolManifestResult`, `ToolMetadata`,
  `ToolTrustRoot`, `NamespaceClaim` and `ToolResolveOpts`. No implementation changes and no
  signature changes. draft-03 defines no manifest, no namespace claim and no tool-metadata
  digest, so treat these names as subject to change.

  One known limit, stated rather than left to be discovered: `ToolManifest.metadataHash` is
  taken over the legacy `canonicalize`, which strips null-valued members and carries no
  domain separation, so a metadata block with an explicit null member and one omitting that
  member hash to the same value. That is pre-existing signed-artifact behaviour and is left
  alone, because changing it would invalidate manifests already signed.
  `capabilityMetadataDigest` is a different digest and not a drop-in for it.

## 7.1.0 (2026-09-22)

### Added

- **draft03-repair.** Draft-native direct revocation for `AuthorityDelegationV1`, under
  `src/v2/authority-revocation/`. Draft-03 section 3.5 states that any delegation may be
  revoked by its issuer, and section 3.5.1 requires a revocation to produce a signed record
  carrying the revoked delegation's identity, the revocation time inside the signed content,
  a reference to the revoking authority, and a machine-readable reason code with optional
  free-text detail, with a transaction identity shared by every record one cascade produces.
  The SDK had no such record: the only revocation record it carried was the pre-draft
  `RevocationRecord`, which has no record type, no domain-separated preimage, no nonce, no
  cascade transaction identity, a raw public key where the draft names an authority, and
  free text where the draft requires a reason code. That record is untouched and is not
  reused here; the two models stay distinguishable.

  New public surface: `AuthorityRevocationV1` and its body type,
  `issueAuthorityRevocation(delegation, input, privateKey)`,
  `verifyAuthorityRevocation(candidate, delegation, options)`,
  `recordAuthorityRevocation(store, delegation, candidate, options)`, the
  `AuthorityRevocationStore` boundary with `InMemoryAuthorityRevocationStore` as a reference
  implementation, `createAuthorityRevocationResolver(store, options)`, and the canonical
  helpers behind three domain tags: `APS-AUTHORITY-REVOCATION-ID-V1`,
  `APS-AUTHORITY-REVOCATION-SIGNATURE-V1` and
  `APS-AUTHORITY-REVOCATION-CASCADE-TRANSACTION-ID-V1`, each followed by one zero byte
  before the JCS bytes. The identifier covers the record with `revocation_id` and `signature` absent; the
  signature covers the record with `signature` absent, so the identifier is signed rather
  than being a label beside the signature; the cascade transaction identity covers the body
  with `cascade_transaction_id` absent. All three are independently recomputable from the
  record, and verification recomputes each rather than accepting what the issuer wrote.

  Issuance takes the revocation time from a caller-supplied `now`, never from a clock, so
  the same inputs produce the same bytes. Authorization applies the section 3.5 rule and
  nothing else: `input.revoker` is compared to the TARGET delegation's own `issuer` member,
  after the target's `delegation_id` has been recomputed from its own body. No field inside
  a revocation authorizes that revocation, and verification resolves the signing key under
  the target's `issuer` rather than under the `revoker` the record carries.

  **No grammar is imposed on `reason_code` or on `verification_method` beyond being a
  non-empty string.** Section 3.5.1 asks for a machine-readable reason code and fixes no
  grammar for one, so none is invented. Nor does any local rule relate
  `verification_method` to `revoker`: whether a method belongs to the issuer is decided
  only by key resolution against the target delegation's `issuer` at `revoked_at`, which
  verification already performs, and a string shape checked locally could not establish it.

  `createAuthorityRevocationResolver` feeds the resolver `verifyAuthorityDelegationChain`
  and `issueSubAuthorityDelegation` already accept. It answers `'revoked'` only for a
  record that verifies against the delegation, and `'active'` only for a delegation the
  store says it tracks and holds no revocation for. **Absence from a store is never
  `'active'`**: an untracked delegation resolves `'unknown'`, which the chain verifier
  already reports as indeterminate under `REVOCATION_UNKNOWN`. A stored record that does
  not verify also resolves `'unknown'`, never `'active'`.

  Scope is direct revocation of one delegation. **No cascade-derived record and no
  cascade-completion record is issued or verified, and nothing in this surface says a
  cascade is complete.** Section 3.5.1 emits a completion record only after the last
  descendant's revocation is persistent, which needs an authoritative enumeration of
  descendants and a durability guarantee this SDK does not have. Enforcement against
  descendants does not wait on either: a chain containing a revoked ancestor fails chain
  verification under the existing `REVOKED` outcome as soon as the resolver reports that
  ancestor revoked, with no per-descendant record involved.

  First VERIFIED revocation for a delegation wins and revocation is irreversible (INV-5).
  `recordAuthorityRevocation(store, delegation, candidate, options)` is the one supported
  way a revocation enters a store: it verifies the candidate against the delegation it
  names and calls the store's write primitive only on a `valid` result. A valid record
  arriving second is reported `recorded: true, inserted: false` with the record already
  held, unchanged; two requests with different nonces mint two different valid records and
  the store keeps the first. A candidate that does not verify is reported
  `recorded: false` with its own verification result and no record at all, even when the
  delegation already has one, so a refused request is never handed somebody else's record
  as its own result.

  The store's write member is `insertVerifiedRevocation(revocation)`, documented as a
  persistence primitive that accepts only a record `recordAuthorityRevocation()` has
  already verified, and returning `{ inserted, stored }`. It is not an entry point for
  arbitrary records: a store cannot verify, because verification needs the target
  delegation and a key resolver and a store holds neither. The check for an existing record
  and the write are one indivisible operation, a single synchronous statement sequence in
  the in-memory reference, so two callers racing on the same delegation cannot both observe
  `inserted: true`. For a **durable** implementation the contract is an atomic conditional
  insert keyed by `delegation_id`; **read-then-write does not satisfy it under
  concurrency**, since two callers can both read an empty slot before either writes and the
  second write would then displace the first.

- `verifyReceiptPredecessorV1(receipt, predecessor)` binds an action-result record to the
  policy-decision record it follows. Section 5.3.3 lines 1104-1105 states that for an
  action-result record prev is the consumed policy-decision receipt_id and that decision_ref
  MUST equal that decision's decision_ref; section 5.6 line 1219 lists prev validation among
  a verifier's checks. The prev linkage carries no BCP 14 keyword, so **this check is opt-in
  hardening, not a draft-03 conformance fix, and draft-03 does not require a verifier to
  perform it.** The predecessor's receipt_id is recomputed from its body rather than read
  from its claimed `receipt_id` field, which sits outside its own preimage and is therefore
  an unauthenticated label. Returns `valid`, `invalid`, `indeterminate` when no predecessor
  was supplied, or `not_applicable` for a record that is not an action-result, each with a
  single failure code.

  Scope is action-result records only. The policy-decision to action-intent link of section
  5.3.2 line 1072 is out of scope. The primitive does **not** verify the predecessor's
  signatures and resolves no keys; callers verify the predecessor separately.

- `verifyReceiptWithDecisionV1` accepts an OPTIONAL `predecessor` in its options and reports
  a new result field `predecessor_bound`: `'not_checked'` when the options carry no
  `predecessor` property, `'not_applicable'` for a record that is not an action-result,
  `'not_established'` when the property is present but holds `undefined` or `null`,
  otherwise `true` or `false`. A `false` makes the composite invalid under the error code
  `predecessor_not_bound`. With the property absent, which is the default, every other field
  of the result is unchanged from the previous release, including `valid`, `status` and
  `errors`.

  **The opt-in is the presence of the property, not the value it holds.** A caller writing
  `{ predecessor: store.get(receipt.prev) }` has asked for the binding, and a lookup miss
  puts `undefined` in that property. Such a call reports `predecessor_bound:
  'not_established'` with `status: 'indeterminate'`, `valid: false` and the primitive's
  `predecessor_not_supplied` code in `errors`, rather than the `valid` it would return for
  an option nobody passed. An `invalid` found elsewhere still dominates. This axis remains
  **opt-in hardening, not a draft-03 conformance fix**: draft-03 states the prev linkage
  without a BCP 14 keyword and does not require a verifier to make the comparison.

### Fixed

- Previously unreachable draft-03 authority-delegation functions are now exported from the
  package root: `issueAuthorityDelegation`, `issueSubAuthorityDelegation`,
  `verifyAuthorityDelegation`, `compareAuthority`, `isValidScopeGrant`, `scopeGrantCovers`,
  `grantsAreCanonical`, `scopeNarrows`, `InMemoryAuthorityBudgetLedger`,
  `isAuthorityDelegationV1` and `validateAuthorityDelegationShape`, along with the
  `SubAuthorityIssueOptions`, `BudgetReservationState` and `BudgetOperationResult` types
  their signatures need. This closes the "Public reachability" gap the 7.0.0 entry below
  describes: `core/delegation.ts`'s own doc comment told callers to build a
  draft-03 chain with `issueAuthorityDelegation` and `issueSubAuthorityDelegation`, and
  none of these were importable from `agent-passport-system`. No behavior change: every
  export is the same function already used internally by the chain verifier, the
  revocation resolver and the budget ledger.

## 7.0.0 (2026-09-20)

Reconciles three surfaces against draft-pidlisnyi-aps-03: action references,
AuthorityDelegationV1 and ReceiptV1. Major, because previously accepted inputs can now
return `invalid`, `unsupported` or `indeterminate`, so a caller that branches on
verification state can observe different behaviour without changing its own code. This is
not a claim of complete draft-03 implementation. See "What a valid result does not
establish" below.

### Breaking

- Receipt verification applies the section 5.3 stage rules. `verifyReceiptV1` and
  `verifyReceiptV1Serialized` return `invalid` for a record that breaks its own stage and
  `unsupported` for a `receipt_type` outside section 5.3. A deployment carrying receipts
  under its own receipt_type sees `unsupported` where it previously saw `valid`.
- `delegation_ref` must be `sha256:` followed by 64 lowercase hex. A bare digest, accepted
  before by both the envelope validator and the issuer, is refused. The shared
  known-answer receipt used a bare digest, which is why its digests moved.
- Only required signatures decide the aggregate receipt state. A non-required signature
  appended by a third party can no longer flip a conforming receipt. Because signatures sit
  outside the `receipt_id` preimage, such an append does not change `receipt_id`. A
  malformed signature descriptor still makes the envelope invalid.
- Key resolution is reported on its own axis. An unsupported identifier scheme is
  `unsupported`. Not found, ambiguous, structurally malformed key material and unreachable
  resolution are `indeterminate`, each with its own code. Malformed key material no longer
  falls through to `signature_invalid`, because no signature check ran.
- Composite verification of a policy-decision receipt is `indeterminate` when the caller
  supplies no expected enforcement-boundary identity. A call that returned `valid: true`
  now returns `valid: false` until `boundaryIdentity` is passed. A conforming deny decision
  now verifies, where it previously failed.
- The serialized verifier's own nesting-depth and wire-size ceilings return `indeterminate`
  with the code `RESOURCE_LIMIT` rather than `invalid` with `parse_error`. Those limits
  belong to this implementation, not to the protocol. Malformed input is unchanged and
  stays `invalid` with `parse_error`, and an unusable limit argument remains an argument
  error.
- `computeActionRefV2` rejects an empty `scope_required` unless the caller supplies
  applicable profile context that permits it, where it previously accepted empty
  unconditionally.
- An artifact under another envelope profile is `unsupported` and is not judged against the
  aps-receipt-v1 schema.
- A receipt string containing a Unicode noncharacter is refused. Section 4.1 also rejects
  Unicode noncharacters.
- Authority-delegation verification separates invalid, indeterminate and unsupported across
  trust, key-resolution and implementation-resource outcomes, applies the draft's
  chain-check ordering, and no longer treats SDK-only grammars or local resource ceilings as
  protocol validity rules. A reservation made again after cancellation is a fresh
  reservation and rechecks its limits.
- Trust and revocation callbacks receive a plain-data copy of each record rather than the
  caller's object. A resolver keyed on object identity no longer matches.

### Unchanged

Timestamp handling accepts second 60 only at 23:59 on the last calendar day of a month, and
no leap-second table is consulted. For inputs that remain conforming, identifiers,
signatures and canonical bytes are unchanged.

### New public API

The stage validator `validateReceiptStageV1` and its types, `RECEIPT_STAGE_TYPES_V1`, and
the DecisionRefV1 builders.

### What a valid result does not establish

A structurally valid stage result does not bind `delegation_ref` to a supplied chain,
recompute `action_ref` from a supplied action, resolve `prev`, recompute `effect_ref`, or
perform section 5.5 evidence resolution. None of those composition points is implemented,
and each is named in the stage module so a caller cannot read silence as a check.

### Public reachability

Not exported from the package root on the authority-delegation surface: both conforming
issuers, the ledger, `compareAuthority`, and the schema and scope helpers. A package
consumer can mint only through the raw canonical helpers, which perform none of the section
3.6 issuance checks and read a caller's value as given, getters and Proxy traps included.
The guarded verifier and issuer paths refuse non-plain in-memory values as `SCHEMA_INVALID`,
and the ledger rejects invalid reservation input with `CONFLICT`. Output from an unmodified
JSON parser is unaffected throughout.


## 6.0.1 (2026-09-04)

Documentation only. The README published with 6.0.0 listed three registries; the package page now lists npm, PyPI, crates.io, Go and the MCP server, and the skills advertise the MCP version npm publishes. No code change.

## 6.0.0 (2026-09-04)

Security release. The full cross-SDK account, including the affected version
ranges and the severity assessment, is in the security advisory for this
release. [The verification boundary](https://github.com/aeoess/agent-passport-system/blob/main/docs/verification-boundary.md)
names the verification APIs that establish authority from caller-supplied trust,
and the trust input each takes.

Several exported verification functions returned a successful verification
result (`valid: true` or an equivalent) without establishing all of the trust,
linkage, context and temporal conditions the result implied. In the affected
paths the verification key came from the artifact itself, the claimed identity
was not bound to the key that signed, chained artifacts were not linked to the
artifacts they claimed to derive from, or an unreadable timestamp compared as
neither expired nor stale. A relying party that treated those results as
authorization could accept an artifact an attacker produced with keys the
attacker controls.

This release changes what the affected functions establish. Trust anchors and
the expected challenge are caller-supplied where the result claims authority;
the presentation domain is signed, and a caller that uses domain as a
relying-party boundary compares it through the expected-domain option.
Identities are bound to keys. Chains are linked. Invalid time fails closed.
Creators refuse to mint artifacts their own verifiers reject. The credential,
presentation, policy-receipt and execution-envelope surfaces require the new
inputs in their public types; the passport surfaces keep an optional options
argument and return `valid: false` without it.

### Affected surfaces

One row per exported surface and defect class; a surface with two defect classes
appears twice. Copied from the security advisory for this release.

| exported name | module path | defect class | consumer change |
|---|---|---|---|
| `verifyExecutionEnvelope` | src/core/execution-envelope.ts | artifact key used as trust root | a new required input: trustedSignerPublicKeys, originalDecision, evaluatorPublicKey and expected |
| `verifyDecisionArtifact` | src/core/decision-semantics.ts | artifact key used as trust root | new required inputs: `keys` ({ intentSignerPublicKey, decisionSignerPublicKey, artifactSignerPublicKey }), `originalIntent` and `originalDecision` |
| `verifyPolicyReceipt` | src/core/policy.ts | chain not linked | a new required input: the PolicyReceiptChainInputs third argument |
| `verifyPolicyReceiptEnvelope` | src/core/policy.ts | chain not linked | a new opt-in: callers wanting envelope-only integrity now call this surface by name |
| `verifyVC` | src/core/vc.ts | identity not bound to key | reissue: credentials issued before the fixed version no longer verify |
| `verifyVerifiableCredential` | src/core/vc-wrapper.ts | identity not bound to key | reissue: credentials issued before the fixed version no longer verify |
| `verifyPresentation` | src/core/vc.ts | identity not bound to key | a new required input: opts.expectedChallenge |
| `verifyVerifiablePresentation` | src/core/vc-wrapper.ts | identity not bound to key | a new required input: opts.expectedChallenge |
| `verifyCredentialResponse` | src/core/credential-request.ts | identity not bound to key | a new required input: expectedChallenge is positional and required |
| `passportToVC` | src/core/vc.ts | identity not bound to key | reissue: the emitted signed preimage changed |
| `delegationToVC` | src/core/vc.ts | identity not bound to key | reissue: the emitted signed preimage changed |
| `floorAttestationToVC` | src/core/vc.ts | identity not bound to key | reissue: the emitted signed preimage changed |
| `receiptToVC` | src/core/vc.ts | identity not bound to key | reissue: the emitted signed preimage changed |
| `passportToVerifiableCredential` | src/core/vc-wrapper.ts | identity not bound to key | reissue: the emitted signed preimage changed |
| `createPresentation` | src/core/vc.ts | creator and verifier disagree | a new required input: options.challenge |
| `createVerifiablePresentation` | src/core/vc-wrapper.ts | creator and verifier disagree | a new required input: options.challenge |
| `verifyGovernanceCredential` | src/core/governance-block.ts | identity not bound to key | reissue: governance credentials signed before the fixed version no longer verify |
| `createVerifiedGovernanceCredential` | src/core/governance-block.ts | identity not bound to key | reissue: the emitted signed preimage changed |
| `verifyAttributionConsent` | src/v2/attribution-consent/verify.ts | identity not bound to key | reissue: receipts naming parties by non-self-certifying identifiers must be reissued under did:key |
| `checkArtifactCitations` | src/v2/attribution-consent/verify.ts | identity not bound to key | reissue: cited receipts must name their parties with self-certifying DIDs |
| `verifyPassport` | src/verification/verify.ts | authority false accept | a new opt-in: pass trustedIssuers for issuer-authority verification; allowSelfSigned: true is an explicit integrity-only opt-in and not a substitute for issuer trust in an authorization gate |
| `checkPassportGate` | src/core/commerce.ts | authority false accept | a new opt-in: the second opts argument carrying trustedIssuers or allowSelfSigned |
| `assignRole` | src/core/intent.ts | authority false accept | a new opt-in: trustedIssuers or allowSelfSigned on the opts object |
| `governIBACIntent` | src/adapters/ibac.ts | authority false accept | a success governance receipt is no longer signed for an expired delegation; per-tuple answers are unchanged |
| `evaluateIBACTuples` | src/adapters/ibac.ts | invalid time fails open | none |
| `createExecutionAttestation` | src/core/execution-attestation.ts | creator and verifier disagree | none for callers already passing RFC 3339 instants in order |
| `verifyExecutionAttestation` | src/core/execution-attestation.ts | invalid time fails open | none for RFC 3339 instants with an explicit offset or Z; attestations carrying zone-less, +0000 or space-separated spellings must be reissued; zone-less and space-separated spellings no longer verify |
| `normalizeTimestamp` | src/core/canonical.ts | invalid time fails open | none for timestamps carrying an offset; a zone-less value now throws |
| `verifyReceiptContext` | src/v2/offline-verifier/context.ts | invalid time fails open | RejectReason gains INVALID_TIMESTAMP; exhaustive switches over RejectReason must add a case |
| `resolveVerificationMethod` | src/core/did-uri.ts | invalid time fails open | none |
| `deriveSAO` | src/core/cross-chain.ts | invalid time fails open | none |
| `verifyDelegation` | src/core/delegation.ts | invalid time fails open | none |
| `isExpired` | src/core/passport.ts | invalid time fails open | none |
| `isPassportValid` | src/core/passport.ts | invalid time fails open | none |
| `verifyChallenge` | src/verification/verify.ts | invalid time fails open | none |
| `computeEvidenceAge` | src/core/freshness.ts | invalid time fails open | none |
| `validateTemporalRights` | src/core/time.ts | invalid time fails open | none |
| `verifyRuntimeAttestation` | src/core/attestation.ts | invalid time fails open | none |
| `addApprovalSignature` | src/core/charter.ts | invalid time fails open | none |
| `evaluateApprovalRequest` | src/core/charter.ts | invalid time fails open | none |
| `isRetentionExpired` | src/core/data-lifecycle.ts | invalid time fails open | none |
| `isSAOExpired` | src/core/cross-chain.ts | invalid time fails open | none |
| `isFrameExpired` | src/core/cross-chain.ts | invalid time fails open | none |
| `verifyCrossChainPermit` | src/core/cross-chain.ts | invalid time fails open | none |
| `verifyExecutionReceipt` | src/core/cross-chain.ts | invalid time fails open | none |
| `checkTermsCompliance` | src/core/data-source.ts | invalid time fails open | none |
| `activateEscalation` | src/core/escalation.ts | invalid time fails open | none |
| `checkEscalatedAction` | src/core/escalation.ts | invalid time fails open | none |
| `isEscalationActive` | src/core/escalation.ts | invalid time fails open | none |
| `verifyGovernanceArtifact` | src/core/governance.ts | invalid time fails open | none |
| `validateCredentialLifecycle` | src/core/governance.ts | invalid time fails open | none |
| `activateKeyRotation` | src/core/key-rotation.ts | invalid time fails open | none |
| `isKeyActive` | src/core/key-rotation.ts | invalid time fails open | none |
| `scheduleNextRecurrence` | src/core/obligations.ts | invalid time fails open | none |
| `verifyEndorsement` | src/core/principal.ts | invalid time fails open | none |
| `addToFleet` | src/core/principal.ts | invalid time fails open | none |
| `verifyEscrowHold` | src/core/transactional.ts | invalid time fails open | none |
| `verifyAttestation` | src/core/values.ts | invalid time fails open | none |
| `negotiateCommonGround` | src/core/values.ts | invalid time fails open | none |
| `lintTaskFeasibility` | src/core/feasibility.ts | invalid time fails open | none |
| `verifyPolicyDecision` | src/core/policy.ts | invalid time fails open | none |
| `isGovernanceBlockExpired` | src/core/governance-block.ts | invalid time fails open | none |
| `importOAuthToken` | src/core/identity-bridge.ts | creator and verifier disagree | none: only out-of-range exp values now throw |
| `createDelegation` | src/core/delegation.ts | creator and verifier disagree | none: only durations past year 9999 now throw |
| `createApprovalRequest` | src/core/charter.ts | creator and verifier disagree | none: only timeouts past year 9999 now throw |

### Migration

| package | old call shape | new call shape | unmigrated call | artifacts reissued |
|---|---|---|---|---|
| typescript | `verifyPassport(signed) with no options returned valid: true on a self-minted passport` | `verifyPassport(signed, { trustedIssuers: [...] }) or verifyPassport(signed, { allowSelfSigned: true })` | valid false: opts stays optional so the call still compiles; result reports issuerTrustChecked false and selfSignedAccepted false | no: passport bytes unchanged; a countersignature is needed only to pass the trustedIssuers path |
| typescript | `checkPassportGate(signedPassport)` | `checkPassportGate(signedPassport, { trustedIssuers: [...] }) or { allowSelfSigned: true }` | valid false: the passport_valid check reports passed false, so the commerce preflight is not permitted | no: no artifact changes; caller supplies the trust input |
| typescript | `assignRole({ signedPassport, role, autonomyLevel, scope, assignerPrivateKey, assignerPublicKey })` | `same opts object plus trustedIssuers: [...] or allowSelfSigned: true` | exception: throws 'Cannot assign role: passport verification failed' | no: no artifact changes; caller supplies the trust input |
| typescript | `verifyVC / verifyVerifiablePresentation over a proof signed on the document body only, proof configuration attached after signing` | `same calls; proofSigningInput places created, proofPurpose, verificationMethod, challenge and domain inside the signed bytes` | valid false: no dual-verification path: artifacts issued before the fixed version do not verify | yes: every VC and VP issued before the fixed version must be reissued |
| typescript | `verifyPolicyReceipt(receipt, verifierPublicKey) with chain omitted` | `verifyPolicyReceipt(receipt, verifierPublicKey, chain: PolicyReceiptChainInputs), or verifyPolicyReceiptEnvelope(receipt, verifierPublicKey) for envelope integrity only` | compile error: the third parameter is no longer optional; an untyped JS caller gets valid false with a chain-not-verified error | no: receipts unchanged; the caller must now present the intent, decision and action receipt plus an anchor for each |
| typescript | `createPresentation(creds, priv, pub) or createVerifiablePresentation(creds, priv) with options omitted or {}` | `createPresentation(creds, priv, pub, { challenge }) and createVerifiablePresentation(creds, priv, { challenge })` | compile error: the options parameter is required; an untyped caller gets an exception from assertPresentationProofOptions | yes: a presentation carrying no challenge does not verify in the fixed version and must be reissued |
| typescript | `verifyPresentation(vp), verifyVerifiablePresentation(vp), verifyCredentialResponse(vp) with no expected challenge` | `verifyPresentation(vp, { expectedChallenge }), verifyVerifiablePresentation(vp, { expectedChallenge }), verifyCredentialResponse(vp, expectedChallenge)` | compile error: the opts object and the second positional argument are now required | no: verifier side only; the verifier must issue and pass its own nonce |
| typescript | `verifyExecutionEnvelope(envelope) with no opts, or opts whose five members were all optional` | `verifyExecutionEnvelope(envelope, { trustedSignerPublicKeys, originalDecision, evaluatorPublicKey, expected }) with optional maxDecisionAgeMs` | compile error: opts and four of its members are required; an untyped caller reaching it with nothing gets valid false rather than a throw | no: envelope bytes unchanged; thirteen existing in-repo call sites passed no options and all now get false |
| typescript | `normalizeTimestamp('2026-04-05T03:39:31') returned an address that moved with the host timezone; date-only and hour 24 were also accepted` | `normalizeTimestamp(ts) with RFC 3339 carrying an explicit offset or Z (lowercase t and z accepted)` | exception: throws naming the rule; zone-less, date-only, impossible calendar dates, hour 24, whitespace-padded and non-string all rejected | no for conforming input: every offset-bearing input produces the identical address; an action_ref derived on a past run from a zone-less timestamp cannot be recomputed at all |
| typescript | `verifyAttributionConsent(receipt) accepted citer and cited_principal as opaque identifiers with any key beside them` | `same call, with each party named by a did:key or a multibase did:aps that commits to the key beside it` | valid false: reason carries 'unresolved' or 'rejected'; checkArtifactCitations, verifyCharter and verifyCompletionReceipt inherit the refusal | yes: receipts whose parties are opaque identifiers must be reissued under did:key; the signed preimage and receipt id did not move |
| typescript | `verifyVC / verifyVerifiablePresentation bound an issuer or holder named by did:web, SPIFFE, an OAuth-derived DID, or the hex form from createDIDHex` | `same calls, with issuer and holder named by did:key or the multibase did:aps from createDID` | valid false: keyAuthority reports 'unresolved' because the method does not self-certify and this SDK resolves no DID documents | yes: credentials whose issuer or holder uses a non-self-certifying method must be reissued under createDID |
| typescript | `verifyExecutionAttestation accepted zone-less, +0000 and space-separated ISO timestamp spellings` | `same call, with RFC 3339 carrying an explicit offset or Z` | valid false: the attestation no longer verifies on its timestamps | yes: attestations carrying those spellings must be reissued |
| typescript | `createExecutionAttestation(input, attestorPrivateKey) minted attestations with unreadable timestamps or with executionCompletedAt before executionStartedAt` | `same call with RFC 3339 instants and completion at or after start (equal instants allowed)` | exception: throws naming the rule at creation instead of minting a signed artifact the verifier would refuse | no: it refuses to mint; already-minted bad artifacts were rejected by the verifier before and after |
| typescript | `createDelegation, createApprovalRequest and importOAuthToken emitted an ISO expanded-year timestamp for durations or an exp landing past year 9999` | `same calls with a duration or exp that lands inside four-digit years` | exception: RangeError from formatRfc3339, and importOAuthToken raises its own documented error | no: an expanded-year timestamp was never readable by this SDK's own verifiers |
| typescript | `consumers matching the checks[] string 'PASS: N evidence attachment(s) present' (two other check strings also reworded)` | `match 'PRESENT: N evidence attachment(s), not verified here'; this verifier does not check evidence` | warning only: the valid verdict is unchanged; only string matching on checks[] stops matching | no: no artifact changes |
| typescript | `verifyDecisionArtifact(artifact, { intentSignerPublicKey, decisionSignerPublicKey, artifactSignerPublicKey })` | `verifyDecisionArtifact(artifact, { intentSignerPublicKey, decisionSignerPublicKey, artifactSignerPublicKey }, originalIntent, originalDecision)` | compile error: two new required parameters; each inner signature is verified under the caller's anchor and the decision must reference the intent | no |
| typescript | `verifyGovernanceCredential(credential, block, publicKey)` over a credential whose proof signed the body only | the same call over a credential produced by the fixed `createVerifiedGovernanceCredential`, whose proof configuration is signed and whose proof key must bind to the issuer | valid false | yes: governance credentials issued before the fixed version are reissued |
| typescript | `floorAttestationToVC`, `receiptToVC`, `delegationToVC`, `passportToVC` | the same calls; the credentials they emit carry the new signed preimage | n/a: creators | yes: credentials they produced before the fixed version are reissued |

## 5.0.3 (released)

### Release process

- Release metadata and pipeline controls only. The package source and generated
  SDK behavior are unchanged from `5.0.0`. This patch is reserved for
  publication through the corrected Trusted Publishing workflow so npm can
  create registry provenance for the new immutable version. It carries the
  same security remediation as `5.0.0`, whose registry entry cannot be amended
  with missing npm provenance.

## 5.0.2 (not published)

- Failed release attempt, never published. The tag `v5.0.2` was pushed on
  2026-09-02 at `37db6b47` and the release workflow run `33692642859` passed
  authorize, test, build, package, probe and attest, then failed in the
  release job at `gh release create`: the command ran at the workspace root
  while the sources were checked out under `release-source/`, so `gh`
  attempted repository inference outside a git checkout and failed. Publish
  was skipped. No GitHub Release and no npm version `5.0.2` exist. The tag
  stays where it is as the record of that attempt; the workflow fix is #141
  and the recovery version is `5.0.3`.

## 5.0.1 (not published)

- Failed release attempt, never published. The tag `v5.0.1` was pushed on
  2026-09-02 at `0bc21579` and the release workflow run `33690069810` passed
  authorize, test and build, then failed in the package job while parsing the
  structured `npm pack --json` result: it was passed through an environment
  variable and exceeded Linux's single-argument limit ("Argument list too
  long", exit 126). The failure occurred before the immutable package handoff,
  probe, attestation, npm publication, or GitHub Release; those downstream
  jobs were skipped. No GitHub Release and no npm version `5.0.1` exist.
  The tag stays where it is as the record of that attempt; the workflow fix is
  #139 and the recovery version is `5.0.2`.

## 5.0.0 (2026-08-29)

### Follow-up audit included in this release

- **`verifySocialContract` normalizes `trustedIssuers` like the other two
  readers of the option.** It read `opts?.trustedIssuers ?? []` and then tested
  `.length > 0`. `??` replaces only `null` and `undefined`, so every other
  malformed shape reached `.length > 0`, evaluated `undefined > 0` to false,
  and the caller's trust configuration was discarded without a word — while a
  bare 64-character key string, which has a numeric `.length`, was read as a
  configured anchor list. One input, three public entry points, three answers:
  with `trustedIssuers: {}`, `verifyPassport` returned `valid: false`,
  `checkPassportTrustPosture` returned `ok: false`, and `verifySocialContract`
  returned `overall: true` with `issuerErrors: []`. The CLI was safe by
  construction, because it builds an array from repeated `--trusted-issuer`
  flags; a library consumer reading `overall` was not.

  A malformed value is now neither "no anchors" nor "all anchors":
  `issuerChecked` is true because a trust root was demanded, `issuerTrusted` is
  false, `issuerErrors` names the option and says why, and the deprecated
  `overall` accessor is false. `[]` and an omitted option are unchanged, and a
  well-formed anchor list is unchanged.

  Found by the retro-audit of Phase 2 (C1). The transferable part is not the
  two-line fix: the original repair enumerated the known CALL SITES of the
  guard and treated that as an enumeration of READERS of the option. A grep for
  readers rather than for callers finds `contract.ts` immediately.
  `tests/trust-anchor-shapes.test.ts` now asserts the property the enumeration
  should have had — for any value of the option, no public entry point admits
  where another refuses.

### Test surface

- **Ed25519 admissibility: the R half is pinned beyond `R = identity`.** Of the
  50 fixture vectors carrying a valid public key and an inadmissible R, only 8
  were LIVE — refused by the guard AND accepted by a permissive verifier — and
  all 8 were `R = identity`. Four vectors are added: an admissible
  torsion-aliased public key with R of order 2, 4 and 8, plus a positive
  control with a full-order R under the same key so the refusals are
  attributable to the R half. All four SDKs consume the same fixture and agree
  on all 495 vectors. The new tests assert LIVENESS rather than counting
  vectors.
- **No test resolves a path through the user's home directory.**
  `tests/reversibility-profile-parity.test.ts` read `~/agent-passport-python`
  and `~/agent-passport-go` unconditionally, so four assertions ran against
  whatever was checked out there and converted to skips under a hermetic
  runner, with the same exit code either way. Both now require `APS_PY_REPO`
  and `APS_GO_REPO` and skip when unset, and `tests/hermeticity.test.ts` keeps
  it that way.


Five verification surfaces returned a permissive verdict when a check had not
run. Each one now separates "checked and passed" from "not checked", and each
fails closed where it used to fail open. The major bump is because these
change verdicts and interface shapes, not because the wire format moved: no
signed artifact that verified before verifies differently now.

Per AGENTS.md this bump is PROPOSED, not decided. A human owns the version.

### Behavior change

- **`verifyApsTxt` no longer reports an unverified document as valid.** With no
  public key it returned `{ valid: true, errors: [] }`, because the `strict`
  option that gated the unsigned verdict defaulted to false. A caller that had
  not yet resolved the publisher key read any aps.txt, including one
  substituted in transit, as valid governance for the whole domain. With no key
  the result is now `valid: false`, `signatureChecked: false`, `reason:
  'UNSIGNED'`. A public key that is not 64 hex characters lands in the same
  unchecked state rather than throwing out of `createDID`, which a verifier
  must not do. Reading an aps.txt without authenticating it keeps its own named
  operation, `parseApsTxt`, which asserts nothing about signatures.
- **`fail_closed` no longer admits unreadable revocation evidence, and a
  typo'd policy value is no longer silent.** An unparseable `checkedAt` was
  mapped to an Infinity age and then compared against the window, which looked
  equivalent to rejecting it and was not: with `cacheGraceMs: Infinity`,
  `Infinity <= Infinity` passed, so `checkedAt: 'not-a-date'` graded FRESH and
  satisfied `fail_closed`. It is now graded stale before any window
  arithmetic. Separately, an unrecognised `revocationCheckPolicy` fell through
  every comparison to the most permissive branch, so `'FAIL_CLOSED'` returned
  `valid: true` with no error: an integrator who typed the strictest setting
  in the wrong case silently got the weakest one. Unknown policy values now
  throw, and `REVOCATION_CHECK_POLICIES` is exported so a caller reading a
  policy out of configuration can check it first.
- **`verifyDelegation`'s `fail_closed` revocation policy now does something.**
  The policy was read into a local and compared against exactly one value,
  `cache_grace`, so `fail_closed` and `fail_open` ran identical code. Driven
  against the SDK, `fail_closed` accepted a cached revocation state two hours
  old and accepted having no revocation evidence at all. The three policies are
  now observably different on the same input: `fail_open` is unchanged and
  remains the default, `cache_grace` is unchanged, and `fail_closed` admits
  only against evidence that is present and inside the freshness bound. A
  `fail_closed` refusal reports `revoked: false` and names the evidence
  problem rather than asserting a revocation nobody observed. Evidence dated in
  the FUTURE is not fresh either: a negative age used to pass the upper bound,
  so `checkedAt: '2999-01-01'` graded as fresh.
- **The revocation posture is selectable from shipped entrypoints.** The
  repaired policy was reachable only from a direct `verifyDelegation` call:
  nine internal call sites, none passing options. `subDelegate`,
  `createReceipt`, `verifyOnAccept`, `consultAdvisor` and the LangChain,
  CrewAI, Gonka and MCP adapters now all accept a `revocation`
  (`RevocationCheckOptions`) argument and thread it through. All default to
  `fail_open`, so no existing caller changes behaviour. `verifyAttribution`'s
  chain walk takes one too, through a PER-DELEGATION resolver rather than a
  single cached state, since one delegation's evidence applied to every hop
  would be a new defect. It defaults to fail_open, so the historical behaviour
  is unchanged.
- **`verifyAgoraMessage` folds the registry check into its verdict.** It ran
  the check, pushed `'Author not found in agent registry'` into `errors`, and
  then returned `valid: signatureValid`, so a message from an unlisted author
  came back as `{"valid":true, errors:["Author not found in agent registry"]}`
  and `verifyFeed` counted it toward `valid` with `invalid: []`. `signatureValid`,
  `registryChecked` and `knownAgent` are now reported separately and the
  verdict conjoins every check that ran. A `null` registry is no registry
  rather than an empty one, and a registry whose `agents` is not an array is a
  check that FAILED rather than one that was skipped, so a refusal always
  states a reason.
- **A malformed `trustedIssuers` value fails closed instead of disabling the
  check.** Two guards read the option with opposite tests, one positive
  (`.length > 0`) and one equality (`.length === 0`), so any value whose
  `.length` is neither exactly 0 nor greater than 0 failed both and composed
  into an admit. `{}`, `NaN`, `0`, `true`, `new Map()` and
  `new Set(['key'])` all land there; the Set is the one an operator actually
  reaches for, and reaching for it silently admitted everyone through all six
  gates. The option is now normalized once, at the boundary, by
  `normalizeTrustAnchors`: anything that is not an array of non-empty strings
  is graded malformed and denied with a reason, and no reader tests `.length`
  on a caller-supplied value again. This sentence originally said "neither
  guard", enumerating the two guards it was written for; there was a third
  READER, `verifySocialContract`, and it was missed. See the entry above in this release. A bare key string is refused
  too, since it has a numeric length and the membership test downstream was
  substring matching. Pre-existing, and older than the gate consolidation;
  what the consolidation changed is that the repair is one function rather
  than six guards.
- **Every SDK execution gate requires a stated trust posture, not just the
  offline verifier.** The relying-party middleware was hardened and the five
  ADAPTER gates that also call `verifyPassport` were not, so the same hole
  stayed open in the gates that actually run the tool. Driven against the SDK:
  `governMCPToolCall` EXECUTED the tool and minted a success receipt for an
  attacker's self-signed passport declaring `admin:everything` carrying a
  delegation they had issued to themselves, and `verifyA2AIdentity` returned
  `{valid: true, errors: []}` for it. `MCPGovernanceConfig`,
  `LangChainGovernanceConfig`, `CrewGovernanceConfig` and `GonkaHostConfig`
  now take `trustedIssuers` and `allowSelfSigned`, `verifyA2AIdentity` takes
  an options argument, and all five deny by default. The rule lives once, in
  `checkPassportTrustPosture` (`src/verification/trust-posture.ts`), which the
  middleware now uses too: five copies of one rule is how four of them ended
  up without it.
- **The relying-party gate requires a stated trust posture.** `evaluateRequest`
  admitted an attacker's self-signed passport declaring `admin:everything` with
  `{"admit": true}`. `verifyPassport` emits a self-signed warning, but
  `GateDecision` had no warnings field, so the gate discarded the one signal
  that said on what basis it was admitting, and `trustedIssuers: []` took the
  same silent path as omitting the option. A non-empty `trustedIssuers` now
  requires a valid countersignature from one of them; `allowSelfSigned: true`
  accepts self-signed credentials and every admit made that way carries the
  warning; neither, or an empty list, denies with the new `UNTRUSTED_ISSUER`
  reason and a 401.
- **`GovernanceLoadPolicy.allowedIssuers` distinguishes "none" from "anyone".**
  The check was guarded with `length > 0`, so an empty list skipped it and
  admitted every issuer, and `DEFAULT_LOAD_POLICY` shipped that empty list. An
  empty list now admits nobody. Wildcard trust is the explicit `ANY_ISSUER`
  (`'*'`) entry, honoured ONLY as the SOLE entry: `['*', key]` is what comes
  out of spreading the default and appending a key, which is an operator
  HARDENING a policy, so it reads as a closed allowlist of the named issuers
  and the dropped wildcard is reported in the new `warnings` array.
  `DEFAULT_LOAD_POLICY` carries `['*']`, so its behaviour is unchanged.
- **`verifySocialContract` separates structure from standing.** It called
  `verifyPassport` with no trust anchors, discarded its self-signed warning,
  and returned the result as `overall`, which the CLI printed as
  "✅ TRUSTED". `structurallyValid` is now the passport's own signature,
  validity window and values attestation, computed WITHOUT the caller's
  anchors so it is a property of the bytes and does not move when the caller
  changes trust configuration. `issuerTrusted` is the separate statement about
  standing, `issuerChecked` says whether it was even asked, and `issuerErrors`
  keeps trust failures out of `identity.errors`.
- **`passport verify` reports four states, not two.** DOES NOT VERIFY,
  TRUSTED, NOT TRUSTED (verifies, but no supplied issuer countersigned it) and
  SELF-SIGNED (verifies, no trust root supplied). It takes a repeatable
  `--trusted-issuer` flag; `getFlag` returned only the first value for a
  repeated flag, which silently dropped the rest of a trust-anchor list.

### Deprecated

- **`TrustVerification.overall`.** Reading it emits a runtime
  `DeprecationWarning`. Its value is unchanged, `structurallyValid && (!issuerChecked
  || issuerTrusted)`, which is exactly what the field always returned. The name
  reads as a trust decision, but with no `trustedIssuers` supplied it has only
  ever meant "the bytes check out". Read `structurallyValid` and
  `issuerTrusted` and decide explicitly which one the call site needs.

### Known limitation

- **`verifyPassport` still returns `valid: true` for a self-signed passport
  declaring `admin:everything`.** This default is relied on across the SDK:
  closing it fails 71 tests spanning accountability, payment rails,
  mutual-auth and the adapters, which makes it a protocol decision rather than
  a local repair. It is escalated, not taken. What changed is that the state is
  now machine-readable: `VerificationResult.issuerTrustChecked` and
  `.selfSignedAccepted` let a caller branch on it instead of string-matching a
  warning. The gate and `verifySocialContract` both refuse to admit on that
  basis without an explicit posture from their own caller.

### Removed

- **`VerifyApsTxtOptions` and the third parameter of `verifyApsTxt`.** The
  `strict` option gated the unsigned verdict; once that verdict became
  unconditional the only thing it still changed was how many entries landed in
  `errors`. A security-shaped option that cannot change a security outcome is
  the defect class this release exists to remove, so it is gone rather than
  kept as a no-op. The behaviour it selected is now the only behaviour, which
  is strictly stronger than what the AV-2 report asked for.

### Breaking type changes

Result interfaces gained required members. Code that READS these results is
unaffected; code that CONSTRUCTS one (test doubles, mocks, re-implementations)
must add them.

| Interface | Change |
|---|---|
| `AgoraVerification` | required `signatureValid`, `registryChecked` |
| `VerifyApsTxtResult` | required `signatureChecked` |
| `GovernanceVerification` | required `warnings` |
| `TrustVerification` | required `issuerChecked`, `issuerTrusted`, `issuerErrors`, `structurallyValid`; `identity` gained required `warnings`; `overall` is now an accessor |
| `GateDenyReason` | union widened with `UNTRUSTED_ISSUER`, so an exhaustive `switch` no longer compiles without a branch |
| `GovernanceLoadPolicy.allowedIssuers` | semantics changed, shape unchanged |
| `DelegationStatus` | optional `revocationEvidence` added |
| `VerificationResult` | optional `issuerTrustChecked`, `selfSignedAccepted` added |
| `VerifyApsTxtOptions` | removed |
| `MCPGovernanceConfig`, `LangChainGovernanceConfig`, `CrewGovernanceConfig`, `GonkaHostConfig` | gained optional `trustedIssuers` and `allowSelfSigned`; all four gates now DENY by default |
| `verifyA2AIdentity` | gained a third options parameter; denies self-signed by default |
| `normalizeTrustAnchors` | new, exported; a malformed `trustedIssuers` now makes `verifyPassport` return `valid: false` instead of silently meaning "no anchors" |
| `traceBeneficiary` | gained a fourth options parameter (`AttributionRevocationOptions`) |

### Tests

- `tests/revocation-policy-reachability.test.ts` drives each shipped entrypoint
  twice with identical input, changing only the revocation posture, and asserts
  the outcome differs. Reverting the threading fails six of its eight cases.
- `tests/v2/authority-delegation-resolver-guards.test.ts` closes two mutation
  survivors on the authority-delegation verifier: dropping the resolver value
  normalization made `undefined`, `null`, a Promise and any unrecognised string
  return `valid: true` with the previous suite fully green. No source in that
  module changed; the tests pass against the shipped implementation.
- `tests/cli-verify.test.ts` drives the real `passport verify` binary and
  asserts on operator-visible output, which is where this defect lived.

## 4.5.1 (2026-08-28)

- Lockfile-only patch; resolves tar advisory GHSA-r292-9mhp-454m in the dev chain; prepared for publication through the Trusted Publishing workflow with build provenance and SBOM. No API change.

## 4.4.0 (2026-08-20)

### Behavior change
- **Signing and new-write boundaries refuse integer-valued numbers outside the interoperable IEEE 754 range (#111).** RFC 7493 section 2.2 says an I-JSON sender cannot expect a receiver to treat an integer whose absolute value exceeds 9007199254740991 as an exact value, and recommends encoding such a value as a JSON string. The SDK signed it as a number anyway, so an artifact could commit to a value a conforming receiver is free to round. A new-write value carrying such an integer now raises `UnsafeIntegerError`, which carries category `invalid_number`, reason `integer_exceeds_interoperable_range`, and the JSON path of the offending member, for example `$.spendLimit: integer exceeds the interoperable IEEE 754 range`. Only integer-valued numbers are bounded, since a fractional double carries no claim to exactness beyond itself. Verification and recompute paths keep calling the unrestricted canonicalizer, so this change alters no verification outcome: an artifact that verified before it still verifies after it, checked against the built package rather than against source. The guard is internal: the public API surface is unchanged, `UnsafeIntegerError` is not exported from the package entry, and a caller who needs to branch on it matches `category` and `reason`. One limit worth knowing at the call site: a documented set of exported helpers both mint and re-derive a value through the same function and stay unrestricted, so that re-derivation of a value minted before the rule keeps working. Minting an unsafe integer through one of those helpers is not covered. Scope, the call-site inventory and the proofs are in #111.
- **`canonicalizeJCS()` rejects `undefined`; existing builders emit explicit `null` (bytes unchanged); `BilateralReceipt` profile documented; fixture READMEs scoped (#101).** `undefined` is not a JSON value and RFC 8785 defines no canonical form for it, but the helper coerced an `undefined` object member into the JSON value `null`, so code could sign a value the caller never wrote while claiming strict RFC 8785 output. It now throws a `TypeError` naming the path, for example `canonicalizeJCS: undefined at $.trusted_issuers[0].stale_behavior`. Eleven builders relied on the coercion because they assigned optional members unconditionally, so an omitted input became a key holding `undefined`; each now writes the `null` explicitly and the emitted bytes are unchanged. Verified by tracing every top-level canonicalization in the suite before and after: all 514 null-carrying outputs are identical, and the pinned mutual-auth conformance vectors and accountability fixture pass untouched. `canonicalizeJCSStrict` remains exported as a deprecated alias. Key presence is preserved exactly: only a member that was present and `undefined` becomes `null`, never one that was absent, since adding a member would move the bytes.

### Fixed
- **Signatures over receipts with an omitted optional member now verify after a JSON round trip.** The coercion put `"member":null` in the signing preimage, but `JSON.stringify` drops an `undefined`-valued member, so the object that travelled did not carry it and a receiver re-canonicalized different bytes. Such artifacts verified in the emitting process and failed for every remote peer. Mutual-auth certificates and trust bundles, ACP and MPP receipts and denials, and trust root policies were all affected. Writing the `null` explicitly makes it survive serialization, so the two sides agree.

### Docs
- Conformance suite links in the README and the package metadata point at the canonical `Agent-Authority-Conformance` owner (#112).

## 4.3.1 (2026-08-15)

### Behavior change
- **The `delegate` numeric flags accept canonical decimal only.** `--limit`, `--depth` and `--hours` were parsed with `Number()`, which accepts every literal form JavaScript accepts. `--limit 0x64` therefore signed a spend cap of one hundred while reading as sixty-four to a human and to every base-10 parser, and the same coercion accepted `1e3`, `+5`, `5.`, `.5` and a value padded with spaces. These flags carry authority, so the accepted grammar is now an optional minus, digits, and an optional fractional part. Hexadecimal, octal and binary literals, exponent form, a leading plus, a bare leading or trailing dot, and surrounding whitespace now exit non-zero and write no delegation. Input that previously produced an artifact now fails, and only non-decimal spellings are affected: `500`, `0`, `0.5` and `007` are unchanged. The documented forms in the usage string were already canonical.
- **A numeric flag supplied without a value is an error rather than a silent default.** `--depth ""`, `--hours ""` and either flag given as the last argument with nothing after it previously fell through to the default and signed it. `getFlag` returns `undefined` both for an absent flag and for one supplied without a value, so the two cases were indistinguishable. Presence is now tested directly and a valueless flag exits non-zero. Omitting a flag entirely still applies its documented default.

### Fixed
- **`delegate --depth` no longer signs a delegation with no depth ceiling.** `Number('abc')` is `NaN`, `NaN` passed `maxDepth: opts.maxDepth ?? 1` unchanged because `NaN` is not nullish, and `JSON.stringify` emits `null` for `NaN`. The signed artifact carried `maxDepth: null`. Chain verifiers guard the depth rule on the ceiling being present, so a null removed the delegation depth bound instead of tightening it: a typo widened authority. `maxDepth` has no validation in `createDelegation` the way `spendLimit` does, so the command line was the only gate. `--depth` now requires a non-negative integer and rejects `abc`, `1.5` and `-1`.
- **`delegate --limit 0` no longer signs a delegation with no spend cap.** The flag was coerced with `Number()` and then passed through a trailing truthiness fallback, and both `0` and `NaN` are falsy, so an explicit zero, a non-numeric value, an empty value and a bare `--limit` all resolved to `undefined`, which means unbounded. An operator asking for a budget of nothing received unbounded authority at exit code 0, and the `Limit:` line in the success output was itself guarded by a truthiness check, so the omission was not printed. `--limit 0` now signs `spendLimit: 0`.

## 4.3.0 (2026-07-26)

### Behavior change
- **`scope_required` now rejects duplicate elements after NFC normalization.** Section 4.1 defines `scope_required` as a duplicate-free array. The canonicalizer normalized and sorted but neither deduplicated nor rejected, so `["a","a"]` and `["a"]` produced different action references while the specification admits one form. The canonicalizer now raises `DuplicateScopeRequiredError`, carrying category `invalid_scope_required` and reason `duplicate_scope_required`, before any identity is computed, so the failure can never present as an identity mismatch. Detection runs after NFC, so two spellings that collide only under normalization also reject. Silent deduplication was rejected as the fix because an equality key must not map distinct inputs onto one value without saying so. Input that previously produced an `action_ref` now raises, and only duplicated input is affected.

### Fixed
- **`decision_ref` construction now normalizes before hashing.** The decision reference was computed over unnormalized input on one path, so two byte-different encodings of the same decision could produce different references.
- **`valid_until` is now bound in `CoreDecisionOutputV1`.** The field was carried but not covered by the signed material, so a validity window could be altered without invalidating the signature.

### Docs
- JCS key-order wording corrected to UTF-16 code units, matching RFC 8785. The action-reference comments are unchanged because scope elements sort by a different rule.
- PRESS wording moved from proof to evidence.

## 4.2.0 (2026-07-20)

### Added
- **aps-mcp-1: pre-dispatch authorization profile for MCP `tools/call`.** A signed, replay-claimed, delegation-referenced authorization object carried in `_meta` under `org.agent-passport/authorization`, plus `createApsMcpToolCallMiddleware`, a pre-dispatch guard that cannot be bypassed by the handler it wraps: transport authentication first, then signature, target, arguments-hash, and action_ref verification, a single-use replay claim, an authority decision, and only then dispatch, with a receipt attached to the result under `org.agent-passport/receipt`. Issue and verify helpers: `issueApsMcpAuthorizationV1`, `verifyApsMcpAuthorizationV1`, `computeMcpArgumentsHashV1`, `canonicalMcpServerUri`.
- **A2A identity extension profile (`identity-v1`).** Native Agent Card extension under `https://agent-passport.org/a2a/extensions/identity/v1` with JWS Agent Card signatures: `attachApsIdentityExtensionV1`, `signA2AAgentCardV1`, `verifyApsA2AAgentCardV1`.
- **v2 core modules behind draft-pidlisnyi-aps-03 landed in the repository:** receipt-core v1, authority delegation with a budget ledger, identity binding v2, action reference v2, and OAuth ID-JAG import v1. Exported from the package entry this release: the two binding profiles and the `HistoricalKeyResolver` types. The remaining v2 module entry points ship in a follow-up once their export surface is deduplicated; until then they are in-repo, tested, and not part of the public API.
- **Liu-family OAuth composition harness** under `interop/` (not part of the npm package): three SDK-emitted vectors (permit, denial, revocation observation), each checked by an independent no-SDK verifier that recomputes JCS and Ed25519.
- Seven new test files registered in the suite (protocol bindings, receipt-core, identity binding, action reference, ID-JAG import, authority delegation and budget).

## 4.1.1 (2026-07-14)

No functional change from 4.1.0. The code, the API, and the test suite are identical.

4.1.0 was published by hand, so the release workflow never reached its publish step and that version carries no build-provenance attestation, no SBOM, and no tarball on its GitHub Release. Every release before it does. This version goes through the release pipeline instead, so the package on npm and its GitHub Release carry the same signed SLSA provenance as 4.0.0 and earlier. Provenance cannot be attached to an already-published version, which is why this ships as a new patch rather than a correction to 4.1.0.

Consumers on 4.1.0 need not upgrade for behavior. Upgrade if you verify provenance before install.

## 4.1.0 (2026-07-13)

### Fixed / Security
- **JCS canonicalization now rejects lone surrogates (RFC 8785).** `canonicalizeJCS` and the signing paths that call it previously accepted strings carrying an unpaired UTF-16 surrogate (U+D800 to U+DFFF) and let it reach the canonical output, so input that is not valid Unicode could be signed and could canonicalize differently across implementations. Such input is now rejected before hashing with a stable error, matching the Python and Go SDKs and the RFC 8785 requirement that input be valid Unicode.

### Behavior change
- Input that was previously accepted is now rejected. A value carrying a lone surrogate on a canonicalization or signing path throws instead of producing a signature. Callers that never emit unpaired surrogates see no change. This is why the minor version moves rather than the patch.

### Internal
- Reversibility-fold v0 groundwork landed (per-effect classifier and profile registry). It is not exported from the package entry and adds no public API. No consumer action.

## 3.3.1 (2026-07-10)

### Fixed / Security (audit 2026-07-10)
- **verify-bundle revocation axis fail-open.** `revocationAxis` read `workflow_response.result`/`.status`, fields that do not exist on `RefreshOutcome`, so the unavailable/skipped branch was dead and an allow decision was reported VERIFIED. Because the frozen F4 record does not carry the freshness result, a consulted-and-fresh source and an unavailable source that failed open are indistinguishable; the VERIFIED ceiling is now EVALUATED, matching the authority and evidence axes.
- **audience-binding threw on untrusted null.** `checkAudience`/`normalizeRecipients`/`matchAudience` threw a TypeError on `aud: null` (or a null proof) from untrusted JSON; they now fail closed (null binding treated as unbound). The gateway route already coalesced null; the SDK primitive is now self-safe.
- **CLI `audit` hardcoded `revoked: false`** for every delegation, so the F-004 revocability check always reported enforced. It now reflects the delegation's advisory `revoked` flag; `verify-bundle` remains the authoritative-honest path.

## 3.3.0 (2026-07-10)
### Added
- Bilateral receipts carry an optional action_ref inside the signed body; pair
  reconciliation (src/v2/bilateral-pair) compares the two parties' copies across five
  mismatch classes (payload_changed, recipient_changed, wrong_audience,
  unilateral_success, action_ref_mismatch), with audience checks in both directions.
- Verifier-side RevocationObservation (src/v2/revocation-enforcement): signed record
  of an observed revocation signal and the decision taken under a stated freshness
  contract, with derived outcome labels and SET ingestion.
- EvidenceBundle (aps:evidence-bundle:v1): signed Merkle-committed evidence sets with
  per-member inclusion proofs, plus CLI verify-bundle printing a per-axis claim-state
  report (authority, action, revocation, evidence) with machine-gating exit codes.
- Jurisdiction selection provenance (selectJurisdictionPacks): records which policy
  packs matched a set of jurisdiction facts, surfaces constraint conflicts instead of
  resolving them, and makes explicit precedence auditable.
- examples/verifiable-workflow: end-to-end demo emitting five evidence bundles gated
  by verify-bundle exit codes.
### Fixed
- computeActionRef now NFC-normalizes scopeRequired scope strings and sorts scope
  arrays by Unicode code point per draft-pidlisnyi-aps-03 section 4.1; single-scope
  ASCII refs are unchanged and the external cross-ecosystem key is unaffected.
- CLI inspect no longer misidentifies bilateral receipts as action receipts.
Go SDK (separate repo): ComputeActionRefScopes (spec 4.1 array shape) with NFC per
scope and code-point sorting on a copied slice; NFC on the legacy single-scope form.
- fix(evidence-bundle): revoked_at with allow and no terminating workflow marks the revocation axis INVALID; terminated running workflow maps RESOLVED (classify domain alignment, T9 OPEN)
- chore: examples renamed to delegated-action-evidence

## 3.2.0

### Fixed / Security
- **Unbounded CBOR map length hung `decodeQntmInvite`** (`src/interop/qntm-bridge.ts`). The map decoder read a declared entry count straight from attacker-controlled input and used it as a loop bound with no check against the actual remaining buffer; an out-of-bounds byte read silently coerced to a valid-looking `major=0/info=0` header instead of erroring, so the runaway loop never hit a natural stop. A 54-byte crafted token declaring 765 million entries hung the decoder indefinitely. Found by fuzzing (see Added, below); fixed by rejecting a declared entry count that cannot fit in the remaining bytes before looping, and by making an out-of-bounds read a hard decode error instead of a silent zero.
- **`verifyPassport` threw on a non-array `delegations` field instead of returning `{valid: false, ...}`** (`src/verification/verify.ts`). `passport.delegations || []` let a present-but-non-array truthy value straight into a `for...of`, violating the function's documented never-throws contract. Fixed with an explicit `Array.isArray` guard.

### Added
- **Coverage-guided fuzzing infrastructure** (`fuzz/`): 7 Jazzer.js harnesses targeting the functions with a history of real vulnerabilities or load-bearing byte-exactness (`decodeQntmInvite`, `cedarPolicyToTuples`, `canonicalize`, `canonicalizeJCS`, `parseGovernanceBlockFromHTML`, `didWebToUrl`, `verifyPassport`), wired into CI via ClusterFuzzLite. `fast-check` property tests (`tests/property-canonical.test.ts`) cover canonicalization determinism and RFC 8785 null-preservation independently of the hand-written suite.
- **Tag-triggered release workflow** (`.github/workflows/release.yml`): runs the full gate (type-check, tests, audit) before publishing to npm via Trusted Publishing (OIDC, no long-lived token), then attaches a signed SLSA build-provenance attestation to the GitHub Release.

### Removed
- **Three unused runtime dependencies**: `@anthropic-ai/sdk`, `@google/generative-ai`, `openai`. None were imported anywhere in the codebase; every consumer installing this SDK was pulling all three for nothing. `@types/uuid` is also removed since `uuid` v14 ships its own type declarations. Runtime dependencies are now exactly `libsodium-wrappers` and `uuid`.

## 3.0.0

### Breaking
- **`traceBeneficiary().verified` now means cryptographic authenticity, not lineage resolution** (`src/core/attribution.ts`). It is `true` only when the receipt signature verifies (`verifyReceipt` against the executor at the chain tail) AND every delegation in the traced lineage verifies (`verifyDelegation`: signature plus temporal validity), reusing the canonical verifiers. Previously `verified` meant only that the chain resolved against the supplied records and a beneficiary was known, so a forged, tampered, or otherwise unauthenticated creator-supplied chain could report `verified: true`. Callers that relied on the old meaning must read the new `resolved` field instead. `verified` attests lineage signature authenticity only; it does not check action authorization or inter-hop scope narrowing (use `verifyDelegationChain` / `scopeAuthorizes`) and does not consult revocation on this path.

### Added
- **`BeneficiaryTrace.resolved`** (`src/types/passport.ts`): a lookup-success field carrying the prior `verified` semantics. It is true when the traced lineage maps to known delegation records and the principal resolves to a known beneficiary. It makes NO cryptographic claim, and is distinct from the now-cryptographic `verified`.
- **Deterministic beneficiary lineage reporting** (`src/core/attribution.ts`): the reported chain is order-independent and its tail is tied to `receipt.delegationId` (the delegation the executor acted under), so re-used delegation key pairs no longer make the reported lineage non-deterministic.
- **APS Composition Check Receipt v0** (`src/v2/composition-check/`): a public carrier and a stateless ANCHOR verifier for an external attestor's composition-hazard check. A chain of individually rule-legal delegations can compose to a globally-unsafe target that per-hop monotonic narrowing cannot detect; detection is private gateway intelligence, so the SDK adds ONLY the carrier. The `CompositionCheckReceipt` records opaque `policy_profile_ids` and `checks_run` plus a `result_per_check[]` from a fixed enum (`pass | fail | indeterminate | not_checked`) over a bound `(chain_hash, action_ref, context_hash)`, signed by an attestor with a declared `attestor_independence_class`. `verifyCompositionCheck` verifies the signature, the binding, freshness, well-formedness, and attestor trust, and surfaces `independence_is_second_anchor` corroborated from the caller's trust context (`registered_by_operator === false`), never the receipt's self-declaration. It evaluates NO policy, computes NO aggregate, and emits NO `safe` boolean: `pass` means only that the named attestor reported pass for the named profile over the bound context, never global safety. `gateway_self` is always weak (one trust domain); only a context-corroborated `independent_registered` is a second anchor, mirroring RAP-v0 gating its strong claim on `domains >= 2`. Exposed as `CompositionCheckV0` via the barrel. Conformance vectors in `conformance/composition-check/v0/`. Additive: a new type and verifier, no change to existing types.

## 2.9.0

### Added
- **`recordSpend(commerceDelegation, amount)`** (`src/core/commerce.ts`): the stateless write primitive for commerce spend. It returns a new `CommerceDelegation` with `spentAmount` incremented, refusing a non-finite or negative amount and refusing a spend that would exceed `spendLimit`. It pairs with `checkSpendGate`: check before a purchase, record after, persist the returned object. The SDK does not persist spend between calls; cumulative enforcement across purchases is the caller's or the gateway's responsibility. This closes a read-but-never-written gap where `spentAmount` stayed 0 so one delegation passed unlimited purchases against its cap. The signed core `Delegation.spentAmount` is documented as an immutable spend-at-issue value (always 0), not a running total.

### Fixed / Security
- **`subDelegate` now verifies the parent delegation signature before minting a child** (`src/core/delegation.ts`). It previously sub-delegated without checking that the parent's own signature verified, so a child could be derived from an unsigned or tampered parent. It now runs `verifyDelegation(parent)` and throws if the parent does not verify.
- **`checkSpendGate` now denies a currency mismatch** (`src/core/commerce.ts`). The spend gate compared amounts without checking currency, so a purchase in one currency passed a budget denominated in another (the SDK does no conversion). A declared currency mismatch is now denied; an absent currency on either side stays unconstrained.
- **RFC 9421 request-signature verification now enforces the signed `expires` parameter** (`src/v2/transport/rfc9421/`). `verifyRequest` checked `created` freshness but never `expires`, so a short-lived signature presented after its `expires` (yet within the broader skew window) still verified. It now returns reason `expired` once `expires` has passed.

### Behavior changes (operations previously permitted now fail closed)
- A cross-currency commerce spend (purchase currency differs from the budget currency) is now denied by `checkSpendGate` instead of passing.
- Sub-delegation from a parent whose signature does not verify now throws instead of producing a child.
- An RFC 9421 request signature presented after its signed `expires` is now rejected instead of accepted.

## 2.8.0

### Added
- **APS Regulated Action Profile v0** (`src/v2/regulated-action/`): a profile for regulated agent actions (action class rank >= 3) with a deterministic, stateless verifier and a typed receipt (`RegulatedActionReceiptV0`). The verifier counts independent trust domains rather than signatures: it returns `reconciled` or `regulator_grade_for_class` only when a pre-committed intent reconciles against two anchors outside the operator trust domain (the IdP authority and the resource system of record), with `domains >= 2`, the resource confirmation validated against an independently registered key, and temporal ordering anchored before execution. `judgment_correctness` is always emitted as `not_claimed`. Exposed as `RegulatedActionV0` via the barrel and as the `agent-passport verify-regulated` CLI subcommand.
- **Conformance vectors** (`conformance/regulated-action/v0/`): 33 vectors pinning every disposition guard, with a TypeScript runner and an independent pure-stdlib Python runner (vendored RFC 8032 Ed25519 and RFC 8785 JCS) that agree byte for byte.
- The receipt type makes raw chain-of-thought unrepresentable by construction; `authority_ref` is a single scalar anchor.

### Notes
- The profile is a verifier and receipt format. The reference build runs its boundary attestation node at the weak level, so an end-to-end honest run reports `intent_precommitted`; `reconciled` requires a deployment whose boundary attestation node is a separate principal. Receiver-attested receipts, intent pre-commitment, and bilateral co-signing are prior art; the contribution here is the composition of an external IdP authority anchor with a verifier-computed trust-domain finality gate.

## 2.6.0-alpha.8
- feat(payment-rails/cycles): optional authority_state_at_admission snapshot on the permit receipt (#41)

## 2.6.0-alpha.4 (unreleased)

### Security
- **Charter amendment signatures now bind the proposed charter (breaking to
  prior amendment signatures).** `createAmendment`, `signAmendment`, and
  `verifyAmendment` previously signed and verified only
  `charterId + ':' + description`, so a collected signature could be replayed
  onto a different `proposedCharter` with the same id and description. All
  three now sign and verify a canonical content that includes the version
  transition and the full `proposedCharter`. This changes the signed bytes,
  so amendment signatures produced by an earlier build no longer verify and
  must be re-collected. No other primitive is affected. Swap-replay
  regression test added.

### Added
- **`computeExternalActionRefV1`** (`src/core/external-action-ref.ts`): a
  separate helper for the external cross-ecosystem correlation key
  (`action-ref-v1-jcs-sha256`, as computed by argentum-core, x402 #2332,
  Gonka, and the joint I-D on A2A #1850). It is `SHA-256(JCS({action_type,
  agent_id, scope, timestamp}))` with snake_case keys, `scope` as a single
  string, and a millisecond RFC 3339 timestamp hashed as opaque bytes (a
  non-canonical timestamp is rejected, not coerced, matching the aps-broker
  verifier). This is a distinct primitive from the APS-native `action_ref`
  (`computeActionRef`, draft-pidlisnyi-aps-01 §4.1): different preimage,
  different key casing, and a single scope string rather than the native
  multi-scope array. `computeActionRef` is unchanged. Byte-matched against
  three published anchors in `tests/external-action-ref.test.ts` (584bc79b,
  fdd7f810, d7a591f6). Additive only; no breaking change.

### Fixed
- **`computeActionRef` is now strict RFC 8785 JCS** per
  `draft-pidlisnyi-aps-01` §4.1. The action_ref pre-image is now hashed
  via `canonicalHashJCS()` (new export from `src/core/canonical-jcs.ts`)
  instead of the legacy null-stripping `canonicalHash()`. Behaviour is
  byte-identical to the prior release for every input whose four-field
  pre-image (`agentId`, `actionType`, `scopeRequired`, `timestamp`)
  contains no null/undefined values — i.e. every production input.
  Inputs that did carry a null pre-image field previously produced
  hashes that diverged from any strict-JCS verifier in the ecosystem
  (x402, AgentGraph CTEF, Nobulex); they now byte-match. Internal call
  sites (`policy.ts`, `execution-envelope.ts`) inherit the fix
  transitively.
- **`computeAttributionActionRef` is now strict RFC 8785 JCS** per
  `ATTRIBUTION-PRIMITIVE-v1.1` §1.6. The four-tuple `{agentId, actionType,
  params, nonce}` is now hashed via `canonicalHashJCS()` from
  `src/core/canonical-jcs.ts` instead of the local null-stripping
  `canonicalHashHex()`. This restores Theorem 1's Assumption A1
  (canonicalization injectivity over schema-valid action tuples) for the
  attribution receipt's security reduction: a `params` object containing
  `{k:null, v:1}` no longer collides with `{v:1}` under the canonical
  bytes. `hashAxisLeaf` and `envelopeBytes` in
  `src/v2/attribution-primitive/canonical.ts` continue to use the local
  canonicalizer in this release; a follow-up will reconcile them once
  cross-impl byte-parity for the Merkle leaves is rerun.
- Full test suite passes unchanged: **2966/2966, 0 failures** (was 2964
  pre-fix; +2 new conformance tests, one per fixed primitive).

## 2.3.0-alpha (unreleased)

Reference implementation of
[docs/ENFORCEMENT-TRUST-ANCHOR.md](./docs/ENFORCEMENT-TRUST-ANCHOR.md)
Component A (bilateral receipts for dumb Web2 sinks). All additions are
protocol primitives; gateway-side integration at `@aeoess/gateway`'s
`ProxyGateway.emit` is separate work that consumes these primitives.

### Added
- `emitDecisionReceipt` — pure function that emits a DSSE-style signed
  envelope carrying the in-toto Decision Receipt v0.1 predicate
  (`https://veritasacta.com/attestation/decision-receipt/v0.1`, tracked at
  [in-toto/attestation#549](https://github.com/in-toto/attestation/pull/549)).
  Returns `{ payloadType, payload: <JCS-canonical Statement string>, signatures,
  _digest }` — the same envelope shape the Python emitter in
  `aeoess/hermes-aps-delegation` produces, so cross-repo verifiers (including
  `@veritasacta/verify`) accept both sides.
- `parseDecisionReceiptStatement`, `computeDelegationChainRoot` — companion
  primitives for offline verification. `computeDelegationChainRoot` is the
  normative definition: `sha256(canonicalizeJCS(chain))`.
- `createPolicyReceiptWithDecisionReceipt` — convenience helper that emits the
  backward-compatible `PolicyReceipt` and the new Decision Receipt envelope in
  one call.
- Type exports: `DecisionReceiptEnvelope`, `DecisionReceiptPredicate`,
  `IntotoStatement`, `IntotoResourceDescriptor`, `DSSESignature`,
  `EmitDecisionReceiptInput`, `EpistemicClaims`, `EpistemicStatus`.
- Public constants: `DECISION_RECEIPT_PREDICATE_TYPE`, `INTOTO_STATEMENT_V1`,
  `INTOTO_PAYLOAD_TYPE`.

### Extended (optional, backward-compatible)
- `PolicyReceipt` gains three optional fields that v2.3 emitters populate and
  v2.3 verifiers prefer when present. v2.2.x consumers ignore them silently:
  - `delegation_chain_root: string` — SHA-256 hex of the JCS canonicalization
    of the full delegation chain that authorized the action.
  - `delegation_depth: number` — hops from the root principal to the acting
    agent.
  - `epistemic_claims: EpistemicClaims` — typed labels for the four claim
    classes (`policy_evaluated`, `authority_consumed`, `scope_within_bounds`,
    `effect_occurred`) per ENFORCEMENT-TRUST-ANCHOR Component 4.
- `createPolicyReceipt` accepts two new optional parameters (`delegationChain`,
  `epistemicClaims`). No change for existing call sites.

### Tests
- `tests/property-bilateral-receipt.test.ts` — 15 property tests covering
  in-toto Statement v1 shape conformance, `delegation_chain_root` determinism
  and sensitivity, epistemic-claim presence on every v2.3 receipt, v2.2.x
  backward compatibility, JCS canonicalization invariants under key
  permutation, and envelope-shape parity with the `hermes-aps-delegation`
  Python emitter.

### Not changed
- `package.json` version remains `2.2.0`. The 2.3 line is alpha and ships
  when Tima bumps and publishes.
- No changes to `docs/ENFORCEMENT-TRUST-ANCHOR.md` or
  `docs/CAPABILITY-TOKEN-SPEC-DRAFT.md` — both remain authoritative as pushed
  at commit 8be36fd.

## 2.1.0

### Added
- Cognitive Attestation envelope primitive (`src/v2/cognitive-attestation/`).
  TypeScript port of the Paper 7 normative schema (Zenodo DOI
  [10.5281/zenodo.19646276](https://doi.org/10.5281/zenodo.19646276)).
  Ships envelope construction, JCS canonicalization, Ed25519 signing,
  Stage 1 cryptographic verification including required-signer-role
  coverage, Stage 2 registry-verification interface, Stage 3 replay stub,
  and typed dispute primitives. Integrators bring their own registry
  resolvers and replay backends. Dispute resolution is explicitly out of
  SDK scope — it lives in `@aeoess/gateway`.
  - Public exports: `buildAttestation`, `canonicalizeAttestation`,
    `signCognitiveAttestation`, `cognitiveAttestationDigest`,
    `sortFeatureActivations`, `validateAttestationShape`,
    `verifyCognitiveAttestationSignature`, `verifyRequiredSignerRoles`,
    `verifyAgainstRegistry`, `verifyByReplay`, plus 25 typed interfaces.
- `verifyBoundWallet` now accepts both positional args and an object form,
  matching the `bindWallet` signature. Reported by @MoltyCel in #16.
  Positional form unchanged.

## v2.0.0-beta.0 (2026-04-17)

**Breaking change:** Product intelligence moved to `@aeoess/gateway`. See
MIGRATION.md for full details.

### Preserved signatures (no change for most consumers)

- `createDelegation`, `verifyDelegation`, `scopeAuthorizes`, `scopeCovers`
- `subDelegate`, `createReceipt`, `verifyReceipt`, `verifyRevocation`
- Passport creation / verification / VC / VP export
- All crypto primitives (Ed25519, did:key, did:web, SPIFFE, JWS, JWKS)
- All type exports
- Reputation primitives (`computeEffectiveScore`, tier definitions,
  `updateReputationFromResult`, `applyTemporalDecay`)
- Attribution primitives (Merkle, `traceBeneficiary`,
  `signAttributionConsent`, `verifyAttributionConsent`)
- Credential check (`verifyOnAccept`, `evaluateCredentialCheck`,
  `resolveCheckMode`, `AcceptanceStamp`)
- v2 pure primitives (`signAttestation`, `computeSemanticDrift`,
  `evaluateSemanticConstraints`, `validateV2UncertaintyCompliance`,
  `isV2MigrationFactorCompatible`)
- Adapter primitives (a2a, adk, crewai v2, langchain v2, mcp, gonka, ibac,
  ibac-cedar, openshell)
- `human-escalation`, `delegation-v2`, `emergency-v2`, `outcome-v2`,
  `wallet-binding`, `provisional-statement`, `attribution-consent`,
  `attribution-settlement` modules

### Moved to @aeoess/gateway

- `ProxyGateway`, `createProxyGateway`
- `AgentContext`, `createAgentContext`
- `DataGateway`, `DataEnforcementGate`
- `ContributionLedger`, `createContributionLedger`, `recordContribution`,
  `queryContributions`, `getSourceMetrics`, `getAgentDataFootprint`
- `SettlementGenerator`, `generateSettlement`, `verifySettlement`,
  `generateDataComplianceReport`
- `IntentNetwork` + all intent-card, discovery, match, intro helpers
- EU AI Act: `classifyRisk`, `mapArticles`,
  `generateTransparencyDisclosure`, `generateComplianceProfile`,
  `identifyGaps`, `generateComplianceReport`
- Training attribution: `createTrainingAttribution`,
  `createTrainingLedger`, `recordTrainingAttribution`,
  `getModelDataSources`, `createDerivation`, `createDerivationStore`,
  `recordDerivation`, `resolveAttributionChain`
- Integration bridges: `commerceWithIntent`,
  `commerceReceiptToActionReceipt`, `validateCommerceDelegation`,
  `coordinationToAgora`, `postTaskCreated`, `postReviewCompleted`,
  `postTaskCompleted`
- `GovernanceHook`, `reportReceipt`, `reportEvaluation`
- 18 v2 behavioral analytics modules (approval-fatigue, emergence,
  governance-drift, effect-enforcement, root-transition,
  cascade-correlation, composite-audit, values-override, blind-evaluation,
  affected-party, effect-sampling, circuit-breakers, output-proportionality,
  amendment, inaction-audit, externality, separation-of-powers,
  cross-chain-audit)
- Reputation analytics (drift, consistency, promotion review, demotion)
- Attribution reports (`computeAttribution`,
  `computeCollaborationAttribution`, `DEFAULT_SCOPE_WEIGHTS`,
  `RESULT_MULTIPLIER`)
- Delegation registries → `DelegationStore` class
  (`revokeDelegation`, `cascadeRevoke`, `batchRevokeByAgent`,
  `getRevocation`, `getDescendants`, `registerRevocationListener`,
  `getChain`, `getReceipts`, `addReceipt`, `getSpent`)
- v2 splits: semantic-drift tracker, scope-violations ledger,
  anomaly-detection store, migration-workflow state machine,
  attestation-ledger
- Core splits: `commercePreflight`, `ReceiptLedger`, downgrade state
  machine, `logicalCounter` / `LogicalClock`, `didCache`, weighted
  attribution models
- Health thresholds: `deriveHealthStatus`

### Migration path

Deprecation stubs ship with v2.0 — the SDK still exports moved names, but
they throw at call time with a pointer to `@aeoess/gateway`. Stubs are
scheduled for removal in v2.1.
