# Changelog

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
