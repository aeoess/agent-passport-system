# Changelog

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
