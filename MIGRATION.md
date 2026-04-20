# Migration from v1.x to v2.0

v2.0 separates the Agent Passport protocol (public SDK) from the reference
gateway implementation (private product). This enables Linux Foundation
stewardship of the protocol while preserving commercial gateway work.

## TL;DR for most consumers

If you only use the core protocol primitives — `createDelegation`,
`verifyDelegation`, `subDelegate`, `scopeAuthorizes`, `scopeCovers`,
`createReceipt`, `verifyReceipt`, `verifyRevocation`, passport creation and
verification, any crypto primitive, or any type export — **nothing changes**.
Upgrade to v2.0 and keep using the same API.

What moved is the stateful, product-side half of the system: long-running
registries, analytics, workflow state machines, and compliance automation.
Those live in `@aeoess/gateway` now.

## What stayed in the SDK (preserved signatures)

### Delegation & authority
- `createDelegation`, `verifyDelegation`, `subDelegate`
- `scopeAuthorizes`, `scopeCovers`
- `createReceipt`, `verifyReceipt`, `verifyRevocation`
- All delegation, scope, receipt, and revocation **types**

Note: `verifyDelegation` is now a pure signature + expiry + notBefore check.
Revocation status is drawn exclusively from `opts.cachedRevocationState`.
Without a cached state, `revoked=false`. Cascade semantics require a
`DelegationStore` from `@aeoess/gateway`.

### Crypto & identity
- All Ed25519 / did:key / did:web / SPIFFE primitives
- All JWS / JWKS / rotation-chain functions
- Passport issuance, verification, VC/VP export

### Reputation primitives
- `computeEffectiveScore`, `createScopedReputation`
- `DEFAULT_K`, `MAX_SIGMA`, `INITIAL_MU`, `INITIAL_SIGMA`, `SCARRING_PENALTY`
- Tier definitions, `resolveAuthorityTier`, `classifyEvidence`
- `DEFAULT_PROMOTION_REQUIREMENTS`, `meetsPromotionRequirements`
- `updateReputationFromResult`, `applyTemporalDecay`

### Attribution primitives
- Merkle tree construction, proofs, `traceBeneficiary`
- `AttributionReceipt`, `signAttributionConsent`, `verifyAttributionConsent`
- `createAttributionReceipt`, `checkArtifactCitations`

### v2 primitives
- `signAttestation`, `assessV2AttestationQuality`
- `STOPWORDS`, `extractKeywords`, `computeSemanticDrift` (pure math)
- `evaluateSemanticConstraints` (pure predicate)
- `validateV2UncertaintyCompliance`
- `isV2MigrationFactorCompatible`
- All v2 types
- `human-escalation` module (kept whole — no state)
- `delegation-v2`, `emergency-v2`, `outcome-v2` modules (kept whole)
- `wallet-binding`, `provisional-statement`, `attribution-consent`,
  `attribution-settlement`

### Adapters (pure primitives)
- `a2a`, `adk`, `crewai` (v2 IBAC-pattern), `langchain` (v2 IBAC-pattern)
- `mcp`, `gonka`, `ibac`, `ibac-cedar`, `openshell`

### Credential check
- `verifyOnAccept`, `evaluateCredentialCheck`, `resolveCheckMode`
- `AcceptanceStamp`, `CredentialCheckMode`, `CredentialCheckPolicy`,
  `CredentialCheckResult`, `CredentialCheckDenialCode`

## Shape changes within preserved primitives

Some primitives stayed in the SDK but changed field-level shape.
Surfaced in response to partner cross-version compat tests (MoltyCel,
issue #16). Field-level diffs are enumerated here so consumers parsing
v1 output structures can port their parsers cleanly.

### Wallet binding: `wallet_ref` field diff (v1 → v2)

The `wallet-binding` primitive is preserved in v2, but the shape of the
`wallet_ref` record (the per-wallet entry inside `passport.bound_wallets`)
changed. Consumers that parse `wallet_ref.signature` or `wallet_ref.nonce`
from v1 attestations will see those fields missing in v2 output.

| Field | v1.x | v2.x | Notes |
|---|---|---|---|
| `address` | ✓ | ✓ | preserved |
| `chain` | ✓ | ✓ | preserved |
| `signature` | ✓ | removed | v1 field: raw wallet signature over nonce |
| `nonce` | ✓ | removed | v1 field: challenge bytes |
| `binding_signature` | — | added | v2 field: passport-key Ed25519 signature over the canonical binding payload (hex) |
| `bound_at` | — | added | v2 field: ISO 8601 timestamp, part of the canonical binding payload |

The semantic shift is intentional and strengthens the primitive: v1
bound wallets with a raw wallet signature (any holder of the wallet
key could produce one); v2 binds wallets with a passport-key signature
over a canonical binding payload (only the passport holder can produce
one, and the binding is cryptographically attributable to the identity
that made it).

**Verifier API reminder.** `verifyBoundWallet` takes positional
arguments, not a config object:

```ts
verifyBoundWallet(
  passport: SignedPassport,
  chain: WalletChain,
  address: string
): boolean
```

Returns `true` for any wallet currently bound to the passport.
Passing a config object (e.g. `verifyBoundWallet({ passport, chain,
address })`) will fail the internal lookup because the positional
slots for `chain` and `address` are `undefined`. The asymmetry with
`bindWallet` (which does accept a config object) is resolved in
v2.1.0 — both forms supported.

## What moved to @aeoess/gateway

### Data lifecycle (commit 4b710c4)

`ProxyGateway` was already moved in af6c02d. This commit moved the
remaining data-lifecycle product chain.

#### `AgentContext` / `createAgentContext`

Reason: stateful per-agent context binding; product intelligence.

```ts
// Before (v1.x)
import { createAgentContext, AgentContext } from 'agent-passport-system'

// After (v2.0)
import { createAgentContext, AgentContext } from '@aeoess/gateway'
```

#### `DataEnforcementGate`

Reason: stateful receipt/access ledger; gateway enforcement surface.

```ts
// Before
import { DataEnforcementGate } from 'agent-passport-system'

// After
import { DataEnforcementGate } from '@aeoess/gateway'
```

SDK retains `DataAccessRequest`, `DataAccessDecision`,
`DataEnforcementConfig`, `DataGatewayConfig`, `TermsAcceptance` as
interface types so the compile-time contract stays shared.

#### `DataGateway`

Reason: terms-of-access state machine + acceptance ledger.

```ts
// Before
import { DataGateway } from 'agent-passport-system'

// After
import { DataGateway } from '@aeoess/gateway'
```

#### `ContributionLedger` / `createContributionLedger` / `recordContribution` / `queryContributions` / `getSourceMetrics` / `getAgentDataFootprint`

Reason: training attribution is product intelligence (the "pixel for data in
the agent economy"). Primitives for signed contribution receipts stay; the
ledger and analytics move.

```ts
// Before
import { createContributionLedger, recordContribution } from 'agent-passport-system'

// After
import { createContributionLedger, recordContribution } from '@aeoess/gateway'
```

#### `SettlementGenerator` / `generateSettlement` / `verifySettlement` / `generateDataComplianceReport`

Reason: settlement computation and compliance reports are product intelligence.

```ts
// Before
import { generateSettlement } from 'agent-passport-system'

// After
import { generateSettlement } from '@aeoess/gateway'
```

#### `IntentNetwork` / `createIntentNetwork` / `createIntentCard` / `verifyIntentCard` / `publishCard` / `removeCard` / `computeRelevance` / `searchMatches` / `requestIntro` / `respondToIntro` / `getDigest`

Reason: cross-tenant discovery and matching is commercial surface.

```ts
// Before
import { createIntentNetwork, searchMatches } from 'agent-passport-system'

// After
import { createIntentNetwork, searchMatches } from '@aeoess/gateway'
```

#### EU AI Act compliance — `classifyRisk`, `mapArticles`, `generateTransparencyDisclosure`, `generateComplianceProfile`, `identifyGaps`, `generateComplianceReport`

Reason: compliance automation is gateway product, not protocol.

```ts
// Before
import { classifyRisk, generateComplianceReport } from 'agent-passport-system'

// After
import { classifyRisk, generateComplianceReport } from '@aeoess/gateway'
```

#### Training attribution — `createTrainingAttribution`, `createTrainingLedger`, `recordTrainingAttribution`, `getModelDataSources`, `createDerivation`, `createDerivationStore`, `recordDerivation`, `resolveAttributionChain`

```ts
// Before
import { recordTrainingAttribution } from 'agent-passport-system'

// After
import { recordTrainingAttribution } from '@aeoess/gateway'
```

#### Integration bridges — `commerceWithIntent`, `commerceReceiptToActionReceipt`, `validateCommerceDelegation`, `coordinationToAgora`, `postTaskCreated`, `postReviewCompleted`, `postTaskCompleted`

Reason: cross-module product orchestration.

```ts
// Before
import { commerceWithIntent } from 'agent-passport-system'

// After
import { commerceWithIntent } from '@aeoess/gateway'
```

### ProxyGateway (commit af6c02d)

The 105 KB runtime `ProxyGateway` implementation moved to
`@aeoess/gateway`. SDK keeps the interface contract in
`src/types/gateway.ts`.

```ts
// Before
import { ProxyGateway, createProxyGateway } from 'agent-passport-system'

// After
import { ProxyGateway, createProxyGateway } from '@aeoess/gateway'
```

### Governance hook + gateway reporter (commit a731f34)

The stateful `GovernanceHook` class and the hosted
`reportReceipt`/`reportEvaluation` helpers moved. Adapters now rely on the
existing `onReceipt`/`onDenied` callbacks.

```ts
// Before
import { GovernanceHook, reportReceipt } from 'agent-passport-system'

// After
import { GovernanceHook, reportReceipt } from '@aeoess/gateway'
```

### 18 v2 behavioral analytics modules (commit e0c009a)

Moved: `approval-fatigue`, `emergence`, `governance-drift`,
`effect-enforcement`, `root-transition`, `cascade-correlation`,
`composite-audit`, `values-override`, `blind-evaluation`, `affected-party`,
`effect-sampling`, `circuit-breakers`, `output-proportionality`,
`amendment`, `inaction-audit`, `externality`, `separation-of-powers`,
`cross-chain-audit`.

```ts
// Before
import { trackApprovalFatigue } from 'agent-passport-system'

// After
import { trackApprovalFatigue } from '@aeoess/gateway'
```

### Reputation analytics (commit 16ff1e1)

Primitives stayed. Drift analytics, consistency scoring, the promotion
review workflow, and demotion triggers moved.

### Attribution reports (commit 1e61b92)

Merkle primitives stayed. Moved: `computeAttribution`,
`computeCollaborationAttribution`, `DEFAULT_SCOPE_WEIGHTS`,
`RESULT_MULTIPLIER`.

```ts
// Before
import { computeAttribution } from 'agent-passport-system'

// After
import { computeAttribution } from '@aeoess/gateway'
```

### Delegation store (commit d6d2ab7)

Module-scope registries (`revocationRegistry`, `receiptStore`,
`chainRegistry`, `spendTracker`, `revocationListeners`) moved into a
`DelegationStore` class. Cascade revocation, chain validation, receipt
storage, spend accumulation, and batch revocation follow.

```ts
// Before
import { revokeDelegation, getReceipts, getDescendants } from 'agent-passport-system'
// revocation registry was module-scope

// After
import { DelegationStore } from '@aeoess/gateway'
const store = new DelegationStore()
store.revokeDelegation(...)
store.getReceipts(...)
```

Moved: `revokeDelegation`, `cascadeRevoke`, `batchRevokeByAgent`,
`getRevocation`, `getDescendants`, `registerRevocationListener`, `getChain`,
`getReceipts`, `addReceipt`, `getSpent`.

Internal SDK adaptation: `rotateAndInvalidate` now takes an optional
`cascadeRevoke` callback. Callers pass `DelegationStore`'s bound method.

### v2 AMBIGUOUS splits (commit c91ae5d)

Per-file: primitives stay, stateful parts move.

- `semantic-drift.ts` → stateful intent-record ledger + aggregate queries
  move to gateway `semantic-drift-tracker.ts`. Pure math stays.
- `semantic-scoping.ts` → scope registry + violation ledger move to
  gateway `scope-violations.ts`. Types + `evaluateSemanticConstraints` stay.
- `anomaly-v2.ts` → action-history ledger + concentration scoring move to
  gateway `anomaly-detection.ts`. `validateV2UncertaintyCompliance` stays.
- `migration-v2.ts` → request store + approval state machine + probation +
  lineage move to gateway `migration-workflow.ts`. Types stay.
- `attestation-v2.ts` → attestation ledger + aggregate queries move to
  gateway `attestation-ledger.ts`. `signAttestation` +
  `assessV2AttestationQuality` stay.

### 6 core AMBIGUOUS splits (commit 4a0467d)

- `commerce.ts` → gate predicates stay. `commercePreflight` pipeline moves.
- `receipt-ledger.ts` → Merkle primitives stay. `ReceiptLedger` class moves.
- `governance-posture.ts` → tier types stay. Downgrade state machine moves.
- `time.ts` → timestamp math stays pure. `logicalCounter` extracted to
  gateway `LogicalClock`.
- `entity-verification.ts` → pure `verify` stays. `didCache` extracted.
- `data-source-attribution.ts` → Merkle + equal-weight model stay. Weighted
  models move.

### Health thresholds (commit f12a9f4)

`deriveHealthStatus` + threshold constants moved to gateway
`health-policy.ts`. SDK retains only the `AgentHealthStatus` interface.

## What moved per commit

| Commit | Scope |
|--------|-------|
| `f12a9f4` | Extract health thresholds from `types/` |
| `e0c009a` | Move 18 v2 behavioral analytics to gateway |
| `a731f34` | Move governance-hook + gateway-reporter to gateway |
| `af6c02d` | Move `ProxyGateway` class to gateway |
| `4b710c4` | Move data lifecycle product chain to gateway |
| `ec92a1c` | Expose primitives needed by migrated gateway code |
| `16ff1e1` | Split `reputation-authority` into SDK primitive + gateway analytics |
| `1e61b92` | Split attribution — Merkle stays, report generators move |
| `d6d2ab7` | Split `delegation.ts` — registries move to `DelegationStore` |
| `c91ae5d` | Split 6 v2 AMBIGUOUS files — primitives stay, product moves |
| `4a0467d` | Split 6 core AMBIGUOUS files — primitives stay, product moves |

## Deprecation stubs

The SDK still exports the names of moved functions and classes. They throw
at runtime with a clear message pointing at `@aeoess/gateway`. This gives
you compile-time visibility (imports still type-check) and a loud,
unmistakable error at the call site if you try to invoke one without
migrating.

Example:

```ts
import { ProxyGateway } from 'agent-passport-system'
const g = new ProxyGateway({})
// throws: "ProxyGateway class moved to @aeoess/gateway. See MIGRATION.md"
```

Plan to migrate your imports before v2.1, when the stubs are removed.

## Timeline

- **v2.0.0-beta.0**: Published to npm `next` tag.
- **48–72h partner test window**: AgentID, MolTrust, Microsoft AGT, Google
  ADK adapter path, InsumerAPI, Kanoniv.
- **v2.0.0 final**: Promoted to `latest` tag if the window stays clean.
- **v1.46.x**: Remains on `legacy-v1` tag for 6 months. Pin there if you
  cannot migrate yet.
- **v2.1**: Deprecation stubs removed. Import from `@aeoess/gateway` before
  this release.

## Appendix: Full stub manifest

The following symbols are retained in the SDK as deprecation stubs that
throw at runtime (or at module-import time). They preserve import paths
so partners see a clear migration error, not a cryptic "module not found."

Stubs are grouped by file. Root-reachable stubs are re-exported from
`src/index.ts` — `import { X } from 'agent-passport-system'` still
type-checks but throws at call time. Subpath-only stubs require
`import { X } from 'agent-passport-system/<subpath>'`; importing them via
the root fails at compile time, which is the intended signal that your
integration needs to move to `@aeoess/gateway`.

### Adapters (src/adapters/)

- **`src/adapters/gateway-reporter.ts`** — `reportReceipt`,
  `reportEvaluation`, `GatewayReporterConfig` (type). Subpath-only.
- **`src/adapters/governance-hook.ts`** — `GovernanceHook` (class),
  `GovernanceHookConfig`, `ActionDescriptor`, `GovernanceVerdict`,
  `GovernanceResult`, `GovernanceReceipt` (all types). Subpath-only.

Note: the factory functions `createCrewAIGovernance`,
`createADKGovernancePlugin`, `createLangChainGovernanceHandler`, and
`createA2AGovernance` are **removed entirely** (no stub). Import them
from `@aeoess/gateway` or rebuild using the primitive mappers in
`src/adapters/{crewai,adk,langchain,a2a}.ts` plus `onReceipt`/`onDenied`
callbacks.

### Core runtime (src/core/)

- **`src/core/gateway.ts`** — `ProxyGateway` (class). Subpath-only.
- **`src/core/context.ts`** — `AgentContext` (class), `createAgentContext`.
  Subpath-only.
- **`src/core/data-contribution.ts`** — `createContributionLedger`,
  `recordContribution`, `queryContributions`, `getSourceMetrics`,
  `getAgentDataFootprint`. Subpath-only.
- **`src/core/data-enforcement.ts`** — `DataEnforcementGate` (class).
  **Root-reachable** (exported from `src/index.ts`).
- **`src/core/data-gateway.ts`** — `DataGateway` (class).
  **Root-reachable** (exported from `src/index.ts`).
- **`src/core/data-settlement.ts`** — `generateSettlement`,
  `verifySettlement`, `generateDataComplianceReport`. Subpath-only.
- **`src/core/euaiact.ts`** — `classifyRisk`, `mapArticles`,
  `generateTransparencyDisclosure`, `generateComplianceProfile`,
  `identifyGaps`, `generateComplianceReport`. Subpath-only.
- **`src/core/integration.ts`** — `commerceWithIntent`,
  `commerceReceiptToActionReceipt`, `validateCommerceDelegation`,
  `coordinationToAgora`, `postTaskCreated`, `postReviewCompleted`,
  `postTaskCompleted`. Subpath-only.
- **`src/core/intent-network.ts`** — `createIntentNetwork`,
  `createIntentCard`, `verifyIntentCard`, `isCardExpired`, `publishCard`,
  `removeCard`, `computeRelevance`, `searchMatches`, `requestIntro`,
  `respondToIntro`, `getDigest`, `getVisibleItems`. Subpath-only.
- **`src/core/training-attribution.ts`** — `createTrainingAttribution`,
  `verifyTrainingAttribution`, `createTrainingLedger`,
  `recordTrainingAttribution`, `getModelDataSources`,
  `getSourceTrainingCount`, `createDerivation`, `createDerivationStore`,
  `recordDerivation`, `resolveAttributionChain`. Subpath-only.
- **`src/core/attribution.ts`** — `computeAttribution`,
  `computeCollaborationAttribution`. Pure Merkle primitives
  (`hashReceipt`, `traceBeneficiary`, `verifyAttributionReport`,
  `buildMerkleRoot`, `generateMerkleProof`, `verifyMerkleProof`) stay.
- **`src/core/delegation.ts`** — stateful registry accessors:
  `revokeDelegation`, `cascadeRevoke`, `revokeByAgent`, `validateChain`,
  `getDescendants`, `getChainEntry`, `onRevocation`, `getReceipts`,
  `getRevocation`, `getSpent`. The 8 pure primitives (`createDelegation`,
  `subDelegate`, `verifyDelegation`, `verifyRevocation`, `createReceipt`,
  `verifyReceipt`, `scopeCovers`, `scopeAuthorizes`) are unchanged.
  `clearStores()` is retained as a no-op for test hygiene.

### v2 AMBIGUOUS-split modules (src/v2/)

Stateful functions throw; pure primitives in the same file stay callable.

- **`src/v2/anomaly-v2.ts`** — stubs: `recordV2Action`,
  `getV2ActionHistory`, `getV2AnomalyFlags`, `getV2UnreviewedFlags`,
  `checkV2FirstMaxAuthority`, `computeV2ConcentrationMetrics`,
  `reviewV2AnomalyFlag`, `clearV2AnomalyStores`. Keeps:
  `validateV2UncertaintyCompliance`.
- **`src/v2/attestation-v2.ts`** — stubs: `createV2Attestation`,
  `getV2Attestation`, `getV2AttestationForAction`,
  `getV2AttestationsForAgent`, `getV2AgentAttestationQualityAvg`,
  `clearV2AttestationStore`. Keeps: `signAttestation`,
  `assessV2AttestationQuality`.
- **`src/v2/migration-v2.ts`** — stubs: `requestV2Migration`,
  `approveV2Migration`, `executeV2Migration`, `isV2InProbation`,
  `computeV2MigrationDiscount`, `traceV2MigrationLineage`,
  `rollbackV2Migration`, `processV2CompletedProbations`,
  `getV2MigrationRequest`, `getV2MigrationRecord`,
  `getV2MigrationsForAgent`, `getV2ActiveProbations`,
  `clearV2MigrationStores`. Keeps: `isV2MigrationFactorCompatible`.
- **`src/v2/semantic-drift.ts`** — stubs: `recordSemanticIntent`,
  `analyzeSemanticDrift`, `getDriftResults`, `getAgentDriftAverage`,
  `isAgentSemanticRisk`, `getSemanticRecord`,
  `clearSemanticDriftStores`. Keeps: `extractKeywords`,
  `computeSemanticDrift`, `STOPWORDS`.
- **`src/v2/semantic-scoping.ts`** — stubs: `defineSemanticScope`,
  `checkSemanticCompliance`, `getScopeViolations`,
  `clearSemanticScopingStores`. Keeps: `evaluateSemanticConstraints`,
  plus `SemanticConstraint`, `SemanticScope`, `ScopeViolation` types.

### v2 behavioral analytics — module-level throw (src/v2/)

These 18 files throw at **import time**, not at call time. Any `import`
of the file fails immediately with a migration pointer. There are no
function-level stubs because the modules were moved wholesale.

`affected-party.ts`, `amendment.ts`, `approval-fatigue.ts`,
`blind-evaluation.ts`, `cascade-correlation.ts`, `circuit-breakers.ts`,
`composite-audit.ts`, `cross-chain-audit.ts`, `effect-enforcement.ts`,
`effect-sampling.ts`, `emergence.ts`, `externality.ts`,
`governance-drift.ts`, `inaction-audit.ts`, `output-proportionality.ts`,
`root-transition.ts`, `separation-of-powers.ts`, `values-override.ts`.

### Summary counts

- Files containing `throw new Error(MOVED)` or equivalent: **19**
  (14 function/class stub files + 5 v2 AMBIGUOUS-split files)
- Files that throw at module import: **18** (behavioral analytics)
- Root-reachable stubs (fail at call time via `import … from 'agent-passport-system'`): **2**
  (`DataGateway`, `DataEnforcementGate`)
- Subpath-only stubs (fail at compile time from the root, at call time via
  subpath import): **all others**
