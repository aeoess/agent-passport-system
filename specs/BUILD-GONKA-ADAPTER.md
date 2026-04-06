# BUILD-GONKA-ADAPTER — Governance layer for decentralized GPU inference networks

## Context

Gonka is a decentralized GPU compute network (15,000+ H100 equivalents, Cosmos SDK chain).
They use on-chain allowlists to control inference access and manual governance votes to
manage participant eligibility. Their new devshards architecture moves inference execution
off-chain into subgroups that need off-chain trust verification.

APS replaces their primitive allowlist with delegation chains (monotonic narrowing,
automatic expiry, cascade revocation) and provides signed receipts for off-chain
devshard audit trails.

## Deliverables

### 1. `src/adapters/gonka.ts` (~160 lines)

```typescript
// === Types ===

interface GonkaInferenceRequest {
  model: string                    // e.g. "Qwen/Qwen3-235B-A22B-Instruct-2507-FP8"
  prompt: string
  maxTokens?: number
  hostAddress?: string             // gonka1... address
  epochId?: number
  devshardId?: string              // off-chain shard identifier
}

interface GonkaHostConfig {
  passport: SignedPassport
  delegation: Delegation
  privateKey: string
  allowedModels?: string[]         // model allowlist
  maxInferencesPerEpoch?: number   // rate limit per epoch
  onReceipt?: (r: ActionReceipt) => void
  onDenied?: (info: { host: string; reason: string }) => void
}

interface GonkaInferenceReceipt {
  receipt: ActionReceipt
  model: string
  epochId?: number
  devshardId?: string
  inferenceHash: string            // sha256 of prompt+response for devshard verification
}

interface GonkaHostVerification {
  authorized: boolean
  reason: string
  scope: string
  hostAddress: string
  model: string
}

// === Functions ===

// Verify a host has authority to serve inference for a model
export function verifyGonkaHost(
  hostAddress: string,
  model: string,
  config: GonkaHostConfig
): GonkaHostVerification

// Govern an inference request — check delegation, model, rate limits
export function governGonkaInference(
  request: GonkaInferenceRequest,
  execute: (req: GonkaInferenceRequest) => Promise<{ response: string; tokensUsed: number }>,
  config: GonkaHostConfig
): Promise<{ result: { response: string; tokensUsed: number }; receipt: GonkaInferenceReceipt } | { denied: true; reason: string; receipt: ActionReceipt }>

// Create a devshard session receipt (off-chain proof for settlement)
export function createDevshardReceipt(
  devshardId: string,
  inferenceCount: number,
  totalTokens: number,
  participants: string[],          // host addresses in the shard
  config: Pick<GonkaHostConfig, 'passport' | 'delegation' | 'privateKey'>
): ActionReceipt

// Convert APS delegation to Gonka-compatible allowlist entry
export function delegationToAllowlistEntry(
  delegation: Delegation,
  passport: SignedPassport
): { address: string; model: string; scope: string[]; expiresAtBlock?: number }

// Convert Gonka epoch timing to APS delegation expiry
export function epochToDelegationExpiry(
  currentEpoch: number,
  epochDurationBlocks: number,
  epochsValid: number
): Date

// Validate PoC (Proof-of-Compute) participation receipt
export function verifyPoCParticipation(
  hostAddress: string,
  epochId: number,
  weight: number,
  config: Pick<GonkaHostConfig, 'passport' | 'privateKey'>
): ActionReceipt
```

Key logic:
- `verifyGonkaHost`: checks passport valid, delegation covers `inference:serve:{model}` scope, model in allowedModels
- `governGonkaInference`: full pipeline — verify host, check model, check rate limit, execute, produce receipt with inferenceHash (sha256 of prompt+response for devshard verification)
- `createDevshardReceipt`: session-level receipt covering all inferences in a devshard round. This is the off-chain audit trail between session creation and on-chain settlement
- `delegationToAllowlistEntry`: bridge from APS delegation to Gonka's native format. Shows how delegation chains replace their CSV allowlist
- `epochToDelegationExpiry`: converts Gonka's block-based epochs to APS time-based expiry
- `verifyPoCParticipation`: receipt proving a host participated in PoC validation (addresses the 48% non-validation problem from epoch 155)

Scope mapping:
- `inference:serve:{model}` — host can serve this model
- `inference:validate` — host can participate in PoC validation  
- `devshard:participate` — host can join devshard sessions
- `devshard:settle` — host can submit settlement to chain
- `governance:vote` — host can vote on proposals

### 2. Export from `src/index.ts`

Add all Gonka adapter exports.

### 3. Tests: `tests/gonka-adapter.test.ts` (~18 tests)

- verify host authorized for model
- verify host denied (wrong model)
- verify host denied (expired delegation)
- govern inference — authorized with receipt
- govern inference — denied (scope violation)
- govern inference — denied (model not in allowlist)
- govern inference — receipt contains inferenceHash
- devshard receipt creation with participants
- devshard receipt signature verification
- delegation to allowlist entry conversion
- epoch to delegation expiry calculation
- PoC participation receipt
- PoC receipt signature verification
- rate limit enforcement (maxInferencesPerEpoch)
- onDenied callback fires
- onReceipt callback fires
- empty model allowlist permits all models
- multiple models in scope

## Build Rules

- Same receipt builder pattern as IBAC/MCP/LangChain adapters (sign + canonicalize directly)
- No Gonka SDK dependency (all types are local interfaces)
- inferenceHash = sha256 of canonicalize({ prompt, response }) for devshard verification
- Use `scopeAuthorizes()` for authorization checks
- `npm run build && npm test` must pass
- Report test count delta

## Strategic Context

This adapter demonstrates how APS delegation chains replace Gonka's primitive
allowlist.csv + manual governance votes with:
1. Automatic expiry (no governance vote to extend)
2. Monotonic narrowing (sub-delegations can only reduce authority)
3. Cascade revocation (one call kills all downstream)
4. Signed receipts (off-chain proof for devshard settlement)
5. Behavioral attestation (catch non-validators systematically)

The devshard angle is the entry point: Gonka just moved inference off-chain
and needs exactly the off-chain trust layer APS provides.
