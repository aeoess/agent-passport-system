# Build Plan: action_ref + freshness types

## Intent

We made specific architectural claims in GitHub threads (A2A#1672 with xsa520/desiorac, A2A#1712 with VCOne-AI) about two features that are designed but not yet concrete in the SDK. This build makes them real.

**Rule: We do not claim what we haven't built. These threads have active WG participants watching.**

## What We're Building

### 1. `action_ref` — Content-Addressed Request Identity

**Thread context (A2A#1672):** xsa520 asked whether `action_ref` identifies the request or the evaluated decision. We answered: `action_ref` = request identity (`SHA-256(canonical(agent + action + scope + timestamp))`), `compound_digest` = evaluated decision identity. Equivalence is over `compound_digest`, invariant to verification method.

**What exists:** `compoundDigest` is already in `src/types/policy.ts` on the `PolicyReceipt` type. `contentHash` exists on `ActionIntent`. But there is NO explicit `action_ref` field that content-addresses the request tuple.

**What to build:**
- Add `actionRef` field to `ActionIntent` type (computed, not user-supplied)
- Add `computeActionRef(intent: ActionIntent): string` function that produces `SHA-256(canonical(agentId + action.type + action.scopeRequired + timestamp))`
- Canonical format: sorted keys, JSON.stringify with keys sorted, ISO 8601 timestamps with SECOND precision UTC (no fractional seconds, no timezone offsets — format: `2026-04-05T03:39:31Z`)
- Add `actionRef` to `PolicyReceipt` so the receipt carries both `actionRef` (request identity) and `compoundDigest` (decision identity)

### 2. `freshness` — Typed Attestation Evidence Freshness

**Thread context (A2A#1712):** VCOne-AI pointed out that `ttl: null` on snapshot-type attestations (TPM quotes) is semantically wrong — it implies the evidence never expires. SPIFFE SVIDs rotate continuously (implicit freshness), TPM quotes are point-in-time snapshots (need explicit staleness policy). We proposed a `freshness` field with `type: 'snapshot' | 'rotating'` and `max_age`.

**What exists:** `src/core/attestation.ts` has freshness checks (timestamp-based). `src/types/passport.ts` has attestation types. But there is NO typed `freshness` structure distinguishing snapshot vs rotating evidence.

**What to build:**
- Add `AttestationFreshness` interface to `src/types/passport.ts`:
  ```typescript
  interface AttestationFreshness {
    type: 'snapshot' | 'rotating' | 'static'
    validAt: string           // ISO 8601 — when the evidence was produced
    ttl?: number              // seconds — for rotating types (SPIFFE SVID lifetime)
    maxAge?: number           // seconds — recommended staleness window for snapshot types
  }
  ```
- Add `freshness?: AttestationFreshness` field to the attestation evidence type
- Add `computeEvidenceAge(freshness: AttestationFreshness): number` — returns seconds since `validAt`
- Add `isEvidenceFresh(freshness: AttestationFreshness, now?: Date): boolean` — checks `ttl` for rotating, `maxAge` for snapshot
- Add `freshness` to `importExternalAttestation()` flow so imported evidence carries freshness metadata
- The `grade` remains as quick-filter index; `freshness` is the detailed metadata consumers check for high-assurance contexts

## Pre-Build Checklist (CC MUST do these FIRST)

### Step 0: Verify machine and pull latest
```bash
whoami && hostname
cd /Users/tima/agent-passport-system
git stash && git pull --rebase && git stash pop
```

### Step 1: Read current state — understand what exists
Read these files BEFORE writing any code:

```
src/types/policy.ts          — ActionIntent, PolicyDecision, PolicyReceipt, compoundDigest
src/types/passport.ts        — attestation types, passport grade, SignedPassport
src/types/context.ts         — AgentContext, 3-sig chain references
src/types/commerce.ts        — CommerceActionReceipt (check for conflicts)
src/types/execution-envelope.ts — ExecutionEnvelopeReceipt, compoundDigest usage
src/core/attestation.ts      — existing freshness checks, importExternalAttestation
src/core/execution-envelope.ts — envelope creation, digest computation
src/core/context.ts          — how 3-sig chain flows through context
src/index.ts                 — all exports (source of truth for public API)
```

### Step 2: Check dependencies
- Verify `crypto` / `node:crypto` usage for SHA-256 (should already be in the codebase)
- Check if there's a `canonicalize` or `canonicalJson` utility already. If not, build one (sorted keys, deterministic JSON)
- Check existing test patterns in `tests/` to understand test structure

### Step 3: Check for naming conflicts
```bash
grep -rn "actionRef\|action_ref" src/ tests/
grep -rn "AttestationFreshness\|evidenceAge\|isEvidenceFresh" src/ tests/
grep -rn "canonicalJson\|canonicalize\|sortedKeys" src/ tests/
```

## Build Order (CC executes in this sequence)

### Phase 1: Utility — Canonical JSON
File: `src/core/canonical.ts` (NEW)

```typescript
export function canonicalJson(obj: Record<string, unknown>): string
export function canonicalHash(obj: Record<string, unknown>): string  // SHA-256 of canonicalJson
export function normalizeTimestamp(ts: string): string  // → YYYY-MM-DDTHH:mm:ssZ (second precision, UTC)
```

- Sorted keys recursively
- No whitespace
- Timestamps normalized to second precision UTC
- Returns deterministic string suitable for hashing
- Tests: identical objects in different key order produce same hash, timestamp normalization strips fractional seconds

### Phase 2: action_ref

File: `src/types/policy.ts` (EDIT — add `actionRef` field)
File: `src/core/action-ref.ts` (NEW)

```typescript
export function computeActionRef(intent: ActionIntent): string
// Returns SHA-256(canonicalJson({ agentId, actionType, scopeRequired, timestamp }))
// timestamp is normalizeTimestamp(intent timestamp or current time)

export function actionRefsMatch(a: string, b: string): boolean
// Two receipts with same actionRef = same request
// Two receipts with same compoundDigest = same decision
```

Changes to existing types:
- `ActionIntent` — add `actionRef?: string` (computed by `computeActionRef`, optional for backwards compat)
- `PolicyReceipt` — add `actionRef?: string` (copied from intent at receipt creation)
- `ExecutionEnvelopeReceipt` — add `actionRef?: string`

**CRITICAL: All existing fields remain. actionRef is additive. No breaking changes.**

Tests:
- Same intent produces same actionRef
- Different timestamp (same second) produces same actionRef (second precision normalization)
- Different timestamp (different second) produces different actionRef
- actionRef is deterministic regardless of field insertion order
- actionRef ≠ compoundDigest (they hash different inputs)

### Phase 3: Freshness types

File: `src/types/passport.ts` (EDIT — add AttestationFreshness)
File: `src/core/freshness.ts` (NEW)

```typescript
export interface AttestationFreshness {
  type: 'snapshot' | 'rotating' | 'static'
  validAt: string
  ttl?: number       // seconds, for rotating (e.g. SPIFFE SVID lifetime)
  maxAge?: number    // seconds, recommended staleness window for snapshot (e.g. TPM)
}

export function computeEvidenceAge(freshness: AttestationFreshness, now?: Date): number
// Returns seconds since validAt

export function isEvidenceFresh(freshness: AttestationFreshness, now?: Date): boolean
// rotating: now - validAt < ttl
// snapshot: now - validAt < maxAge (if maxAge defined), true if maxAge undefined
// static: always true (e.g. certificate-based, managed by CA)

export function createSnapshotFreshness(validAt: string, maxAge?: number): AttestationFreshness
export function createRotatingFreshness(validAt: string, ttl: number): AttestationFreshness
```

Changes to existing types:

- Find the attestation evidence type in `passport.ts` — add `freshness?: AttestationFreshness`
- `importExternalAttestation()` in `src/core/attestation.ts` — accept optional freshness param, attach to imported evidence
- Export new types and functions from `src/index.ts`

**CRITICAL: freshness field is optional. No breaking changes to existing attestation flows.**

Tests:
- Snapshot freshness with maxAge 3600: fresh at +1800s, stale at +3601s
- Rotating freshness with ttl 300: fresh at +200s, stale at +301s
- Static freshness: always fresh regardless of age
- Missing maxAge on snapshot: always returns fresh (conservative default)
- computeEvidenceAge returns correct seconds
- Round-trip: create freshness → check → age → check again after simulated time advance

### Phase 4: Integration — Wire into existing flows

- `createIntent()` (if exists) should auto-compute `actionRef`
- `createEnvelope()` / execution envelope flow should propagate `actionRef` from intent to receipt
- `importExternalAttestation()` should accept and store freshness
- Verify the 3-sig chain still works: ActionIntent (with actionRef) → PolicyDecision → ActionReceipt → PolicyReceipt (with both actionRef and compoundDigest)

### Phase 5: Export from index.ts

Add to `src/index.ts`:
```typescript
// Canonical JSON & action_ref
export { canonicalJson, canonicalHash, normalizeTimestamp } from './core/canonical.js'
export { computeActionRef, actionRefsMatch } from './core/action-ref.js'

// Attestation freshness
export { computeEvidenceAge, isEvidenceFresh, createSnapshotFreshness, createRotatingFreshness } from './core/freshness.js'
export type { AttestationFreshness } from './types/passport.js'
```

## Post-Build Verification (CC MUST do ALL of these)

### Step 1: TypeScript strict compilation
```bash
npx tsc --noEmit
```
Must exit 0 with zero errors. If not, fix before proceeding.

### Step 2: Run full test suite
```bash
npm test
```
All 2,189+ existing tests must still pass. Zero regressions.

### Step 3: Run new tests specifically
```bash
npm test -- --grep "canonical\|actionRef\|action_ref\|freshness\|evidenceAge"
```
All new tests must pass.

### Step 4: Check exports
```bash
node -e "const aps = require('./dist/index.js'); console.log(typeof aps.computeActionRef, typeof aps.isEvidenceFresh, typeof aps.canonicalHash)"
```
Should print: `function function function`

### Step 5: Cross-reference thread claims
Verify these specific claims are now concrete:

1. `actionRef = SHA-256(canonical(agent + action + scope + timestamp))` — ✓ computeActionRef does this
2. Equivalence is over `compoundDigest`, not `actionRef` — ✓ both fields exist independently
3. `freshness.type: 'snapshot' | 'rotating'` with `maxAge` — ✓ AttestationFreshness type
4. `isEvidenceFresh()` checks ttl for rotating, maxAge for snapshot — ✓ function exists
5. Timestamp precision is ISO 8601 second precision UTC — ✓ normalizeTimestamp enforces this

### Step 6: Build dist
```bash
npm run build
```
Must exit 0.

## DO NOT DO

- Do NOT bump version number — Tima handles versioning
- Do NOT run `npm publish` — requires Touch ID
- Do NOT modify gateway code — this is SDK only
- Do NOT break existing type signatures — all new fields are optional
- Do NOT remove or rename existing fields — actionRef and freshness are additive
- Do NOT modify test infrastructure — only add new test files
- Do NOT commit or push — leave for Tima to review the diff first

## Commit Message (when Tima approves)

```
feat: add action_ref content-addressed request identity + attestation freshness types

- canonicalJson/canonicalHash: deterministic JSON serialization for cross-system receipt comparison
- computeActionRef: SHA-256 of canonical(agentId + actionType + scope + timestamp)
- actionRef field on ActionIntent, PolicyReceipt, ExecutionEnvelopeReceipt
- AttestationFreshness type: snapshot (TPM) vs rotating (SPIFFE) vs static evidence
- isEvidenceFresh/computeEvidenceAge: staleness evaluation for typed evidence
- normalizeTimestamp: ISO 8601 second-precision UTC normalization
- All fields optional — zero breaking changes

Addresses: A2A#1672 (xsa520/desiorac decision equivalence), A2A#1712 (VCOne-AI freshness semantics)
```

## File Summary

| File | Action | What |
|------|--------|------|
| `src/core/canonical.ts` | NEW | canonicalJson, canonicalHash, normalizeTimestamp |
| `src/core/action-ref.ts` | NEW | computeActionRef, actionRefsMatch |
| `src/core/freshness.ts` | NEW | evidence age/freshness evaluation |
| `src/types/policy.ts` | EDIT | add actionRef to ActionIntent, PolicyReceipt |
| `src/types/passport.ts` | EDIT | add AttestationFreshness type, freshness field |
| `src/types/execution-envelope.ts` | EDIT | add actionRef to ExecutionEnvelopeReceipt |
| `src/core/attestation.ts` | EDIT | accept freshness in importExternalAttestation |
| `src/core/execution-envelope.ts` | EDIT | propagate actionRef through envelope flow |
| `src/index.ts` | EDIT | export new types and functions |
| `tests/canonical.test.ts` | NEW | canonical JSON + hash tests |
| `tests/action-ref.test.ts` | NEW | actionRef computation + matching tests |
| `tests/freshness.test.ts` | NEW | evidence freshness evaluation tests |
