# Build Plan: Evidence-Based Grade Assignment

## Intent

VCOne-AI identified a real flaw on A2A#1712: our grade assignment in `importExternalAttestation()` maps by identity method prefix, not by evidence quality. A TPM-backed `did:key` with hardware attestation gets Grade 0 because it's `did:key`, while a SPIFFE SVID from a misconfigured cluster gets Grade 2 because it's SPIFFE. That's backwards.

We committed to the fix in the thread. Now build it.

**Rule: We do not claim what we haven't built. VCOne-AI and 64R3N are watching this thread.**

## What Exists

The current grade assignment logic lives somewhere in `src/core/attestation.ts` (or nearby). It maps grades roughly by method:
- `did:key` → Grade 0
- Issuer countersigned → Grade 1  
- SPIFFE → Grade 2
- Principal endorsement → Grade 3

The `importProviderAttestation()` function accepts an `evidence` field and a `freshness` field (just added in the previous build). But the grade number is assigned based on the method/provider type, NOT based on what the evidence actually proves.

## What To Build

Refactor grade assignment so it factors in evidence quality:

- **Grade 0:** Bare keypair, no evidence of how it was generated or stored
- **Grade 1:** Issuer countersigned (any third party vouched for the key)
- **Grade 2:** Infrastructure-attested (evidence that the key is bound to a specific runtime). This includes BOTH:
  - SPIFFE SVID with verified workload identity
  - TPM-backed did:key with hardware attestation evidence
  - Any method where `evidence` field proves hardware/infrastructure binding
- **Grade 3:** Principal-bound (verified human or legal entity linked to the key)

The key change: **a did:key with TPM attestation evidence reaches Grade 2, same as SPIFFE.** The differentiator is the evidence attached, not the DID method prefix.

## Pre-Build Checklist

### Step 0: Verify machine and pull latest
```bash
whoami && hostname
cd /Users/tima/agent-passport-system
git stash && git pull --rebase && git stash pop
```
### Step 1: Read current state — understand what exists
Read these files BEFORE writing any code:

```
src/core/attestation.ts           — importProviderAttestation, grade assignment logic
src/types/attestation.ts          — RuntimeAttestation, ProviderAttestation, PassportAttestationSummary
src/types/passport.ts             — AttestationFreshness (just added), grade-related types
src/core/passport.ts              — passport creation, any grade computation
src/index.ts                      — current exports
```

Search for existing grade logic:
```bash
grep -rn "grade\|Grade\|GRADE" src/ --include="*.ts" | grep -v node_modules | grep -v dist
grep -rn "assignGrade\|computeGrade\|passportGrade\|attestationGrade" src/ --include="*.ts"
grep -rn "importProvider\|importExternal\|importRuntime" src/ --include="*.ts"
```

### Step 2: Understand the current grade assignment flow
Map exactly WHERE grade numbers are assigned and WHAT inputs determine them. The fix must change the decision logic, not invent a new flow.

### Step 3: Check test patterns
```bash
grep -rn "grade\|Grade" tests/ --include="*.ts" -l
```
Understand which tests exercise grade assignment so you don't break them.

## Build Order

### Phase 1: Add evidence classification types

Add to the appropriate types file (likely `src/types/attestation.ts`):

```typescript
/** Evidence quality level — determines grade independent of identity method */
export type EvidenceQuality = 
  | 'none'              // bare keypair, no proof of generation/storage
  | 'issuer_vouched'    // third party signed the key (countersignature)
  | 'infrastructure'    // evidence of hardware/runtime binding (TPM, SPIFFE, TEE)
  | 'principal_bound'   // verified human or legal entity linked to key

/** Map evidence quality to passport grade */
export function evidenceQualityToGrade(quality: EvidenceQuality): number {
  switch (quality) {
    case 'none': return 0
    case 'issuer_vouched': return 1
    case 'infrastructure': return 2
    case 'principal_bound': return 3
  }
}
```
### Phase 2: Add evidence classification function

```typescript
/** Classify evidence quality from attestation metadata.
 *  This is where did:key + TPM evidence gets elevated to Grade 2. */
export function classifyEvidenceQuality(opts: {
  method?: string           // "did:key", "spiffe", "oauth", etc.
  hasIssuerSignature?: boolean
  hasPrincipalBinding?: boolean
  evidence?: Record<string, unknown>  // raw evidence payload
}): EvidenceQuality {
  // Principal binding takes precedence
  if (opts.hasPrincipalBinding) return 'principal_bound'
  
  // Infrastructure evidence: SPIFFE, TPM attestation, TEE proof
  if (opts.method === 'spiffe') return 'infrastructure'
  if (opts.evidence?.tpm_quote) return 'infrastructure'
  if (opts.evidence?.hardware_attestation) return 'infrastructure'
  if (opts.evidence?.tee_proof) return 'infrastructure'
  if (opts.evidence?.infrastructure_binding) return 'infrastructure'
  
  // Issuer vouched
  if (opts.hasIssuerSignature) return 'issuer_vouched'
  
  // Default: bare keypair
  return 'none'
}
```

**CRITICAL:** The evidence field keys (`tpm_quote`, `hardware_attestation`, `tee_proof`, `infrastructure_binding`) must be checked loosely — external attestations come in many shapes. The classifier should check for the presence of any key that indicates hardware/infrastructure binding.

### Phase 3: Refactor existing grade assignment

Find wherever the current grade is assigned (likely in `importProviderAttestation` or a helper function) and replace the method-based mapping with:

```typescript
const quality = classifyEvidenceQuality({
  method: attestation.method || provider,
  hasIssuerSignature: !!attestation.signature,
  hasPrincipalBinding: !!attestation.principalId,
  evidence: attestation.evidence || {}
})
const grade = evidenceQualityToGrade(quality)
```

**DO NOT** remove the old grade paths entirely — keep them as fallback for backward compatibility. The new classification should be additive: if evidence is present, use it; if not, fall back to method-based grading.

### Phase 4: Export new functions

Add to `src/index.ts`:
```typescript
export { classifyEvidenceQuality, evidenceQualityToGrade } from './core/attestation.js'
// or wherever they end up
export type { EvidenceQuality } from './types/attestation.js'
```

### Phase 5: Tests

Create `tests/evidence-grade.test.ts`:

1. **did:key with no evidence → Grade 0**
2. **did:key with TPM quote evidence → Grade 2** (this is the key fix)
3. **did:key with issuer countersignature → Grade 1**
4. **SPIFFE with no special evidence → Grade 2** (preserves existing behavior)
5. **Any method with principal binding → Grade 3**
6. **did:key with hardware_attestation evidence → Grade 2**
7. **Unknown method with infrastructure_binding evidence → Grade 2**
8. **Backward compat: existing grade paths still work when no evidence present**

Register new test file in `package.json` test script.
## Post-Build Verification

### Step 1: TypeScript strict compilation
```bash
npx tsc --noEmit
```
Must exit 0 with zero errors.

### Step 2: Run full test suite
```bash
npm test
```
All 2,215+ existing tests must still pass. Zero regressions.

### Step 3: Run new tests specifically
```bash
npm test -- --grep "evidence.*grade\|Grade.*evidence\|classifyEvidence\|evidenceQuality"
```

### Step 4: Check exports
```bash
node -e "const aps = require('./dist/index.js'); console.log(typeof aps.classifyEvidenceQuality, typeof aps.evidenceQualityToGrade)"
```
Should print: `function function`

### Step 5: Cross-reference thread claims
Verify these specific claims from A2A#1712 are now concrete:

1. Grade 0 = bare keypair, no evidence → classifyEvidenceQuality returns 'none'
2. Grade 1 = issuer countersigned → classifyEvidenceQuality returns 'issuer_vouched'
3. Grade 2 = infrastructure-attested (TPM OR SPIFFE) → classifyEvidenceQuality returns 'infrastructure' for BOTH
4. Grade 3 = principal-bound → classifyEvidenceQuality returns 'principal_bound'
5. A TPM-backed did:key with hardware attestation evidence reaches Grade 2

### Step 6: Build dist
```bash
npm run build
```
Must exit 0.

## DO NOT DO

- Do NOT bump version number — Tima handles versioning
- Do NOT run `npm publish` — requires Touch ID
- Do NOT modify gateway code — this is SDK only
- Do NOT break existing attestation flows — evidence-based grading is additive
- Do NOT remove method-based grade fallback — keep it for backward compat when no evidence is present
- Do NOT commit or push — leave for Tima to review the diff first

## Commit Message (when Tima approves)

```
feat: evidence-based passport grade assignment

- classifyEvidenceQuality: grades by evidence quality, not identity method
- evidenceQualityToGrade: maps evidence quality to passport grade number
- TPM-backed did:key with hardware attestation now reaches Grade 2
- SPIFFE behavior preserved (still Grade 2, now via evidence classification)
- Method-based grading preserved as fallback when no evidence is present
- All new fields/functions additive — zero breaking changes

Addresses: A2A#1712 (VCOne-AI evidence-based regrade critique)
```

## File Summary

| File | Action | What |
|------|--------|------|
| `src/types/attestation.ts` | EDIT | Add EvidenceQuality type |
| `src/core/attestation.ts` | EDIT | Add classifyEvidenceQuality, evidenceQualityToGrade, refactor grade assignment |
| `src/index.ts` | EDIT | Export new types and functions |
| `tests/evidence-grade.test.ts` | NEW | Evidence-based grade classification tests |
| `package.json` | EDIT | Register new test file |