# Build Spec: EvaluationContext + BehavioralAttestationResult Types

## Context
Issue #9 on our repo. lowkey-divine proposed schema additions for behavioral attestation. We accepted with modifications (see comment on #9).

## What
Add two types to the SDK that separate evaluation input conditions from evaluation output results.

## Where
- `src/types/attestation.ts` (new file)
- Export from `src/index.ts`

## Types

```typescript
/** Input conditions for a behavioral evaluation. Immutable after creation. */
interface EvaluationContext {
  substrate: string                    // model/runtime identifier
  responseFormatSchema: string         // expected output format
  normalizationMethod: string          // how cross-substrate results are aligned
  evaluationProtocolVersion: string    // sha256:<hash> of methodology
  sampleSize: number                   // MANDATORY — 1 run ≠ 50 runs
  evaluatedAt: string                  // ISO 8601
}

/** Output of a behavioral evaluation. References context by hash. */
interface BehavioralAttestationResult {
  evaluationContextHash: string        // sha256 of canonical EvaluationContext
  dimensionScores: Record<string, {
    score: number
    weight: number                     // MUST reconstruct aggregate via weights
  }>
  aggregateScore: number
  classification: 'hold' | 'bend' | 'break'
  confidence: number                   // 0.0-1.0
  formatArtifactCorrected: boolean
  dimensionalInversionDetected: boolean  // MUST be derivable from dimensionScores
}
```

## Functions needed

```typescript
/** Create and hash an evaluation context */
function createEvaluationContext(opts: Omit<EvaluationContext, never>): {
  context: EvaluationContext
  hash: string  // sha256 of canonicalized context
}

/** Create a result that validates internal consistency */
function createBehavioralAttestationResult(opts: {
  context: EvaluationContext
  dimensionScores: Record<string, { score: number; weight: number }>
  classification: 'hold' | 'bend' | 'break'
  confidence: number
  formatArtifactCorrected: boolean
}): BehavioralAttestationResult
// Auto-computes: aggregateScore from weighted dimensions
// Auto-computes: dimensionalInversionDetected from dimension data
// Auto-computes: evaluationContextHash from canonical context

/** Validate internal consistency of a result */
function validateAttestationResult(result: BehavioralAttestationResult): {
  valid: boolean
  errors: string[]
}
// Checks: aggregate matches weighted dimension sum
// Checks: dimensionalInversionDetected matches actual dimension analysis
// Checks: confidence is in [0,1]
// Checks: all weights sum to ~1.0
```

## Integration with existing SDK
- `createArtifactProvenance()` should accept `BehavioralAttestationResult` as evidence metadata
- The result hash should be includable in `ActionReceipt` as attestation evidence

## Tests
- Create context, hash is deterministic
- Create result, aggregate auto-computed from weighted dimensions
- Dimensional inversion detected when dimensions disagree but aggregate matches
- Validation catches mismatched aggregate
- Validation catches self-declared inversion that contradicts dimensions
- Round-trip: create → serialize → deserialize → validate → pass

## References
- Issue #9 thread with lowkey-divine
- evoked.dev Relational Fidelity Measurement Specification v0.1.0
- Our existing `classifyEvidenceQuality()` in SDK
