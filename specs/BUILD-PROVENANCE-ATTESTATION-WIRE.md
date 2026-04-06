# Build Spec: Wire BehavioralAttestationResult into createArtifactProvenance

## Context
APS Issue #9 comment. We committed: "The `createArtifactProvenance` function will accept a `BehavioralAttestationResult` as evidence metadata, signed alongside the provenance record."

CC already built the EvaluationContext + BehavioralAttestationResult types. This spec wires them into the existing provenance system.

## What
Modify `createArtifactProvenance()` to optionally accept a `BehavioralAttestationResult` as evidence metadata. The result hash gets included in the provenance record, making behavioral evaluation results cryptographically linked to artifact provenance.

## Where
- `src/core/provenance.ts` (modify existing)
- `tests/evaluation-context.test.ts` (add integration test)

## How

1. Find `createArtifactProvenance` in `src/core/provenance.ts`
2. Add optional parameter: `behavioralAttestation?: BehavioralAttestationResult`
3. When provided:
   - Validate it via `validateAttestationResult()`
   - Include `evaluationContextHash` in the provenance record's `evidence` field
   - Include `aggregateScore` and `classification` in provenance metadata
4. The provenance signature covers the attestation data (tamper-evident)

## Expected interface change

```typescript
// Before:
createArtifactProvenance(opts: {
  artifactHash: string
  agentId: string
  // ... existing fields
}): ArtifactProvenance

// After:
createArtifactProvenance(opts: {
  artifactHash: string
  agentId: string
  // ... existing fields
  behavioralAttestation?: BehavioralAttestationResult  // NEW
}): ArtifactProvenance
```

When `behavioralAttestation` is provided, the provenance record's metadata should include:

```json
{
  "behavioralEvidence": {
    "evaluationContextHash": "sha256:...",
    "aggregateScore": 0.85,
    "classification": "hold",
    "confidence": 0.92
  }
}
```

## Tests needed
- createArtifactProvenance without attestation still works (backward compat)
- createArtifactProvenance with valid attestation includes evidence in metadata
- createArtifactProvenance with invalid attestation (mismatched aggregate) throws
- Round-trip: create provenance with attestation → verify provenance → attestation evidence present

## After building
- Commit referencing Issue #9
- Post comment on APS Issue #9 confirming the wire-up is complete
