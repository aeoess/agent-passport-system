# Build Spec: Interop Test Suite

## Context
We have interop artifacts scattered across the repo: IETF envelope receipts, Signet interop spec, MolTrust attestation, cross-protocol test vectors. This spec consolidates them into a single runnable interop test suite.

## What
A unified `npm run test:interop` command that validates all cross-system receipt compatibility in one run.

## Where
- `tests/interop/` directory (new, consolidates existing interop tests)
- `tests/interop/ietf-envelope.test.ts` — verify APS receipts in IETF draft format
- `tests/interop/signet-combined.test.ts` — verify combined Signet+APS credentials
- `tests/interop/moltrust-attestation.test.ts` — verify MolTrust governance attestation signals
- `tests/interop/cross-protocol-vectors.test.ts` — existing test vectors round-trip
- `tests/interop/receipt-chaining.test.ts` — verify linear + DAG chaining compat

## New npm script

Add to package.json:
```json
"test:interop": "npx tsx --test tests/interop/*.test.ts"
```

## Tests per file

### ietf-envelope.test.ts
- Load 3 receipts from `examples/interop/ietf-envelope/`
- Verify each has required IETF fields (spec, receipt_id, issued_at, issuer_id, payload, signature)
- Verify receipt_id is content-addressed (sha256 of canonical payload)
- Verify Ed25519 signature over canonical payload
- Verify chain integrity (previousReceiptHash links correctly)
- Verify APS extensions present inside payload.extensions.aps

### signet-combined.test.ts
- Load test vectors from `specs/test-vectors/signet/`
- Verify combined envelope has both signet_link and aps_delegation
- Verify aps_delegation_hash matches canonical hash of the delegation
- Verify Ed25519 signature on embedded delegation
- Test revocation scenario: revoked link → delegation unreachable

### moltrust-attestation.test.ts
- Create a governance_attestation signal using SDK functions
- Verify JWS structure (header.alg = EdDSA, header.kid present)
- Verify payload has required fields (signal_type, iss, delegation_chain_hash, evaluation_timestamp, expires_at, active_constraints)
- Verify signature against test JWKS

### cross-protocol-vectors.test.ts
- Load existing vectors from `specs/cross-protocol-test-vectors.json` and `specs/cross-protocol-test-vectors-v2.json`
- Round-trip: serialize → deserialize → verify signature → compare fields
- Cross-language: verify TypeScript output matches expected canonical form

### receipt-chaining.test.ts
- Linear chain: 3 receipts with previousReceiptHash
- Verify chain integrity (each hash matches previous receipt's content hash)
- Verify tampering detection (modify middle receipt → chain breaks)

## After building
- All interop tests should pass
- Add `test:interop` to package.json
- Commit with message referencing ecosystem interop
