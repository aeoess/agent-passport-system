# Rotation-Attestation Specification v1

**Status:** v1, stable. Canonical bytes served at `https://aeoess.com/fixtures/rotation-attestation/`.
**Published:** 2026-04-24
**Scope:** wire-format for the continuity-layer claim in the four-layer agent-identity split (identity / transport / authority / continuity) established on a2aproject/A2A#1672.

## Purpose

A DID-bound agent can rotate its signing key. A rotation chain that carries only "old key signed something that names the new key" is not sufficient continuity evidence for a verifier that wasn't online during the rotation. This spec defines the wire-format claim a verifier needs to accept a rotated identity as continuous, and the fixture set other implementations can pin bytes against.

## Claim types in this spec

- **rotation attestation** (required): old key signs canonical `{previousKey, newKey, mode, activationTime}` via Ed25519. This is the `rotationSignature` field on each entry in `rotationLog`.
- **cross-signature** (optional): new key also signs the same canonical rotation payload. Indicates mutual attestation; both keys testify to the transition.
- **migration attestation** (optional): a third-party attestor signs canonical `{previousKey, newKey, migrationType, fromClass, toClass, migratedAt}`. Used for key-class upgrades (v1) and key-class migrations (v2+).

## Canonicalization rule

**Every signature input and every hash input in this spec is RFC 8785 JCS-canonicalized before signing or hashing.**

This applies without exception to:
- The rotation payload signed by `rotationSignature` (`{previousKey, newKey, mode, activationTime}`)
- The same rotation payload signed by `crossSignature` when present
- The migration payload signed by `migrationAttestation.attestorSignature` (`{previousKey, newKey, migrationType, fromClass, toClass, migratedAt}`)
- The `canonicalSha256` entries in `test-vectors.json` (SHA-256 of JCS of the full fixture document)

Consumers pinning bytes must canonicalize before hashing. A verifier that hashes the raw file bytes instead of the JCS output will get a different SHA-256 and fail to pin correctly.

## Fixture set v1

Five fixtures published at `https://aeoess.com/fixtures/rotation-attestation/`:

| Fixture | Shape | Expected |
|---|---|---|
| `happy-path.json` | Baseline: `rotationSignature` only | pass |
| `cross-signed.json` | `rotationSignature` + `crossSignature` | pass |
| `migration-attested.json` | `rotationSignature` + `migrationAttestation` | pass |
| `happy-path-compound.json` | All three attestation types in one entry | pass |
| `negative-no-attestation.json` | `rotationSignature: ""` | fail-closed, `INVALID_CLAIM_SCOPE` |

The compound fixture is the most realistic production shape: key-class upgrade where both old and new key sign, and a third-party attestor (gateway, HSM, or similar) witnesses the migration.

## Verifier rule for the continuity layer

At the continuity layer, a verifier MUST:

1. Fetch the `rotationLog` array from the DID document.
2. For each entry, reconstruct the canonical rotation payload as `JCS({previousKey, newKey, mode, activationTime})`.
3. Verify `rotationSignature` against `previousKey` over that payload. If signature is empty or invalid, return `INVALID_CLAIM_SCOPE` and stop evaluating higher layers.
4. If `crossSignature` is present, verify it against `newKey` over the same payload. A bad cross-signature when present is `INVALID_CLAIM_SCOPE` (not just a warning).
5. If `migrationAttestation` is present, reconstruct the canonical migration payload as `JCS({previousKey, newKey, migrationType, fromClass, toClass, migratedAt})` and verify `attestorSignature` against `attestorKey`. A bad migration attestation when present is `INVALID_CLAIM_SCOPE`.

Continuity passes only when every present claim verifies. Missing optional claims (no `crossSignature`, no `migrationAttestation`) do not fail the layer; what fails the layer is a present-but-invalid claim, or an empty/missing required `rotationSignature`.

## Scope boundary: v1 vs v2

**v1 covers:**
- `migrationType` enum: `{key_class_upgrade}`
- `fromClass` / `toClass` enum: `{self_asserted, infrastructure_attested, provider_attested, hardware_attested}`
- Single-hop rotation per document (one entry in `rotationLog`)

**v2 will extend:**
- `migrationType` adds `did_method_migration` (e.g., `did:web` → `did:aps`) and `pq_migration` (Ed25519 → ML-DSA-65)
- Multi-hop rotation chains (A → B → C → D) with cross-entry continuity rules
- Revoked-mid-rotation composition

A v1 verifier MUST reject any `migrationType` value outside `{key_class_upgrade}` with `INVALID_CLAIM_SCOPE`. A v2 verifier reading v1 fixtures is backward-compatible.

## Attestor key material

Fixture-signing attestor:
- **kid:** `aeoess-fixture-attestor-v1`
- **Public key:** published at `https://aeoess.com/fixtures/rotation-attestation/keys/attestor-v1.pub.json`
- **Stability:** this key will never be rotated. v2 introduces a separate `attestor-v2` key without invalidating v1 fixtures.

The attestor key is dedicated to fixture signing and has no other role. It is not a gateway key, not a production issuer key, not usable for live delegations. Its private seed is documented in the generation script at `scripts/generate-rotation-attestation-fixtures.ts` so any third party can reproduce the fixtures byte-for-byte.

## Reproducibility

The generation script uses fixed Ed25519 seeds and fixed ISO timestamps. Re-running `npx tsx scripts/generate-rotation-attestation-fixtures.ts` from a fresh clone produces byte-identical output. Consumers pinning `canonicalSha256` values in `test-vectors.json` get a stable reference that survives clean rebuilds.

## Reference implementations

This spec uses APS core primitives:
- `src/crypto/keys.ts` - Ed25519 sign/verify
- `src/core/canonical.ts` - RFC 8785 JCS canonicalization
- `src/core/did.ts` - `did:aps` construction
- `src/core/key-rotation.ts` - `announceKeyRotation`, `activateKeyRotation`, `verifyRotationChain`
- `src/types/passport.ts` - `RotatableDIDDocument`, `DIDRotationEntry`

The two optional fields (`crossSignature`, `migrationAttestation`) are fixture-level extensions to `DIDRotationEntry` that do not break backward compatibility with SDK consumers who only use the core `rotationSignature` field.

## Citation

CTEF v0.3.1 §6.3 references the continuity-layer claim. A2A Agent Cards spec extension will cite this fixture set as the canonical continuity-layer reference. BBIS v1 maps continuity-layer invariants to the same claim structure.

Related threads:
- a2aproject/A2A#1672 (four-layer split convergence)
- OWASP/www-project-top-10-for-large-language-model-applications#817 (BBIS continuity claims)
- aeoess/agent-governance-vocabulary#36 (interop fixture structure)
