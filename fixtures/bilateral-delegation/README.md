# Bilateral Delegation — Canonicalization Fixtures (v1)

Cross-implementation test vectors for JCS canonical JSON
([RFC 8785](https://www.rfc-editor.org/rfc/rfc8785)) as used in bilateral
delegation receipts.

The APS SDK, SINT migrationAttestation, and the in-toto Decision Receipt
predicate all sign canonical JSON. Signatures only verify across
implementations if every side produces **byte-identical canonical output**
for the same input. These fixtures let each implementation prove that
on its own, before any bilateral receipt ever gets exchanged.

## Files

| File | Purpose |
|------|---------|
| `canonicalize-fixture-v1.json` | 10 test vectors, frozen. Do not edit by hand. |
| `generate-keypair.ts` | Deterministic Ed25519 keypair derivation and fixture regeneration. |
| `test-canonicalize.ts` | Verifies a canonicalizer against the fixture. |
| `README.md` | This file. |

## Deterministic keypair

All signatures in the fixture are produced by a keypair derived as:

```
seed = SHA-256("aps-canonicalize-fixture-v1")  // 32 bytes
private key = seed (RFC 8032 Ed25519 seed)
public key  = Ed25519 derivation of seed
```

Any implementation that can do Ed25519 from a raw 32-byte seed can
reproduce the exact keypair and check signatures end-to-end.

- seed hex: `4f3d8defea1e82c1705c35d97ee4db046c6313ba83855a7d0de04a44f04c834a`
- pubkey hex: `16bd0f3e8181e93d58c23268ee0d5f4d5b70b3ce66fc246c0f5d7ec3dda9ab80`

## Vector shape

Each entry in `vectors[]`:

```json
{
  "name": "kebab-case-id",
  "description": "what this vector exercises",
  "input": { },
  "canonical_bytes_hex": "hex(utf8(canonicalize(input)))",
  "canonical_sha256": "hex(sha256(canonical_bytes))",
  "ed25519_pubkey_hex": "pubkey, same for all vectors",
  "ed25519_signature_over_canonical_hex": "Ed25519(canonical_bytes)",
  "expected_verification": true
}
```

## The 10 vectors

| Name | Tests |
|------|-------|
| `nested-null-preservation` | JCS preserves `null` at every depth. |
| `key-ordering-unicode` | Keys sort by Unicode code point, not ASCII-only. |
| `empty-containers` | `{}` and `[]` pass through unchanged. |
| `deeply-nested` | Five levels of mixed object/array nesting. |
| `string-escape-tab` | `\t` and `\n` escapes per RFC 8785 §3.2.2.2. |
| `string-escape-unicode` | Non-ASCII emit as literal UTF-8 (snowman, thumbs-up). |
| `numeric-edge-cases` | ECMA-262 number serialization; `-0` → `"0"`. |
| `array-of-objects` | Array order preserved, each element canonicalized in place. |
| `bilateral-receipt-shape` | In-toto Statement v1 wrapping AEOESS delegation receipt predicate. |
| `migration-attestation-shape` | In-toto Statement v1 wrapping SINT migrationAttestation predicate. |

## Verification (any language)

```
for each vector v in vectors:
  c = canonicalize_jcs(v.input)         // RFC 8785
  assert hex(utf8(c)) == v.canonical_bytes_hex
  assert hex(sha256(utf8(c))) == v.canonical_sha256
  assert ed25519_verify(
      pubkey   = v.ed25519_pubkey_hex,
      message  = utf8(c),
      sig      = v.ed25519_signature_over_canonical_hex,
  ) == v.expected_verification
```

## Regenerating the fixture (APS SDK maintainers only)

```
npx tsx fixtures/bilateral-delegation/generate-keypair.ts
```

This overwrites `canonicalize-fixture-v1.json`. The seed is fixed; the
keypair is fixed; changes only happen if you change the vector list
or the canonicalizer. If a regeneration produces different bytes
than the committed fixture, that's a canonicalizer change — treat as
a breaking interop event and bump the fixture version before
republishing.

## Running the verification

```
npm run test:fixtures
```

All 10 vectors must pass.

## On failure

If any check fails, **do not** modify `src/core/canonical-jcs.ts` to make
the fixture pass. Canonicalizer bugs are a separate concern that need
Tima's review — a silent change to canonical output breaks every
previously-signed receipt in the wild. Open an issue with the failure
output and the version of the SDK you're running.

## References

- RFC 8785 — JSON Canonicalization Scheme (JCS)
  https://www.rfc-editor.org/rfc/rfc8785
- in-toto/attestation#549 — Decision Receipt v0.1 predicate (arian-gogani)
  https://github.com/in-toto/attestation/pull/549
- sint-ai/sint-protocol PR #178 — migrationAttestation envelope
  https://github.com/sint-ai/sint-protocol/pull/178
- A2A#1718 — bilateral delegation coordination thread (pshkv)
  https://github.com/google/A2A/issues/1718
- APS canonicalizer: `src/core/canonical-jcs.ts`
