# Mutual Authentication Conformance Vectors

Reference test vectors for implementations of APS Mutual Authentication v1.

## Purpose

These vectors pin the canonical byte sequences for certificates, trust anchor
bundles, and handshake attests. An implementation that produces the same bytes
for the same inputs will interoperate; this directory provides the inputs and
the expected outputs so that can be checked.

No cross-language comparison is executed against THESE vectors. Nothing in
this repository runs a Python, Go, or Rust implementation over them, so they are
a published reference rather than an enforced multi-language gate. A separate
cross-implementation check does exist for the canonicalizer itself, at
.github/workflows/cross-impl-jcs.yml; it does not cover mutual authentication.

The canonical form is stated in terms of JSON, not in terms of any one
language's absent-value convention. Three certificate and bundle members are
present as JSON `null` when the caller supplies no value:

- `attestation_grade`
- `capabilities`
- `revoked_anchors`

They are members carrying the JSON value null, not omitted members. An
implementation reproducing these bytes constructs that null explicitly. This
matters because the reference implementation is TypeScript, where a member left
unset used to reach the canonicalizer as the JavaScript value `undefined` and be
coerced; as of #101 the canonicalizer rejects `undefined` and the builders write
the null themselves, so the canonical form no longer depends on a coercion that
only one language has.

## Vector shape

Each `.json` file contains a single vector:

```jsonc
{
  "name": "descriptive-slug",
  "spec_section": "3.1",         // which RFC-style section this covers
  "input": { ... },              // inputs to the primitive under test
  "primitive": "buildCertificate" | "signCertificate" | "buildAttest" | ...,
  "expected": {
    "canonical_bytes_b64": "...", // RFC 8785 JCS output
    "canonical_sha256": "sha256:..." // stable fingerprint
  }
}
```

## Verification

An implementation passes a vector iff:

1. Running its `primitive` on `input` yields output whose canonical JCS
   encoding matches `canonical_bytes_b64` exactly.
2. SHA-256 of that canonical encoding matches `canonical_sha256`.

Signatures are NOT part of conformance because Ed25519 signing is
deterministic per-key but the vectors do not embed private keys. The
signed variants test determinism of the unsigned canonical form only.

## Coverage

The vectors in this directory target:

- `vec01-certificate-canonical.json` — minimum-field certificate
- `vec02-certificate-all-fields.json` — all optional fields populated
- `vec03-bundle-canonical.json` — trust anchor bundle
- `vec04-attest-canonical.json` — handshake attest (unsigned canonical)
- `vec05-session-derivation.json` — derived session_id from two attests

Generator: `scripts/build-mutual-auth-vectors.ts`.

## Non-goals

These vectors do not cover end-to-end signature interop (each language
has its own Ed25519 library and may produce equivalent but not
byte-identical signatures depending on libSodium vs noble vs others;
all are valid). They cover only the canonicalization, field ordering,
and content-hash computation.
