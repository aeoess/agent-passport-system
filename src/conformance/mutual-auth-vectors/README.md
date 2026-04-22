# Mutual Authentication Conformance Vectors

Reference test vectors for implementations of APS Mutual Authentication v1.

## Purpose

Any downstream implementation (Python, Go, Rust) claiming conformance to
APS Mutual Auth v1 MUST produce identical byte sequences for the canonical
forms of certificates, bundles, and handshake attests given the same
inputs. This directory provides the inputs and the expected outputs.

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
