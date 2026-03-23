# APS Canonical JSON Serialization — Conformance Specification

## Version: 1.0.0 (frozen)
## Status: FROZEN — changes require major version bump + signature migration

This document defines the canonical JSON serialization used by the Agent Passport
System for all cryptographic operations (signing, verification, content hashing).

## Algorithm

1. Input is a JavaScript/TypeScript value
2. `null` and `undefined` → JSON string `"null"`
3. `Date` objects → JSON string representation (ISO 8601 via `JSON.stringify`)
4. Primitives (string, number, boolean) → `JSON.stringify(value)`
5. Arrays → `[element0,element1,...]` (recursive, preserves null elements as `"null"`)
6. Objects → sorted keys alphabetically, null/undefined VALUES OMITTED
   - `{a: 1, b: null}` canonicalizes as `{"a":1}` (b omitted)
   - `{a: 1, b: null, c: [null, 2]}` → `{"a":1,"c":[null,2]}`
7. No trailing commas, no whitespace between tokens

## Null Asymmetry Rule (documented, intentional)

- Object keys with null/undefined values: **OMITTED**
- Array elements with null/undefined: **PRESERVED as `null`**

This means `{a: 1, b: null}` and `{a: 1}` produce IDENTICAL canonical forms.
This is a known design choice. Implementers MUST NOT rely on null-valued
object keys for signature-relevant semantics.

## Forbidden Values

The following values MUST NOT appear in any signed object:

- `NaN` — not representable in JSON, serialization is implementation-defined
- `Infinity` / `-Infinity` — not representable in JSON
- `undefined` as a standalone value in arrays — use `null` instead
- Numeric values outside IEEE 754 double precision safe integer range
  (beyond ±2^53 - 1) — serialization varies across platforms
- Strings containing unpaired Unicode surrogates (U+D800–U+DFFF)

Implementations MUST reject these values before signing. Verification
implementations MUST reject signatures over objects containing these values.

## Conformance Test Vectors

Implementers MUST produce identical output for all vectors below.

```
Input: null
Output: "null"

Input: undefined
Output: "null"

Input: true
Output: "true"

Input: 42
Output: "42"

Input: "hello"
Output: "\"hello\""

Input: [1, null, 3]
Output: "[1,null,3]"

Input: {a: 1, b: null}
Output: "{\"a\":1}"

Input: {b: 2, a: 1}
Output: "{\"a\":1,\"b\":2}"

Input: {a: 1, b: null, c: [null, 2]}
Output: "{\"a\":1,\"c\":[null,2]}"

Input: {z: {b: 2, a: 1}, a: 0}
Output: "{\"a\":0,\"z\":{\"a\":1,\"b\":2}}"

Input: []
Output: "[]"

Input: {}
Output: "{}"

Input: ""
Output: "\"\""

Input: 0
Output: "0"

Input: -1
Output: "-1"

Input: {a: 1, b: undefined, c: 3}
Output: "{\"a\":1,\"c\":3}"
```

## Cross-Language Compatibility

Three implementations are verified compatible as of v1.19.2:
- TypeScript: `src/core/canonical.ts`
- Python: `docs/canonical.py` + `agent-passport-python`
- noble-curves runner: qntm interop vectors

All implementations MUST pass the conformance vectors above.
New implementations SHOULD run the full vector suite before
claiming APS signature compatibility.

## Versioning

This canonicalization scheme is version 1.0.0. Any change to the
algorithm requires a major version bump and a signature migration
plan. The scheme is FROZEN — do not modify without committee approval.
