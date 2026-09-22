# `aps:authority-revocation:v1` — deterministic vectors

Draft-03 section 3.5.1 direct revocation of an `AuthorityDelegationV1`, generated
from the merged TypeScript implementation under `src/v2/authority-revocation/`.

This family exists so a second-language port has a source of truth for the wire
format: the exact preimage bytes, the identifiers they hash to, the signature
over them, and the verification outcome the reference returns for one valid
record and nine named defects.

## Files

| file | what it is |
|---|---|
| `authority-revocation-vectors-v1.json` | the vectors |
| `generate-fixtures.ts` | deterministic generator |
| `recompute-independent.ts` | recompute of the valid case with no SDK imports |

The TypeScript reference run lives in `tests/v2/authority-revocation-vectors.test.ts`
and is wired into `npm test`.

## What the vector pins

For the valid case:

- the target `AuthorityDelegationV1`, minted with a fixed nonce and fixed
  `issued_at` / `not_before` / `not_after`
- the full `AuthorityRevocationV1` record
- the three preimages, as **hex of their UTF-8 bytes** — hex rather than text
  because each domain tag ends in one NUL byte:
  - `cascade_transaction_id_preimage_hex` — cascade tag + JCS of the record
    without `revocation_id`, `signature` and `cascade_transaction_id`
  - `revocation_id_preimage_hex` — ID tag + JCS of the record without
    `revocation_id` and `signature`
  - `signature_preimage_hex` — signature tag + JCS of the record without
    `signature`; `revocation_id` **is** inside these bytes
- the resulting `cascade_transaction_id`, `revocation_id` and `signature`, and
  the signing public key
- the three domain tags, as text and as hex

Plus the key-resolver table as data, so a consumer runs the resolver this file
was generated against rather than inventing one.

### Negative cases

Each is one named defect from the valid record, carrying the state and failure
code the merged verifier returns.

| name | outcome |
|---|---|
| `tampered-reason-code-stale-ids` | `invalid` / `CASCADE_TRANSACTION_MISMATCH` |
| `tampered-reason-code-cascade-repaired` | `invalid` / `ID_MISMATCH` |
| `tampered-reason-code-ids-repaired` | `invalid` / `SIGNATURE_INVALID` |
| `cascade-transaction-id-swapped` | `invalid` / `CASCADE_TRANSACTION_MISMATCH` |
| `revoker-not-issuer` | `invalid` / `REVOKER_NOT_ISSUER` |
| `signed-by-non-issuer-key` | `invalid` / `SIGNATURE_INVALID` |
| `revoked-at-before-key-valid-from` | `indeterminate` / `KEY_NOT_FOUND` |
| `record-type-changed` | `unsupported` / `UNSUPPORTED_RECORD_TYPE` |
| `version-changed` | `unsupported` / `UNSUPPORTED_VERSION` |

Two of these are worth reading before porting:

- A plain field tamper is caught as `CASCADE_TRANSACTION_MISMATCH`, not
  `ID_MISMATCH`. `reason_code` sits inside the cascade origin, and the verifier
  checks the cascade identity before the record identifier. The three
  `tampered-reason-code-*` cases walk the same tamper through all three layers:
  stale identifiers, cascade repaired, both identifiers repaired.
- `revoked-at-before-key-valid-from` is `indeterminate`, never `invalid`. No
  signature was checked, so saying the record is forged would be saying more than
  the verifier knows.

## SDK reference

Generated against `aeoess/agent-passport-system` at
`f6792af732f2102b239cca6b18840f6fa7d8fe87`, also recorded in the JSON under
`sdk_reference.commit`. That SHA pins the **implementation** the outcomes came
from; the vector files themselves land on a later commit.

## Determinism

Nothing in the generator reads a clock or a random source:

- Ed25519 seeds are `sha256(utf8("agent-passport-system:authority-revocation-vector:<label>"))`.
  The 32 bytes are the seed, so anybody can re-derive the keys from the label
  alone. They are test keys in a public repository and control nothing.
- `now`, `nonce`, `reason_code`, `detail`, every delegation time, and the
  resolver table are constants in the generator.
- Ed25519 signing is deterministic (RFC 8032).

Regenerate:

```
npx tsx fixtures/authority-revocation/generate-fixtures.ts
# or: npm run fixtures:authority-revocation
```

Two runs produce a byte-identical file; `git diff` after a regeneration is the
check. The generator also re-runs the merged verifier over every case and refuses
to write the file if an outcome no longer matches the one that case declares, so
a behaviour change surfaces at generation rather than being silently
re-baselined.

## Independent recompute

```
npx tsx fixtures/authority-revocation/recompute-independent.ts
# or: npm run fixtures:authority-revocation:recompute
```

`recompute-independent.ts` imports nothing from `src/`. Its only imports are
`node:crypto` and `node:fs`. It re-states RFC 8785 JCS for the string-only
objects this record is made of, re-types the three domain tags as literals and
checks them against the hex the vector publishes, and uses the platform's SHA-256
and Ed25519. From the vector file alone it rebuilds both identifier preimages and
the signature preimage, compares all three byte for byte, recomputes both
identifiers, and verifies the signature.

Nothing in the valid case had to be skipped for want of the SDK. One scope
difference is deliberate: `src/crypto/keys.ts` additionally refuses small-order
Ed25519 key material before calling the platform primitive, and the recompute
does not reimplement that. It is a property of the SDK's verifier, not of these
bytes.

## Not covered

- **0B derived records.** This family is one direct revocation of one delegation.
  Nothing a cascade would produce for descendants is here.
- **0C cascade completion.** Section 3.5.1 makes completion depend on the last
  descendant's revocation being persistent, and no store interface in this
  repository establishes persistence.
- Store behaviour (first-wins insertion), the resolver built over a store, and
  chain-level enforcement of a revoked ancestor. Those are exercised in
  `tests/v2/authority-revocation.test.ts` and are not pinned as vectors.
- JCS escaping of non-ASCII and control characters. Every string here is
  printable ASCII on purpose; escaping is pinned by
  `tests/cross-impl/jcs-test-vectors.json`.
