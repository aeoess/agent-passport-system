# APS Composition Check Receipt v0 conformance vectors

`vectors.json` pins the behavior of the public **anchor verifier**
`CompositionCheckV0.verifyCompositionCheck`. A `CompositionCheckReceipt` is a signed
carrier an external attestor produces to record which named, opaque policy profiles it ran
over an exact `(chain_hash, action_ref, context_hash)` and the per-check results. The SDK
verifies the anchor only: signature, binding, freshness, well-formedness, and attestor
trust, and it surfaces independence. It runs no policy, computes no aggregate, and never
emits a `safe` verdict.

Detection of composition hazards is private gateway intelligence and is **not** in this
repo. This is the carrier and the anchor verifier, nothing more.

## Vectors

| id  | scenario | anchor_verified | note |
|-----|----------|-----------------|------|
| V01 | independent registered attestor | true | second anchor (strong) |
| V02 | gateway_self attestor | true | surfaced as weak, one trust domain |
| V03 | presented after `expires_at` | false | `expired` |
| V04 | wrong `chain_hash` binding | false | `chain_binding` |
| V05 | tampered signature | false | `signature` |
| V06 | result outside the fixed enum | false | `result_enum` |
| V07 | claims independent, context says operator-registered | true | downgraded, NOT a second anchor (honest floor) |
| V08 | attestor not trusted for a named profile | false | `attestor_not_trusted_for_profiles` |

`independence_is_second_anchor` is corroborated from the caller's trust context
(`registered_by_operator === false`), never from the receipt's self-declaration. A
self-declared `independent_registered` the context does not back is downgraded, never
upgraded. This mirrors RAP-v0 gating its strong claim on `domains >= 2`.

## Run

```bash
npx tsx conformance/composition-check/v0/verify.mjs     # standalone runner
npx tsx --test tests/v2/composition-check/conformance.test.ts   # in-suite
```

## Regenerate

```bash
npx tsx conformance/composition-check/v0/generate.mts
```

Keys are fresh per run; the committed `vectors.json` is the pinned artifact. Expectations
in `vectors.json` are hand-specified (not computed by the verifier), so the conformance
test is a real check rather than a tautology.
