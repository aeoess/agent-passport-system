Status: DRAFT. Not for publication until review and sign-off.

# read_fidelity_receipt v0.1

## Status

- Version: v0.1 draft
- Date: 2026-07-04
- Stability: draft. The field set, seed derivation, sampling algorithm, and
  scoring method below are frozen only after review and sign-off. Do not build
  external integrations against this document while the DRAFT marker stands.

This document specifies the `read_fidelity_receipt` record (TypeScript type
`ReadFidelityReceipt`): a signed record of a sampled readback challenge over
perceived content. It is a fidelity primitive, not an authorization or
execution primitive: this record family is about read fidelity of perceived
content, a different question from whether an action or verification
pipeline executed correctly.

## Motivation

Agents increasingly consume content through lossy perceptual channels:
screenshots, rendered pages, OCR passes, vision encoders. The invariant this
record family exists to serve is:

"Nothing perceived through a lossy channel is authoritative."

A digest that was merely seen cannot be trusted to have been seen correctly.
As reported in the pxpipe README and its legibility audit, word handles were
read back correctly in 13 of 15 trials while raw hex digests were read back
correctly in 0 of 15, with glyph confusability the dominant failure mode.
These numbers were verified 2026-07-04 against the pxpipe README and
LEGIBILITY-AUDIT by the maintainer. The assumed word-confusion rate q used
elsewhere in this record family is taken from these findings, q about 2/15
per handle readback.

A `read_fidelity_receipt` turns "the agent read the content" from an
unfalsifiable assertion into a scored, replay-bound, signed claim: the
verifier learns that whoever produced the responses could reproduce k of n
randomly sampled spans of the source text, under a challenge that cannot be
precomputed or replayed.

## Definition

A `read_fidelity_receipt` is a signed record binding together:

1. the canonical content (by digest),
2. the rendered presentation as served (by digest, or null),
3. a verifier-supplied single-use nonce,
4. a deterministic span-sampling challenge derived from all of the above,
5. commitments to the sampled span texts,
6. a digest of the ordered readback responses and the resulting score k of n,
7. an Ed25519 signature by the attester key.

The mandatory statement of what the record means, carried verbatim as the
doc comment on the record type in both SDKs:

"A read fidelity receipt proves sampled readback fidelity at the stated n
under the declared sampling assumptions. It does not prove every byte was
read correctly, does not prove perception or comprehension, does not prove
which channel was used, and carries no normative pass threshold: the
consumer judges k of n."

## Record shape

Every digest-valued field uses the format `sha256:<64 lowercase hex>`.
Canonicalization is the JSON Canonicalization Scheme, RFC 8785, strict form
(keys sorted by code point, no whitespace, ES2015 string escaping); JCS key
sorting determines the serialized field order.

```json
{
  "type": "read_fidelity_receipt",
  "content_digest": "sha256:<hex of the canonical content bytes>",
  "presentation_digest": "sha256:<hex of the rendered presentation as served>",
  "challenge": {
    "nonce": "<verifier-supplied string>",
    "seed": "<hex, MUST equal the derivation in the next section>",
    "algorithm": "span_sample_v1",
    "version": "1",
    "span_len": 12,
    "span_commitments": ["sha256:<hex>", "..."]
  },
  "response_digest": "sha256:<hex>",
  "k": 5,
  "n": 6,
  "scoring_method": "exact_match_v1",
  "attester": "<ed25519 public key hex>",
  "model_claim": "<string>",
  "runtime_claim": "<string>",
  "verification_method": "asserted",
  "challenge_issued_at": "2026-07-04T00:00:00Z",
  "response_observed_at": "2026-07-04T00:00:00Z",
  "receipt_issued_at": "2026-07-04T00:00:00Z",
  "lexicon_id": "sha256:<hex, OPTIONAL>",
  "lexicon_profile": "single-list-v1",
  "sig": "<128 hex>"
}
```

Field rules:

- `type`: the fixed string `read_fidelity_receipt`.
- `content_digest`: digest of the canonical content bytes.
- `presentation_digest`: digest of the rendered presentation as served, or
  `null` when no distinct presentation exists. The null is recorded, not
  omitted.
- `challenge.nonce`: verifier-supplied, single use, and never derivable from
  the document alone. A challenger that lets the responder pick the nonce
  has no replay protection.
- `challenge.seed`: MUST equal the derivation below. Verifiers recompute it
  and reject on mismatch.
- `challenge.algorithm`: `span_sample_v1`. `challenge.version`: `"1"`.
- `challenge.span_len`: integer span length in code points, recorded because
  it is required to recompute the spans.
- `challenge.span_commitments`: sha256 of the UTF-8 bytes of each sampled
  span text, in sampling order. The raw span texts are NOT in the record.
- `response_digest`: `"sha256:" + sha256hex(JCS(responses))` where
  `responses` is the ordered array of readback strings.
- `k`, `n`: integers. `n` MUST equal `span_commitments.length`. `k` is the
  count of exact matches under `scoring_method`.
- `scoring_method`: `exact_match_v1` (exact string equality per span).
- `attester`: Ed25519 public key hex of the SIGNING identity. See "Signer
  and executor" below.
- `model_claim`, `runtime_claim`: free-text claims about the executing model
  and runtime. They are claims, not proofs.
- `verification_method`: `"asserted"` or `"provider_attestation"`.
- `challenge_issued_at`, `response_observed_at`, `receipt_issued_at`:
  ISO 8601 timestamps, all caller-provided. The library performs no
  wall-clock reads; the timestamps are attester claims, not proofs of
  timing.
- `lexicon_id`, `lexicon_profile`: OPTIONAL, present when word_digest_handles
  appear in the flow (see docs/word-handles-spec.md). `lexicon_profile` is
  `single-list-v1` and appears alongside `lexicon_id`.
- `sig`: 128 hex characters, Ed25519 over the JCS canonicalization of the
  record with `sig` excluded entirely.

## Seed derivation and replay binding

The challenge seed is derived, exactly:

```
seed = sha256hex( utf8( canonicalizeJCS({
         content_digest,
         presentation_digest,   // null when absent
         nonce,
         version
       }) ) )
```

The preimage is the RFC 8785 JCS canonicalization of an object carrying the
four bound fields (keys sorted: `content_digest`, `nonce`,
`presentation_digest`, `version`). Each field is a distinct JSON member, so
`presentation_digest` is `null` when absent and can never be folded into an
adjacent field. An earlier concatenation preimage let a null-presentation
record with `nonce = P || N` derive the same seed as a `P`-presentation
record with nonce `N`, so a verifier that pinned only the seed could not tell
the two apart; the structured preimage closes that at the source, and the
regression is pinned by a cross-language test in both SDKs.

This binds the challenge to the exact content, the exact presentation, the
verifier's nonce, and the protocol version:

- A record replayed under a different nonce fails verification because
  `challenge.seed` no longer matches the derivation, even though the
  signature over the replayed record may verify.
- A record whose `presentation_digest` is swapped after the fact fails the
  same derivation check.
- Because the nonce is verifier-supplied and single use, responses cannot be
  precomputed from the document alone, and a receipt cannot be reused across
  challenges.

## Challenge protocol

1. The verifier issues a fresh nonce (single use per nonce).
2. `content_digest` is computed over the canonical content bytes;
   `presentation_digest` over the rendered presentation as served, or null.
3. Both sides derive `seed` per the formula above.
4. Spans are sampled deterministically from the source text (algorithm
   below) using `seed`, `n`, and `span_len`; positions are reproducible by
   any party holding the source.
5. `span_commitments` are computed over the sampled span texts in sampling
   order.
6. The responding side produces the ordered readback strings for the sampled
   spans from the content as it perceived it.
7. Responses are scored with `exact_match_v1`, giving `k`;
   `response_digest` commits to the ordered response array.
8. The record is assembled with caller-provided timestamps and signed by the
   attester key.

## Span sampling (span_sample_v1)

The source text is treated as a sequence of Unicode code points.

- `L` = code point count. Requires `L >= span_len`.
- `range = L - span_len + 1`. Requires `1 <= n <= range`.
- For each `i` in `0..n-1`: starting at `j = 0`, compute
  `h = sha256(utf8(seed + ":" + i + ":" + j))`, take the first 8 bytes of
  `h` as a big-endian unsigned 64-bit integer, and set
  `pos = that integer mod range`. If `pos` was already selected for an
  earlier span, increment `j` and recompute until a fresh position appears.
- Span `i` is the code points `[pos, pos + span_len)`, joined.

Positions are distinct within one challenge. The construction is
deterministic: the same `(sourceText, seed, n, span_len)` yields bit-exact
identical spans in every conforming implementation.

## Scoring (exact_match_v1)

Response `i` matches if and only if it is exactly string-equal to span text
`i`. `k` is the number of matches. The record carries `k` and `n` and no
verdict: there is no normative pass threshold in this specification, and
consumers MUST apply their own k-of-n judgment appropriate to their risk
context.

## Signer and executor

The `attester` field is the signing identity: the Ed25519 key whose
signature closes the record. The signer may differ from the executing model.
`model_claim` and `runtime_claim` are claims about the executor made by the
signer; the record does not verify them.

`verification_method` distinguishes the strength of that binding:

- `asserted`: the signer asserts the executor identity with no external
  corroboration.
- `provider_attestation`: the binding between record and executing
  model/runtime is vouched for by the runtime provider. The vouching
  mechanism itself is out of scope for v0.1.

## Verification

Three operations, named here in TypeScript form (the Python SDK mirrors them
in snake_case):

- `verifyReadFidelityReceipt(record)`: shape checks, digest format checks,
  `n` equals `span_commitments.length`, seed derivation recomputes, and the
  signature verifies against `attester` over JCS of the record minus `sig`.
- `verifyAgainstSource(record, sourceText)`: additionally recomputes the
  spans from `challenge.seed`, `n`, and `challenge.span_len` over
  `sourceText`, hashes each, and compares to `span_commitments`. ALL
  commitments must match.
- `verifyResponses(record, sourceText, responses)`: recomputes `k` from the
  responses, checks it against the claimed `k`, and checks
  `response_digest` against the JCS digest of the response array.

A record whose recorded `k` is less than `n` is not invalid: an honest
partial score verifies as a valid record with that recorded `k`.

## What a read_fidelity_receipt proves

That the holder of the responses could reproduce `k` of `n` seed-sampled
spans of the source text, under a challenge bound to the stated content,
presentation, and nonce, and that the attester key signed that claim.

## What a read_fidelity_receipt does not prove

Restating the mandatory statement in list form, plus its consequences:

- It does not prove every byte was read correctly. Sampling covers `n` spans
  of `span_len` code points; everything outside the sampled spans is
  unexamined.
- It does not prove perception or comprehension. Correct readback of spans
  is not understanding.
- It does not prove which channel was used. See Limitations.
- It carries no normative pass threshold: the consumer judges k of n.
- Timestamps, `model_claim`, and `runtime_claim` are attester claims, not
  verified facts.

## Limitations

- Memorization: a model may reproduce spans from prior knowledge of the
  content without reading the presentation at all. The nonce prevents
  replaying old responses, but it cannot prevent a model that already knows
  the content from answering out of memory. Consumers challenging widely
  published content should weight receipts accordingly.
- Channel non-enforcement: the record cannot prove which input channel
  produced the readback. A responder with lossless access to the source text
  can score k = n regardless of what any lossy channel showed it.
  `verification_method` and `runtime_claim` narrate the channel; they do not
  enforce it.
- Coverage is not bounded by n: the sampler guarantees distinct start positions,
  not distinct or non-overlapping spans. When the source is short relative to
  `n * span_len`, spans overlap and the unique code points checked fall well
  below `n * span_len`; a periodic source can collapse `n` sampled spans to a
  few distinct span texts, so a reader who reproduces the repeating unit scores
  k = n while checking far fewer than n independent challenges. Consumers should
  read `n`, `span_len`, and the source length together, and treat the fidelity
  claim as weak when the source is short or repetitive. A future
  `span_sample_v2` could require distinct span texts; that is a versioned
  algorithm change, so v1 documents the limitation rather than silently altering
  sampling.
- Sampling assumptions: the fidelity claim holds "at the stated n under the
  declared sampling assumptions." Small `n` or short `span_len` weaken the
  claim; consumers see both in the record and judge.

## Durability

The value of this record family is independent of vision-token pricing. The
failure mode it addresses is perceptual fidelity, not cost: cheaper vision
input does not make a lossy channel lossless, and content perceived through
any lossy channel still needs readback evidence before a digest seen there
is treated as load-bearing.

## Word handle interplay

When word_digest_handles are used in the surrounding flow (for example, a
human reads a handle aloud and the agent resolves it), the record pins the
lexicon via the OPTIONAL `lexicon_id` and `lexicon_profile` fields so the
handle encoding is reproducible later. The handle encoding itself is
specified in docs/word-handles-spec.md.

## Open items

- The top-level `type` field is a house convention addition; the amendment
  text was silent on it.
- `challenge.span_len` is recorded in the challenge object because it is
  required to recompute spans; confirm placement.
- The null-vs-present `presentation_digest` seed collision demonstrated in an
  earlier draft is RESOLVED: the seed preimage is now the RFC 8785 JCS of the
  four bound fields (see Seed derivation), and a cross-language regression test
  in both SDKs pins that the previously colliding pair now derives distinct
  seeds. This settled the signing-preimage change for v0.1.
- Coverage under overlapping and periodic sources is not bounded by `n` (see
  Limitations). Decide whether `span_sample_v2` should require distinct span
  texts, and whether the record should record a coverage figure.
- The rejection-sampling loop in span selection has no explicit iteration cap.
  It terminates with probability 1 and `n` is bounded by the record payload, so
  the cost is bounded; a hard cap would be defensive only.

## Pointers

- Reference implementation (TypeScript):
  [src/v2/read_fidelity_receipt/](../src/v2/read_fidelity_receipt/). The
  Python SDK carries a mirrored module under
  `agent_passport/v2/read_fidelity_receipt/` with a byte-identical shared
  parity fixture.
- Conformance fixture family:
  [fixtures/read-fidelity-receipt/](../fixtures/read-fidelity-receipt/).
- Word handle codec: [src/v2/word_handles/](../src/v2/word_handles/) and
  [docs/word-handles-spec.md](./word-handles-spec.md).
