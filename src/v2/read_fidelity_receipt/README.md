# read_fidelity_receipt (v2)

A read fidelity receipt proves sampled readback fidelity at the stated n under the declared sampling assumptions. It does not prove every byte was read correctly, does not prove perception or comprehension, does not prove which channel was used, and carries no normative pass threshold: the consumer judges k of n.

The record is a signed commitment to a sampled readback challenge: a verifier supplies a nonce, spans are drawn deterministically from a seed bound to that nonce and to the exact content and presentation, and the record carries sha256 commitments of the span texts plus the scored result (k of n). The raw span texts and responses are never in the record.

## Record shape

Every digest is `"sha256:<64 lowercase hex>"`. JCS (RFC 8785) sorts keys; the object below shows the fields.

```json
{
  "type": "read_fidelity_receipt",
  "content_digest": "sha256:...",
  "presentation_digest": "sha256:..." ,
  "challenge": {
    "nonce": "verifier-supplied string",
    "seed": "64 hex chars, MUST equal the derivation below",
    "algorithm": "span_sample_v1",
    "version": "1",
    "span_len": 12,
    "span_commitments": ["sha256:...", "..."]
  },
  "response_digest": "sha256:...",
  "k": 5,
  "n": 5,
  "scoring_method": "exact_match_v1",
  "attester": "ed25519 public key hex",
  "model_claim": "...",
  "runtime_claim": "...",
  "verification_method": "asserted",
  "challenge_issued_at": "2026-07-04T00:00:00Z",
  "response_observed_at": "2026-07-04T00:00:00Z",
  "receipt_issued_at": "2026-07-04T00:00:00Z",
  "sig": "128 hex chars"
}
```

- `presentation_digest` is the digest of the rendered presentation as served, or `null` when there is none.
- `n` MUST equal `challenge.span_commitments.length`; this is rejected at create and at verify.
- `response_digest` is `"sha256:" + sha256hex(canonicalizeJCS(responses))` where `responses` is the ordered array of readback strings.
- `attester` is the SIGNING identity and may differ from the executing model; `model_claim` and `runtime_claim` are claims about the executor, and `verification_method` records whether they are merely `asserted` or backed by a `provider_attestation`.
- All three timestamps are caller-provided ISO 8601 strings; the library never reads a wall clock.
- `lexicon_id` and `lexicon_profile` (`"single-list-v1"`) are optional and appear when word_digest_handles appear in the flow.

## Signature convention

`sig` is EXCLUDED from the signing preimage. The preimage is `canonicalizeJCS(record with the sig key removed entirely)`, not a record with an emptied sig field. `canonicalNoSig(record)` returns the preimage string.

## Seed derivation and replay binding

```
seed = sha256hex( utf8( canonicalizeJCS({
         content_digest,
         presentation_digest,   // null when absent
         nonce,
         version
       }) ) )
```

The preimage is the RFC 8785 JCS canonicalization of the four bound fields (keys sorted: `content_digest`, `nonce`, `presentation_digest`, `version`). The nonce is verifier-supplied and never derivable from the document alone; a nonce is single-use per challenge. Because the seed binds the nonce to the exact content digest and presentation digest, replaying span commitments under a different nonce, content, or presentation breaks the derivation even if the record is re-signed: the signature is then valid but verification fails on the seed recompute (`SEED_MISMATCH`).

Each field is a distinct JSON member, so `presentation_digest` is `null` when absent rather than an empty string spliced against the nonce. An earlier concatenation preimage let a null-presentation record with `nonce = P || N` derive the same seed as a `P`-presentation record with nonce `N`; the structured preimage closes that.

## Sampler (span_sample_v1)

`sampleSpans(sourceText, seed, n, spanLen)` splits the source into unicode code points (`Array.from`), so astral characters count as one position and spans never split a surrogate pair. With `L` code points the position range is `L - spanLen + 1`; it throws unless `1 <= n <= range` and `L >= spanLen`. Position `i` (attempt `j`, starting at 0) is:

```
h   = sha256(utf8(seed + ":" + i + ":" + j))
pos = BE-uint64(first 8 bytes of h) mod range
```

bumping `j` on a repeat until the position is unused. The span text is code points `[pos, pos + spanLen)`.

## API

- `deriveSeed(contentDigest, presentationDigestOrNull, nonce, version)` returns the seed hex.
- `sampleSpans(sourceText, seed, n, spanLen)` returns `[{pos, len, text}]`.
- `commitSpans(spanTexts)` returns `"sha256:" + sha256hex(utf8(text))` per span, in order.
- `scoreResponses(spanTexts, responses)` returns `{k, results}` under exact_match_v1 (exact string equality per index; throws on a length mismatch).
- `createReadFidelityReceipt(fields, privateKeyHex)` validates the input (n consistency, seed derivation, digest formats, timestamps), sets `attester` from the key, and signs. Throws on any validation failure.
- `verifyReadFidelityReceipt(record)` returns `{valid, reason?}`. Check order: shape and n consistency, then the Ed25519 signature against `attester`, then the seed derivation. A record tampered after signing fails on the signature; a re-signed nonce or presentation swap fails on the seed.
- `verifyAgainstSource(record, sourceText)` additionally recomputes the spans from `challenge.seed` / `n` / `span_len` over the source, commits each, and compares positionwise against `span_commitments` (ALL must match). Returns `{valid, reason?, commitment_matches, signature_valid, seed_valid}`.
- `verifyResponses(record, sourceText, responses)` returns `{k_recomputed, matches_claimed_k, response_digest_ok}`.

## Shared parity vectors

`vectors/generate.ts` deterministically writes `vectors/read-fidelity-receipt-v0.1-vectors.json`: JCS known-answer tests (including a unicode case), word handle round trips and negatives (substitution, transposition, out-of-lexicon), seed derivation KATs (null and non-null presentation digest), sampler cases (ascii, emoji plus cyrillic, longer), and a fully signed record case with its canonical-no-sig sha256. The Python SDK copies the file byte-identically and asserts its implementation reproduces every value; Ed25519 signing is deterministic, so re-signing the record body with the fixture key must yield the identical sig.

## Limitations

- Memorization: a model may reproduce spans from prior knowledge of the content without reading the presentation.
- Channel non-enforcement: the record cannot prove which input channel produced the readback.
- Sampling only: fidelity is evidenced at the sampled positions, at the stated n; nothing is claimed about unsampled bytes.
