# action_ref v1 (`action-ref-v1-jcs-sha256`)

## Status

- Version: v1.0
- Date: 2026-06-09
- Stability: frozen preimage. The four-field preimage and the derivation
  defined here do not change under the v1 label. See Versioning.
- Changed acceptance behavior, 2026-10-02: the Input domain section below is
  now enforced. Values that were accepted and hashed before are rejected now.
  See that section for exactly what changed.
- Pinned reference revision: giskard09/argentum-core
  [6ceecf5442fb9a573fdc87a0559755437a7f379f](https://github.com/giskard09/argentum-core/commit/6ceecf5442fb9a573fdc87a0559755437a7f379f).
  Every claim this document makes about the upstream profile was read from
  `docs/spec/action-ref.md` and
  `plugins/agt_evidence_anchor/action_ref.py` at that one revision, and it is
  the only reference revision cited anywhere in this profile's code, docs and
  vectors. Where this implementation's timestamp acceptance differs from that
  revision's validator, see "Differences from the reference validator".

This document specifies the cross-ecosystem `action_ref` v1 form, the one
computed by `computeExternalActionRefV1`. The derivation follows the form
converged in public standards discussion in 2026 (w3c-cg/ai-agent-protocol#34).
It is distinct from the APS-native `action_ref` of
`draft-pidlisnyi-aps` section 4.1 (`computeActionRef`), whose preimage uses
camelCase keys, a multi-scope array, and second-precision timestamps. The two
are separate primitives with intentionally different preimages; this document
specifies only the v1 cross-ecosystem form.

## Definition

`action_ref` is a correlation key, not an authorization claim. It joins the
commitment, decision, and receipt records for a single action by a single
producer. Two records carrying the same `action_ref` from the same producer
refer to the same action; nothing more is implied.

## Preimage

The preimage is the four-field tuple:

```json
{
  "agent_id":    "<string>",
  "action_type": "<string>",
  "scope":       "<string>",
  "timestamp":   "<string, RFC 3339 UTC millisecond form>"
}
```

All four fields are required strings. Field semantics:

- `agent_id`: the terminal executing agent DID after delegation resolution.
  Never the delegator, never a display label. When agent A delegates to agent
  B and B executes, `agent_id` is B.
- `action_type`: an opaque, producer-scoped semantic label. It enters the
  preimage as bytes; it is not a cross-producer semantic key. Two producers
  using the same `action_type` string are not thereby claiming the same
  semantics.
- `scope`: the terminal executing agent's requested-intent scope, not the
  authorized or narrowed scope. Narrowing lives in the decision and
  commitment records that `action_ref` correlates. A single string; this
  differs from the APS-native form, whose `scopeRequired` is an array.
- `timestamp`: RFC 3339 UTC with exactly three fractional digits, uppercase
  `T`, uppercase `Z`, zero-padded: `YYYY-MM-DDTHH:MM:SS.mmmZ`. There is one
  valid byte sequence per instant. Producers MUST emit this form. Receivers
  MUST treat any other representation (lowercase `t` or `z`, an explicit
  offset such as `+00:00`, missing or non-three-digit fractional seconds) as
  invalid for `action_ref` computation, rejected rather than coerced.
  Implementations holding epoch-millisecond integers convert to this form
  before hashing, at the serialization layer. The timestamp string is hashed
  as opaque bytes and never normalized.

The accepted timestamp grammar, exactly as implemented:

```
^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$
```

## Input domain

This helper enforces the following input checks. They follow the Domain
paragraph of the pinned upstream specification, except for the timestamp
differences listed under "Differences from the reference validator". There is
no "canonicalize an out-of-domain preimage some other way" fallback. A preimage
that fails a check is refused with `OUT_OF_PROFILE_DOMAIN` and the refusal happens
**before any digest is computed or compared**, the same pattern as
`UNSUPPORTED_CANONICAL_PROFILE`. This follows the Domain paragraph of
giskard09/argentum-core `docs/spec/action-ref.md` (commit
[6ceecf5442fb9a573fdc87a0559755437a7f379f](https://github.com/giskard09/argentum-core/commit/6ceecf5442fb9a573fdc87a0559755437a7f379f),
with the 2026-07-29, 2026-08-15 and 2026-08-16 entries) and its reference
validator `plugins/agt_evidence_anchor/action_ref.py::_validate_domain`.

- `agent_id`, `action_type`, `scope`: ASCII only. Every code point MUST be
  `<= 0x7F`. This subsumes the surrogate-pair case, and it closes the Unicode
  normalization ambiguity by construction rather than by picking a form: NFC
  and NFD diverge only on non-ASCII code points, so neither can reach the
  preimage. No normalization is performed, because none can be needed.
- `scope`: non-empty. There is no `""` "not applicable" exception. The
  exception existed in the upstream specification until 2026-08-15, when it
  was removed to match the published Internet-Draft
  `draft-etcheverry-action-ref-02` section 6 ("free-form non-empty string").
- Preimage keys: no duplicates. A duplicate key is `OUT_OF_PROFILE_DOMAIN`.
  This is a property of parsing, not of validation: once a document has been
  parsed into an object the second `agent_id` has overwritten the first and
  the evidence is gone. Implementations that receive wire bytes MUST decide it
  on the bytes, comparing member names after JSON string decoding so that
  `"a"` and an escaped `"\u0061"` are the same name.
- `timestamp`: the grammar above, plus calendar validity. Unchanged by this
  section, it was always strict here.

The domain belongs to this profile, not to canonicalization in general. The
general-purpose JCS canonicalization this derivation calls
(`src/core/canonical-jcs.ts`) is unchanged and still accepts non-ASCII
strings, as RFC 8785 requires. The APS-native `action_ref` of
`draft-pidlisnyi-aps` section 4.1 (`computeActionRef`) has its own, different
input rules and is not affected by anything in this section.

### Changed acceptance behavior (2026-10-02)

Three classes of input that this implementation accepted and hashed before are
rejected now:

- A non-ASCII `agent_id`, `action_type` or `scope`. Previously hashed as UTF-8
  bytes. Conformance vector `av-003` carried the digest
  `a99472d9b5ce07b8d977fc217452361df5b137af66d40bd03639bee4caa2b158` for a
  Cyrillic-and-emoji preimage. It is now a rejection vector.
- An empty `scope`. Previously hashed. Conformance vector `av-007` carried the
  digest `cea68656343a06fad083af9a283329af96fcbc6c5fa183229823070fe635641b`.
  It is now a rejection vector.
- A duplicate preimage key, when the preimage arrives as bytes. Previously the
  last occurrence silently won, because `JSON.parse` resolved it before the
  helper saw it. `parseExternalActionRefV1Preimage` is the serialized entry
  point that rejects it.

No accepted digest changed: every preimage still inside the domain hashes to
exactly what it hashed to before, so this is a narrowing of acceptance, not a
change of derivation, and it stays under the v1 label. Any party that computed
an `action_ref` over an out-of-domain preimage was never computing a
conformant v1 value. That digest is not reproducible by a conformant verifier
and never was.

### One error marker for every domain failure

Every rejection of an input outside the profile carries the literal string
`OUT_OF_PROFILE_DOMAIN` in its message, with the original wording kept after
the marker. That covers a non-string field, a non-ASCII `agent_id`,
`action_type` or `scope`, an empty `scope`, a duplicate preimage key, a
non-object top level, malformed JSON, and every timestamp grammar or calendar
failure (including a `Date` that is invalid or renders outside years
0000-9999). The timestamp rules are part of the domain, not a separate
well-formedness layer, so a caller that wants to tell "this input is not in
the profile" from any other error needs exactly one check and never has to
pattern-match prose. The conformance verifier
`conformance/action-ref-v1/verify.py` follows the same rule.

## Differences from the reference validator

The reference validator is
`plugins/agt_evidence_anchor/action_ref.py::compute_action_ref` (which calls
`_validate_domain` with `allow_epoch_ms=False`) in giskard09/argentum-core at
commit
[6ceecf5442fb9a573fdc87a0559755437a7f379f](https://github.com/giskard09/argentum-core/commit/6ceecf5442fb9a573fdc87a0559755437a7f379f),
the single revision this profile is pinned to. The two implementations were
compared directly on timestamp boundary inputs, holding `agent_id`,
`action_type` and `scope` fixed and in-domain. In the cases tested, every input
accepted by both produced the same digest. Acceptance differs in three classes
of timestamp, stated here as facts, not as recommendations:

1. **Year 0000.** This implementation accepts `0000-01-01T00:00:00.000Z` and
   `0000-02-29T00:00:00.000Z` (year 0 is a leap year in the proleptic
   Gregorian calendar) and hashes them. The reference validator rejects both
   with `OUT_OF_PROFILE_DOMAIN: timestamp: ... (year must be in 1..9999, not
   0)`, because it decides calendar validity with Python
   `datetime.datetime.strptime`, whose `MINYEAR` is 1. Both sides' grammars
   admit a four-digit `0000` for the year, so neither rejects it on shape.
   Only the calendar step diverges.

2. **Second 60 (leap second).** This implementation accepts second 60 at 23:59
   on the last day of any month (for example `2016-12-31T23:59:60.000Z`,
   `2026-06-30T23:59:60.000Z`, `9999-12-31T23:59:60.000Z`) and rejects it
   anywhere else. It does not check whether a leap second was announced for
   that date, which RFC 3339 section 5.7 requires for a valid leap second, so
   it accepts month-end values where no leap second occurred. This existing
   behavior is unchanged. The reference
   validator rejects second 60 unconditionally, with
   `OUT_OF_PROFILE_DOMAIN: timestamp: ... (second must be in 0..59, not 60)`,
   again because `strptime` constructs a `datetime` and 60 is not a
   representable second. The two sides agree on rejecting second 60 away from
   23:59 on a month's last day, and differ at month end.

3. **Non-ASCII decimal digits in the timestamp.** This implementation rejects
   `٢٠٢٦-06-30T12:00:00.000Z` (Arabic-Indic digits in the year) as a grammar
   failure, because its grammar is written with the explicit ASCII class
   `[0-9]`. The reference validator **accepts** it and returns a digest
   (`53878dd707b0a91be188b9fbbf32f5a2c6806ab186db2cbccc99308ea0c7df2b`),
   because Python's `\d` matches any Unicode decimal digit and `strptime`
   parses them. This is the one disagreement where the reference side is the
   more permissive one, and it lets a non-ASCII code point reach the preimage
   through the one field the Domain paragraph's ASCII rule does not name.

The first two disagreements mean this implementation accepts a timestamp the
reference validator refuses. A digest it produces for one of those instants is
therefore not reproducible by that validator, even though both sides agree the
value is grammatical. The third means the reference validator produces a
digest this implementation refuses to produce. Nothing in this section changes
what either side does: the timestamp behavior here is unchanged and is the
behavior documented under **Preimage** above.

The comparison covered years 0000, 0001 and 9999, second 60 at 23:59 on the
last day of a month, at 23:59 on a day that is not the last day, and at
another minute, February 29 in a leap and a non-leap year, February 30,
April 31, `23:59:59.999Z` and `00:00:00.000Z`, and the lowercase `t`/`z`,
trailing-newline and non-ASCII-digit variants. Every case not listed in the
three classes above agreed, including on the digest where both sides accept.
The comparison covers these cases only, not every possible timestamp.

## Derivation

1. Assemble the four-field tuple above.
2. Canonicalize with the JSON Canonicalization Scheme, RFC 8785, strict form:
   keys sorted by code point, no whitespace, ES2015 string escaping. Note
   that this is strict JCS, not the legacy APS canonical serialization
   (docs/CANONICAL-SPEC.md) that strips null values; the distinction cannot
   matter for this preimage, since all four fields are required strings, but
   conformant implementations use strict JCS.
3. SHA-256 over the UTF-8 bytes of the canonical string.
4. Render the digest as lowercase hex (64 characters).

Because JCS sorts keys by code point, the canonical serialized form is
always, in this exact key order:

```
{"action_type":"...","agent_id":"...","scope":"...","timestamp":"..."}
```

Worked example:

```
agent_id    = "did:aps:zExampleAgent001"
action_type = "document.sign"
scope       = "repo:example/docs"
timestamp   = "2026-06-09T12:00:00.000Z"

canonical   = {"action_type":"document.sign","agent_id":"did:aps:zExampleAgent001","scope":"repo:example/docs","timestamp":"2026-06-09T12:00:00.000Z"}
action_ref  = f5cc735aa740b1a5006bf4d41f6e3cacbabcab3e369043b58d924e3bb69b4988
```

## Non-goals

- Cross-producer `action_type` comparison. The label is producer-scoped.
- Authorization. Holding or presenting an `action_ref` authorizes nothing.
- Uniqueness across producers. Two producers can compute the same
  `action_ref`; the key is meaningful within one producer's record family.

## What action_ref does not prove

An `action_ref` does not prove that the action was authorized, that it
occurred, or that the scope was honored. Those claims live in the records it
correlates: authorization in the decision record, occurrence in the receipt,
scope conformance in the commitment and decision records. The key only joins
them.

## Relationship to the record family

Commitment, decision, and receipt records each reference `action_ref` as the
join key for a single action. Related provenance primitives in this
repository:

- Context Provenance Attestation (CPA), which seals the context an agent
  reasoned over: [SPEC-v0.1.md](../../src/v2/context-provenance/SPEC-v0.1.md)
  and [README.md](../../src/v2/context-provenance/README.md).
- Instruction provenance, which classifies and binds instruction sources
  (module, no standalone spec document yet):
  [src/v2/instruction-provenance/](../../src/v2/instruction-provenance/).

## Versioning

Any change to the preimage (field set, field semantics, timestamp grammar) or
to the derivation (canonicalization, hash, encoding) is a v2 with a new
derivation label. The v1 label is `action-ref-v1-jcs-sha256`. Implementations
MUST NOT emit a changed form under the v1 label.

## Pointers

- IETF Internet-Draft: `draft-pidlisnyi-aps` (the APS-native action_ref is
  section 4.1 of that draft; this document is the cross-ecosystem v1 form).
- Reference implementation:
  [src/core/external-action-ref.ts](../../src/core/external-action-ref.ts)
  over [src/core/canonical-jcs.ts](../../src/core/canonical-jcs.ts).
  `computeExternalActionRefV1` takes a parsed input, and
  `parseExternalActionRefV1Preimage` is the entry point for wire bytes and is
  the only place a duplicate preimage key can still be seen.
- Conformance vectors and verifiers:
  [conformance/action-ref-v1/](../../conformance/action-ref-v1/).
- Pinned upstream reference, read at
  [6ceecf5442fb9a573fdc87a0559755437a7f379f](https://github.com/giskard09/argentum-core/commit/6ceecf5442fb9a573fdc87a0559755437a7f379f):
  `docs/spec/action-ref.md` (the Domain paragraph) and
  `plugins/agt_evidence_anchor/action_ref.py` (`_validate_domain`,
  `compute_action_ref`). The timestamp disagreements with that validator are
  enumerated under "Differences from the reference validator".
