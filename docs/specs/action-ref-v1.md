# action_ref v1 (`action-ref-v1-jcs-sha256`)

## Status

- Version: v1.0
- Date: 2026-06-09
- Stability: frozen preimage. The four-field preimage and the derivation
  defined here do not change under the v1 label. See Versioning.

This document specifies the cross-ecosystem `action_ref` v1 form, the one
computed by `computeExternalActionRefV1` and by independent implementations in
the action-ref-v1 ecosystem (argentum-core, x402 #2332, Gonka, the joint I-D
work on A2A #1850). It is distinct from the APS-native `action_ref` of
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

Worked example (pinned against independent ecosystem implementations):

```
agent_id    = "pioneer-agent-001"
action_type = "payment.send"
scope       = "mycelium:payment"
timestamp   = "2026-05-24T10:30:00.000Z"

canonical   = {"action_type":"payment.send","agent_id":"pioneer-agent-001","scope":"mycelium:payment","timestamp":"2026-05-24T10:30:00.000Z"}
action_ref  = 584bc79bb11ce3af5058b3da84d03f85e4aa464a175bd4f913aeb82a22cef60f
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
- Conformance vectors and verifiers:
  [conformance/action-ref-v1/](../../conformance/action-ref-v1/).
