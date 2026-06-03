# Context Provenance Attestation (CPA)

Code/spec name: `ContextProvenanceAttestation` (CPA). Buyer-facing name:
**Context Custody Receipt**.

A CPA is a signed, partitioned-Merkle commitment to the context basis a
producer used for an action. It is a protocol primitive: offline,
fail-closed, with no network, no private keys on the verify path, and no
gateway state.

## What a Context Custody Receipt gives you

A Context Custody Receipt records, in a tamper-evident form, the context
basis a producer declares it used, partitioned by where each item came from,
and binds that record to the specific action it belongs to. A later party,
holding only the receipt and the producer's public DID document, can verify
it offline.

### What CPA proves

- Custody of the declared context basis by the producer key at the stated
  time.
- Admissibility of the disclosed evidence under a declared selection policy.
- Tamper-evidence: any change to a committed field breaks the signature or
  the Merkle recomputation.
- Replay-resistance via mutual binding: the CPA carries the `action_ref` of
  its action, and decision and completion receipts carry the CPA's
  `cpa_ref`, so the receipt cannot be detached and reused under a different
  action without detection.
- Structural-origin partitioning: each item is committed under one of eight
  channels, and the channel is part of the leaf preimage.
- In full-set mode, completeness of the disclosed evidence relative to the
  signed tree: the disclosed leaves reconstruct the signed root.

### What CPA does NOT prove

- It does NOT prove the truth of any item's content.
- It does NOT prove cleanliness of the context.
- It does NOT prove completeness of what the model actually saw.
- It does NOT prove faithful capture: that the declared basis equals the
  basis the model was actually conditioned on.

CPA is a flight recorder, not a seatbelt. It records what was declared so a
later party can detect tampering and re-derive the commitment. It does not
prevent a bad basis from being used.

### The one NOT-CLOSED vector

Pre-attestation faithful-capture failure is out of v0.1 scope. If a producer
attests basis A while the model was actually conditioned on basis B, no check
in CPA catches it, because the divergence is not present in the signed bytes:
a perfectly formed CPA over the wrong basis still verifies valid. Closing
this requires an independent capture boundary that observes the basis at the
moment of use, outside the producer's own assertion: a trusted execution
environment (TEE) attestation, write-time receipts at context-assembly time,
or runtime instrumentation of the inference path. Those mechanisms are out of
v0.1 scope and are a deferred follow-on.

## The eight structural-origin channels

The channel is a partition key, not a trust assertion. Producer
discretionary labels such as "trusted", "clean", or "safe" are banned as
origin claims.

| Order | Channel           | Typical origin                          |
| ----- | ----------------- | --------------------------------------- |
| 1     | `system-config`   | system prompt and platform configuration |
| 2     | `developer`       | developer-authored instructions          |
| 3     | `user-socket`     | the live user turn                        |
| 4     | `retrieval-store` | retrieved documents (RAG)                 |
| 5     | `tool-result`     | tool and function-call outputs            |
| 6     | `external`        | third-party or fetched content            |
| 7     | `memory`          | persisted prior-session memory            |
| 8     | `quarantine`      | content held under suspicion              |

The top tree is built over the present partition roots in this order; empty
channels are omitted.

## Two disclosure modes

- **full-set.** Every present partition carries all of its leaves. The
  verifier recomputes every partition root and the top root from the
  disclosed leaves. A valid full-set CPA reports completeness `PROVEN`: the
  disclosed set is exactly the committed set, relative to the signed tree.
- **inclusion.** Every present partition carries a count
  (`hidden_leaf_count`) and may carry a disclosed subset of leaves, each with
  an inclusion proof that folds to the declared partition root. A valid
  inclusion CPA reports completeness `NOT_PROVEN`: counts and a partial
  selection, not a full reconstruction.

## Mutual binding

CPA does not own receipt orchestration. Binding is carried by small
reference fields and checked offline (see [BINDING.md](./BINDING.md)):

- the CPA carries its own `action_ref` (CPA to action);
- decision and completion receipts carry the CPA's `cpa_ref` (receipt to
  CPA).

`carryCpaRef(cpa)` and `bindCpaRefToReceipt(receipt, ref)` attach the
`cpa_ref` field before the caller signs the receipt with its own machinery.
At verification time, the receipt's `action_ref` and `cpa_ref` are handed to
`verifyCPA` and both directions are checked.

## Offline verifier and reason codes

`verifyCPA(cpa, didDoc, receipt?, opts?)` returns `{ valid, reasons,
completeness }`. It is fail-closed: `valid` is true only when there are no
reasons. The structured reason codes are:

`SHAPE_INVALID`, `SIGNATURE_INVALID`, `KEY_NOT_ACTIVE`, `DID_MISMATCH`,
`ACTION_REF_MISMATCH`, `CPA_REF_MISMATCH`, `CONTENT_REF_MISMATCH`,
`PARTITION_ROOT_MISMATCH`, `ROOT_MISMATCH`, `CARDINALITY_MISMATCH`,
`INCLUSION_PROOF_INVALID`, `DISCLOSURE_POLICY_UNSATISFIED`,
`DOMAIN_TAG_CONFUSION`.

Completeness is `PROVEN` only for a valid full-set CPA; every other valid
result, including every valid inclusion CPA, is `NOT_PROVEN`.

## Frozen tree shape

The cryptographic tree shape is frozen and specified in
[TREE-SHAPE.md](./TREE-SHAPE.md): three domain tags
(`CPA:v0.1:leaf\n`, `CPA:v0.1:node\n`, `CPA:v0.1:sign\n`), the four-field
leaf preimage `{ byte_len, channel, content_ref, ctx_id }`, raw 32-byte node
hashing, ctx_id ordering, RFC 6962 odd-node promotion (which closes
CVE-2012-2459), the empty-tree sentinel, and the `cpa_ref` content address.
The full specification is in [SPEC-v0.1.md](./SPEC-v0.1.md).

## Usage

```ts
import {
  buildCPA, computeCpaRef, carryCpaRef, verifyCPA,
} from './index.js'

const cpa = buildCPA({
  privateKey, action_ref, producer_did, attested_at,
  mode: 'full-set',
  items, // flat list of ContextItem; each item's channel picks its partition
})

const result = verifyCPA(cpa, didDoc)
// result.valid === true, result.completeness === 'PROVEN'

// Bind into a downstream receipt before that receipt is signed:
const receiptBody = { ...decision, ...carryCpaRef(cpa) }
```

## Tests

- `__tests__/known-answer.test.ts`: hand-derived RFC 8785 canonicalization
  vectors, an Ed25519 known-answer cross-checked against Node's native
  verifier, and CPA byte-layout pins recomputed directly with `node:crypto`.
  This is the canonicalization-correctness gate.
- `__tests__/parity.test.ts`: an independent reimplementation of the
  producer asserted byte/hex identical to `buildCPA`. It shares the JCS
  primitive, so it does not by itself prove RFC 8785 correctness, and it is
  not a cross-language parity; a second-language port is a deferred
  follow-on.
- `__tests__/conformance.test.ts`: a matrix of valid CPAs through `verifyCPA`
  in both modes with the expected completeness.
- `__tests__/disclosure.test.ts`, `__tests__/adversarial.test.ts`,
  `__tests__/roundtrip.test.ts`: functional and fail-closed coverage.

## Boundary

This module imports only core primitives (`canonical-jcs`, `keys`,
`key-rotation`, `action-ref`, type-only `passport`) and `node:crypto`. It
pulls in no gateway intelligence: no network or fetch, no analytics or
scoring, no orchestration, no policy hosting, no cross-tenant or stateful
stores, and no private keys on the verify path.
