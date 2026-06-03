# Context Provenance Attestation (CPA) v0.1 Specification

Code/spec name: `ContextProvenanceAttestation` (CPA). Buyer-facing name:
Context Custody Receipt.

This document is the implementer-facing specification for CPA v0.1. It
defines the data shapes, the frozen tree shape, the two disclosure modes,
the mutual binding fields, the offline verifier and its reason codes, and
the claim boundary. The cryptographic tree shape is frozen and is described
in detail in [TREE-SHAPE.md](./TREE-SHAPE.md); this spec references it
rather than restating the byte layout.

## 1. What CPA is

A CPA is a signed, partitioned-Merkle commitment to a declared context
basis. A producer groups the context items it used into structural-origin
channels, builds one Merkle partition per non-empty channel, commits the
present partition roots into a single top root, and signs the result with a
producer key at a stated time. A verifier checks the signature, the key
state at that time, the binding to an action, and the Merkle structure,
offline and fail-closed.

### 1.1 What CPA proves

- Custody of the declared context basis by the producer key at the stated
  time.
- Admissibility of the disclosed evidence under a declared selection policy
  (the disclosure mode).
- Tamper-evidence over the committed structure: any change to a committed
  field breaks the signature or the Merkle recomputation.
- Replay-resistance via mutual binding: the CPA carries the `action_ref` of
  the action it attests, and decision and completion receipts carry the
  CPA's `cpa_ref`, so a CPA cannot be detached from its action and reused
  under a different one without detection.
- Structural-origin partitioning: each item is committed under one of eight
  channels, and the channel is part of the leaf preimage, so a producer
  cannot silently relabel an item's declared channel without changing the
  root.
- In `full-set` mode, completeness of the disclosed evidence relative to the
  signed tree: the disclosed leaves reconstruct the signed root, so the set
  shown is exactly the set committed.

### 1.2 What CPA does NOT prove

- It does NOT prove the truth of any item's content.
- It does NOT prove cleanliness of the context.
- It does NOT prove completeness of what the model actually saw or
  conditioned on.
- It does NOT prove faithful capture: that the declared basis equals the
  basis the model was actually conditioned on. A perfectly formed CPA over a
  basis that differs from what the model actually used still verifies valid,
  because nothing in the disclosed bytes lets the verifier detect that
  divergence.

CPA is a flight recorder, not a seatbelt. It records what was declared so a
later party can detect tampering and re-derive the commitment. It does not
prevent a bad basis from being used.

### 1.3 The one NOT-CLOSED vector

Pre-attestation faithful-capture failure is out of v0.1 scope. If the
producer attests basis A but the model was actually conditioned on basis B,
no check in this spec catches it, because the divergence is not present in
the signed bytes. Closing this vector requires an independent capture
boundary that observes the basis at the moment of use, outside the producer's
own assertion: a trusted execution environment (TEE) attestation,
write-time receipts emitted at context-assembly time, or runtime
instrumentation of the inference path. These mechanisms are out of v0.1 scope
and are a deferred follow-on, not part of this specification.

## 2. Channels

There are exactly eight structural-origin channels. The channel is a
partition key, not a trust assertion. Producer discretionary labels such as
"trusted", "clean", or "safe" are banned as origin claims.

`CHANNEL_ORDER` (frozen):

1. `system-config`
2. `developer`
3. `user-socket`
4. `retrieval-store`
5. `tool-result`
6. `external`
7. `memory`
8. `quarantine`

The top Merkle tree is built over the present partition roots taken in this
order. Empty channels are omitted entirely.

## 3. Data shapes

### 3.1 ContextItem (leaf)

```
ContextItem {
  ctx_id:      string        // ordering key, unique within its partition
  channel:     ContextChannel // MUST equal the partition's channel
  content_ref: string        // 64-hex sha256 of the raw content bytes
  byte_len:    number        // >= 0
  trust_tier?: string        // OPTIONAL metadata, NOT in the leaf preimage
  content?:    string        // OPTIONAL disclosed raw content, base64
}
```

The leaf preimage is exactly `{ byte_len, channel, content_ref, ctx_id }`.
`content` and `trust_tier` are excluded from the preimage, so the root is
identical whether or not the raw content is later disclosed. `trust_tier` is
producer-declared metadata only and is not proof-bearing.

### 3.2 CpaPartition

```
CpaPartition {
  channel:           ContextChannel
  partition_root:    string          // 64-hex subtree root
  leaf_count:        number          // >= 1
  context_profile?:  ContextProfile  // REQUIRED in inclusion, OMITTED in full-set
  leaves?:           ContextItem[]   // ALL leaves in full-set, optional subset in inclusion
  inclusion_proofs?: InclusionProof[] // inclusion mode only, when a subset is disclosed
}
```

`ContextProfile { channel, hidden_leaf_count }` carries
`hidden_leaf_count = leaf_count - disclosed`.

### 3.3 ContextProvenanceAttestation (signed)

```
ContextProvenanceAttestation {
  version:        'cpa/0.1'
  action_ref:     string         // 64-hex action identity
  producer_did:   string         // producer DID, MUST equal didDoc.id
  producer_pubkey:string         // 64-hex Ed25519 key that signs the CPA
  attested_at:    string         // ISO 8601 UTC
  mode:           'full-set' | 'inclusion'
  partitions:     CpaPartition[] // present partitions, sorted by CHANNEL_ORDER
  root:           string         // 64-hex top Merkle root
  signature:      string         // 128-hex Ed25519, '' in the unsigned shape
}
```

The signature covers `canonicalizeJCS({ ...cpa, signature: '' })` using the
RFC 8785 JSON Canonicalization Scheme from `src/core/canonical-jcs.ts`.

## 4. Frozen tree shape

The tree shape is frozen and specified in
[TREE-SHAPE.md](./TREE-SHAPE.md). In summary:

- Three mutually-distinct domain tags separate the hashing roles:
  `LEAF_TAG = "CPA:v0.1:leaf\n"`, `NODE_TAG = "CPA:v0.1:node\n"`,
  `SIGN_TAG = "CPA:v0.1:sign\n"`. Each is hashed as its raw UTF-8 bytes
  including the trailing line feed.
- `leaf_hash = sha256( utf8(LEAF_TAG) || utf8(canonicalizeJCS(leaf_preimage)) )`.
- `node_hash(left, right) = sha256( utf8(NODE_TAG) || left32 || right32 )`
  over raw 32-byte child digests.
- Within a partition, leaves are sorted ascending by `ctx_id`; a duplicate
  `ctx_id` is rejected.
- Odd nodes are promoted unchanged (RFC 6962); they are never duplicated,
  which closes CVE-2012-2459.
- Each partition root is the bottom-up reduction of its sorted leaf digests.
  The top root is the reduction of the present partition roots in
  `CHANNEL_ORDER`. A single present partition gives `root = partition_root`.
- Empty tree: `partitions = []` and
  `root = hex( sha256( utf8(NODE_TAG) || utf8("EMPTY") ) )`, a fixed signable
  constant.
- `cpa_ref = hex( sha256( utf8(SIGN_TAG) || utf8(canonicalizeJCS(signed_cpa)) ) )`
  content-addresses the fully signed object, including its signature.

## 5. Disclosure modes

### 5.1 full-set

Every present partition carries all of its leaves and no `context_profile`.
The verifier recomputes every `partition_root` and the top `root` from the
disclosed leaves. A valid full-set CPA yields completeness `PROVEN`: the
disclosed evidence reconstructs the signed root under the declared selection
policy, so the disclosed set is exactly the committed set, relative to the
signed tree.

### 5.2 inclusion

Every present partition carries a `context_profile` with `hidden_leaf_count`
and may carry a disclosed subset of leaves, each accompanied by an inclusion
proof. The verifier checks that each disclosed leaf carries a proof that
folds to the declared `partition_root`, folds the declared partition roots in
`CHANNEL_ORDER` to the declared top root, and checks the cardinality
`hidden_leaf_count === leaf_count - disclosed`. A valid inclusion CPA yields
completeness `NOT_PROVEN`: it carries counts and a partial selection, not a
full reconstruction.

## 6. Mutual binding

CPA is a pure protocol primitive; it does not own receipt orchestration or
gateway state. Binding is carried by small reference fields and checked
offline. See [BINDING.md](./BINDING.md).

- CPA to action: the CPA carries its own `action_ref`. If a receipt is
  presented with an `action_ref`, it must match the CPA's via
  `actionRefsMatch` (`src/core/action-ref.ts`); a mismatch is
  `ACTION_REF_MISMATCH`.
- Receipt to CPA: a decision or completion receipt carries `cpa_ref`. If a
  receipt is presented with a `cpa_ref`, it must equal `computeCpaRef(cpa)`;
  a mismatch is `CPA_REF_MISMATCH`.

`carryCpaRef(cpa)` returns `{ cpa_ref }` and `bindCpaRefToReceipt(receipt,
ref)` returns a new object with the field added. Neither signs anything; the
caller signs the receipt body with its own machinery so the `cpa_ref` lands
inside the receipt's signed bytes.

## 7. Offline verifier

`verifyCPA(cpa, didDoc, receipt?, opts?)` is offline and fail-closed: it
consults only its arguments plus the public material in the DID document. It
uses no network, no private keys, and no gateway state. `valid` is true only
when `reasons.length === 0`. The checks, in order:

1. Strict shape decode of the CPA.
2. DID binding: the DID document is well-shaped and `didDoc.id ===
   producer_did`.
3. Signature over `canonicalizeJCS({ ...cpa, signature: '' })`.
4. Key active at `attested_at` (rotation chain valid, key not retired).
5. Merkle recompute: full-set recomputes every partition root and the top
   root; inclusion folds each disclosed leaf's proof to the declared
   partition root and the declared roots to the top root.
6. Content binding: every disclosed leaf carrying `content` must have
   `sha256(content) === content_ref` and `byte_len === content.length`.
7. Mutual binding against an optional receipt (sections 6).
8. Disclosure policy: with `opts.requireContent`, every disclosed leaf must
   carry `content` and at least one leaf must be disclosed.

### 7.1 Reason codes

```
SHAPE_INVALID                  malformed CPA shape
SIGNATURE_INVALID              Ed25519 signature did not verify
KEY_NOT_ACTIVE                 producer key not active at attested_at
DID_MISMATCH                   DID doc malformed or id != producer_did
ACTION_REF_MISMATCH            receipt.action_ref does not match the CPA
CPA_REF_MISMATCH               receipt.cpa_ref != computeCpaRef(cpa)
CONTENT_REF_MISMATCH           disclosed content does not hash to content_ref
PARTITION_ROOT_MISMATCH        recomputed partition_root != declared
ROOT_MISMATCH                  recomputed top root != declared
CARDINALITY_MISMATCH           leaf_count or hidden_leaf_count inconsistent
INCLUSION_PROOF_INVALID        a disclosed leaf has no valid inclusion proof
DISCLOSURE_POLICY_UNSATISFIED  content-requiring policy not met
DOMAIN_TAG_CONFUSION           duplicate ctx_id within a partition
```

### 7.2 Completeness

`completeness` is `PROVEN` only for a valid full-set CPA (the disclosed
leaves reconstruct the signed root). Every other valid result is
`NOT_PROVEN`, including every valid inclusion CPA, which by design carries
counts and a partial selection rather than a full reconstruction.

## 8. Conformance and known-answer vectors

The module ships four test suites:

- `known-answer.test.ts`: hand-derived RFC 8785 canonicalization vectors,
  an Ed25519 known-answer cross-checked against Node's native verifier, and
  CPA byte-layout pins recomputed directly with `node:crypto`. This is the
  canonicalization-correctness gate.
- `parity.test.ts`: an independent reimplementation of the producer (not
  importing the module's Merkle or assembly code) asserted byte/hex
  identical to `buildCPA`. This isolates the Merkle and assembly logic. It
  shares the JCS primitive, so it does not by itself prove RFC 8785
  correctness, and it is not a cross-language parity; a second-language port
  is a deferred follow-on.
- `conformance.test.ts`: a matrix of valid CPAs through `verifyCPA` in both
  modes with the expected completeness.
- `adversarial.test.ts` and `disclosure.test.ts`: fail-closed and functional
  coverage.
