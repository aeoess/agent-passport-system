# CPA v0.1 Tree Shape (FROZEN)

This document fixes the tree shape for Context Provenance Attestation (CPA)
v0.1. The shape is frozen. Any change to a domain tag, the leaf preimage
field set, the hashing formulas, the ordering rules, or the empty-tree
sentinel is a new version, not a patch.

## What CPA attests

A CPA records custody of the declared context basis by a producer key at a
stated time, and the admissibility of the disclosed evidence under a
declared selection policy (the disclosure mode). The truth of any item's
content, and whether the declared channel for an item reflects its real
origin, are downstream consumer responsibilities. `trust_tier` is optional
producer-declared metadata only, it is not proof-bearing, and it is
excluded from the leaf preimage.

## Domain tags

Three mutually-distinct ASCII tags separate the three hashing roles so a
digest computed in one role cannot be reinterpreted in another. Each tag is
hashed as its raw UTF-8 bytes, including the trailing newline, which is part
of the byte value.

| Constant   | Exact byte value (UTF-8)      | Role                              |
| ---------- | ----------------------------- | --------------------------------- |
| `LEAF_TAG` | `CPA:v0.1:leaf\n`             | leaf preimage prefix              |
| `NODE_TAG` | `CPA:v0.1:node\n`             | internal node and top-tree prefix |
| `SIGN_TAG` | `CPA:v0.1:sign\n`             | `cpa_ref` prefix only             |

The `\n` above denotes a single line-feed byte (0x0A) appended to the ASCII
text. `LEAF_TAG` is 14 bytes, `NODE_TAG` is 14 bytes, `SIGN_TAG` is 14
bytes.

## Channels and canonical order

There are exactly eight channels. The channel is a structural partition
key, not a trust assertion. Producer discretionary labels such as
"trusted", "clean", or "safe" are banned as origin claims.

```
CHANNEL_ORDER = [
  'system-config',
  'developer',
  'user-socket',
  'retrieval-store',
  'tool-result',
  'external',
  'memory',
  'quarantine',
]
```

## Leaf preimage

The leaf preimage is exactly these four fields, and only these four:

```
leaf_preimage = { byte_len, channel, content_ref, ctx_id }
```

`content` (the optional disclosed raw bytes, base64) and `trust_tier` are
excluded from the preimage. This is deliberate: the partition root and the
top root are identical whether or not the raw content is later disclosed, so
disclosure does not move the root. The tree commits to `content_ref` (the
64-hex sha256 of the raw content bytes), not to the raw content.

## Leaf and node hashing

Digests are carried as raw 32-byte values internally. Hex appears only at
object boundaries (`partition_root`, `root`, `content_ref`, `cpa_ref`).

```
leaf_hash(leaf) = sha256( utf8(LEAF_TAG) || utf8(canonicalizeJCS(leaf_preimage)) )

node_hash(left, right) = sha256( utf8(NODE_TAG) || left32 || right32 )
```

`canonicalizeJCS` is the RFC 8785 JSON Canonicalization Scheme from
`src/core/canonical-jcs.ts`. `node_hash` concatenates the two raw 32-byte
child digests, not their hex strings.

## Within-partition ordering

Within a partition, leaves are sorted ascending by `ctx_id` using
JavaScript string comparison (Unicode code-point order). `ctx_id` must be
unique within its partition. A duplicate `ctx_id` throws on build and is
reported as `DOMAIN_TAG_CONFUSION` on verify.

## Odd-node promotion (RFC 6962)

The tree is built bottom-up. At every level, pairs are combined with
`node_hash`. When a level has an odd number of nodes, the final unpaired
node is promoted unchanged to the next level. It is never duplicated.

Promoting rather than duplicating the odd node closes CVE-2012-2459, the
Bitcoin Merkle duplicate-leaf class in which duplicating the last node lets
two distinct leaf multisets share a root. A single leaf gives
`partition_root = hex(leaf_digest)` with no node hashing.

## Partition root and top root

Each present partition's `partition_root` is the bottom-up reduction of its
sorted leaf digests under `node_hash`.

The top root is built over the present partitions only, taken in
`CHANNEL_ORDER`. Empty partitions are omitted entirely (they contribute no
leaf to the top tree and appear nowhere in the CPA). The raw 32-byte
`partition_root` digests are the leaves of the top tree, reduced under
`node_hash` with the same odd-promotion rule. A single present partition
gives `root = partition_root`.

## Empty-tree sentinel

When zero leaves exist in total, `partitions = []` and the top root is a
fixed, signable sentinel:

```
root = hex( sha256( utf8(NODE_TAG) || utf8("EMPTY") ) )
```

This is a constant. It lets a producer attest custody of an empty context
basis without a special wire case, and the verifier recomputes the same
constant.

## cpa_ref

`cpa_ref` content-addresses the fully signed CPA object under `SIGN_TAG`:

```
cpa_ref = hex( sha256( utf8(SIGN_TAG) || utf8(canonicalizeJCS(signed_cpa)) ) )
```

The input is the complete signed attestation, including its `signature`
field, so the `cpa_ref` is stable for a given signed object and changes if
any signed field changes.

## Disclosure modes and completeness

In `full-set` mode every present partition carries all of its leaves and no
`context_profile`. A verifier recomputes every `partition_root` and the top
`root` from the disclosed leaves. A valid full-set CPA yields completeness
`PROVEN`: the disclosed evidence reconstructs the signed root under the
declared selection policy.

In `inclusion` mode every present partition carries a `context_profile`
with `hidden_leaf_count` and may carry a disclosed subset of leaves.
Inclusion-proof membership is added in Phase 1. A valid inclusion CPA yields
completeness `NOT_PROVEN`: it carries counts and a partial selection, not a
full reconstruction.
