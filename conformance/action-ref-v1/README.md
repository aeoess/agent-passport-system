# action_ref v1 conformance suite

This directory holds the conformance vectors for the cross-ecosystem
`action_ref` v1 correlation key (`action-ref-v1-jcs-sha256`), specified in
[docs/specs/action-ref-v1.md](../../docs/specs/action-ref-v1.md). Run the
Python verifier with `python3 verify.py` (stdlib only; it vendors a minimal
RFC 8785 serializer and recomputes every hash independently of the SDK). Run
the Node verifier with `npm run build` from the repository root, then
`node verify.mjs` from this directory; it imports the real
`computeExternalActionRefV1` from the SDK build, so the vectors stay pinned
to shipping code rather than a reimplementation. Both exit 0 on a full pass
and nonzero with a per-vector diff on any failure.

The suite holds 17 vectors: 6 accept and 11 reject. The reject vectors cover
5 non-canonical timestamp forms, 4 input-domain violations (non-ASCII
`agent_id`, `action_type` or `scope`, and an empty `scope`) and 2 duplicate
preimage keys. A duplicate key cannot be written in a JSON object, so those
two vectors state their preimage as raw JSON text in `input_json` instead of
`input`, and both verifiers feed that text through a duplicate-rejecting
parser (`parseExternalActionRefV1Preimage` in Node, a strict
`object_pairs_hook` in Python) rather than through `JSON.parse`/`json.loads`,
which would keep the last occurrence and destroy the evidence.

Both verifiers reproduce the six expected digests and reject the eleven
negative vectors (the Domain paragraph of giskard09/argentum-core
`docs/spec/action-ref.md` at commit
`6ceecf5442fb9a573fdc87a0559755437a7f379f`). These vectors do not cover every
timestamp boundary or every invalid preimage. In particular, `verify.py` is
looser than the SDK helper on timestamps: it hashes February 30, Arabic-Indic
digits and a trailing newline, so its pass covers these 17 vectors only. The accept
vectors are recomputed by two separate verifiers here (verify.mjs and
verify.py). Cross-implementation agreement is checked elsewhere: the
published ecosystem anchors are pinned in tests/external-action-ref.test.ts,
and the Composable Evidence Criteria lab's pinned vectors run in the
external-action-ref-v1 workflow. A pass does not prove anything about
what an `action_ref` means in a live system: not that an action was
authorized, not that it occurred, and not that the scope was honored. Those
claims belong to the commitment, decision, and receipt records the key
correlates, per the specification's non-goals.
