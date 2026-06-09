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

A pass proves byte-exact agreement on the derivation: the four-field
preimage, strict RFC 8785 canonicalization, SHA-256, lowercase hex, and the
rejection of every non-canonical timestamp form in the negative vectors. Two
of the accept vectors additionally byte-match hashes published by independent
ecosystem implementations, so a pass demonstrates cross-implementation
agreement, not just self-consistency. A pass does not prove anything about
what an `action_ref` means in a live system: not that an action was
authorized, not that it occurred, and not that the scope was honored. Those
claims belong to the commitment, decision, and receipt records the key
correlates, per the specification's non-goals.
