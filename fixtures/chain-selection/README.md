# Chain selection parity vectors

`chain-selection-vectors-v0.json` is the cross-language parity record for
`src/v2/chain-selection`. The TypeScript test `tests/v2/chain-selection.test.ts` and the
Python test `tests/test_chain_selection_parity.py` in `aeoess/agent-passport-python` each
rebuild every case's inputs from this file and assert the recorded outcome member for
member, against a byte-identical copy. A behaviour difference between the two SDKs fails
one of them.

## What it tests

draft-pidlisnyi-aps-03 section 3.3, lines 594-596 of the plain-text rendering:

    594    Each action selects one root-to-leaf authority chain.  A verifier
    595    MUST NOT union scopes or budgets from multiple chains.  Cross-
    596    principal composition requires a separate profile.

Cases CS-01 to CS-07 and CS-12 to CS-19 are that rule. Cases CS-08 to CS-11 are the
fallback half, which is **proposed, not draft-03**: they exercise invariant candidate
L11, "No silent authority resurrection", in `AUTHORITY-LIFECYCLE.md` of the
`aeoess/agent-authority-lifecycle` concept document, whose own status there is
`proposed`. `fallback`, `fall back`, `resurrect` and `reselect` occur zero times in the
published draft.

## Setup

Three single-hop root delegations, three different roots, all naming the same leaf agent.
`read_r1` grants `resource1:read`, `write_r2` grants `resource2:write`, and
`read_r1_alt` grants `resource1:read` again from a third root, which is what the fallback
cases need somewhere to go. All three carry an equal bounded ceiling of 5 in the same
unit, so their sums are strictly larger than any one of them and an amount of 8
discriminates a pooled ceiling from a single chain's own. `chain_concat` is not a chain:
it is two of those roots in one array, the shape a caller reaches for to have two chains
evaluated as one.

## Determinism

    npx tsx fixtures/chain-selection/generate-fixtures.ts

Nothing in the generator reads a clock or a random source. A private key is
`sha256(seed_label_prefix + <root label>)` used as the RFC 8032 Ed25519 seed, a nonce is
the first 32 hex characters of `sha256(seed_label_prefix + "nonce:" + <record label>)`,
and an `action_ref` is `sha256(<case id>)` in lowercase hex. The seed rule is written into
the vector file itself, so the records are re-derivable without reading the generator.
Ed25519 signing is deterministic, so two runs emit byte-identical output and `git diff`
after a second run is the check that matters. These are test keys published in a public
repository and they control nothing.

Every expected outcome is observed rather than asserted: the generator runs the
implementation, compares what it returned against a declaration written beside each case,
and refuses to write the file if the two disagree.

## What a pass establishes

For the SDK revision that was run, that an action is decided against exactly one of the
chains an agent holds, that the result names that one chain, that a second held chain's
scope grants and spend ceiling never enter the decision, that a concatenation of two
chains is refused as a presentation before any facet comparison runs, that an unknown
revocation answer leaves the selection not established rather than refused, and that a
switch away from the chain an action selected happens only when the caller passed an
authorization object and is reported when it does.

## Does not claim

That L11 is correct, adopted or specified. That the opaque `authorization_ref` this
module records establishes that any fallback was authorized, which the proposed text does
not define. Anything about cross-principal composition, which line 596 says requires a
separate profile. Anything about cumulative spend across a subtree over a sequence of
actions: every case uses a fresh ledger and at most one reservation. Anything about chains
deeper than one record, key rotation, or root trust, since every chain here is one
trusted root whose key resolves.
