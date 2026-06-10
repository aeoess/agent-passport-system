# Producer attestation commitment

APS consumes attestations, it never produces them. This module makes that
composition concrete: an external producer attestation (an EAT per RFC 9711,
a TEE quote, a vendor report) is bound into evidence by reference. The
receipt-side shape is an `EvidenceCommitment` of type `producer_attestation`
carrying a format label (open set, e.g. `eat+jwt`, `tee-quote`), the sha256
of the attestation bytes in `credentialHash`, an optional locator URI, and an
optional free-text note of what the attestation covers (producer identity,
code measurement, environment). The CPA-side shape is the optional
`producer_attestation` slot on a Context Provenance Attestation, the same
reference in the CPA's snake_case field style, signed inside the CPA bytes
when present.

Both carriers are additive. A receipt whose commitments omit the kind, and a
CPA that omits the slot, serialize and sign byte-for-byte as they did before
this module existed; the builders add keys by conditional spread so no
explicitly-undefined key ever reaches a canonicalization path.

## Non-goals

APS does not check TEE quotes or EAT tokens. There are no vendor SDKs here
and no parsing of attestation internals. The commitment binds bytes by hash
so a relying party can fetch the attestation (via the locator or out of
band) and evaluate it with its own tooling.

## What it proves and what it does not prove

A matching hash shows that the bytes a relying party fetched are the bytes
the committer referenced, and the signed carrier shows the committer held
that reference at signing time. The receipt claim is custody of the
reference, not validity of the attestation: nothing here shows the
attestation is genuine, that its producer is trustworthy, or that what it
attests held at any time. Those judgments belong to the relying party's
attestation tooling and policy, outside APS.
