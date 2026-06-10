# Verification source

How a verifying key was obtained, carried in signed evidence rather than in
verifier logs. A `VerificationSource` records the acquisition method for one
signature check: `inline` (key material presented with the artifact),
`pinned` (key previously obtained and stored; the record must say when the
pin was populated and through which method, because a pin's trust posture is
the posture of whatever populated it), or `resolver` (key fetched at
verification time from an allowlisted HTTPS origin, which the record names).
External ecosystems that record a `cache` acquisition method map onto APS
`pinned`.

Two integration points, both optional and additive. An
`EvidenceCommitment` may carry `verificationSource`, placing the record
inside the signed bytes of a bilateral receipt; a receipt whose commitments
omit the field serializes and signs byte-for-byte as before. A
`CheckedSignature` handed to the evidence-descriptor builder may carry the
same record, and it is then echoed on the corresponding `SignerClaim` fact
in the descriptor output.

## What it proves and what it does not prove

It proves what the verifier recorded about key acquisition at verification
time, signed into the evidence: which method was used, when, and (for
resolver) which origin or (for pinned) what populated the pin and when. It
does not prove the resolver was honest, that the pin store was uncompromised,
or that the recorded method was the one actually executed by a dishonest
verifier. Validation here is structural and fail closed: a pinned source
without population provenance is invalid, a resolver source without its
origin is invalid. Judging whether a given acquisition posture is acceptable
is relying-party policy and is out of scope; this module specifies the
record, tests its validation rules, and nothing more.
