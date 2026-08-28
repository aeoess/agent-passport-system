# insight.oracle-safety-check:v2 — upstream generator

**This directory is the upstream generator** for the
`insight.oracle-safety-check:v2` cross-stack evidence vectors (conformance
issue `Agent-Authority-Conformance/aps-conformance-suite#26`).

An `OracleSafetyCheck` attestation (Insight, EIP-712 schema v2, 26 signed
fields) riding inside the APS ReceiptV1 envelope as the evidence referenced by
a policy-decision receipt's `evidence_refs` (draft-pidlisnyi-aps §5.5).

Composite gate semantics (fail-closed): the pre-trade action proceeds **only
if** the authority half holds AND the oracle-safety evidence is authentic,
current and permitted. Any missing / expired / denied / unverifiable half is a
HALT.

**What the conformance runner checks on the authority half is enumerated, not
assumed.** It verifies each delegation's Ed25519 signature, the parent
linkage (`parent_delegation_id`) and issuer/subject continuity across the chain,
plus the leaf expiry (`not_after`) and declared revocation. It does **not** run
the SDK's full delegation-chain verification (authority attenuation, spend-limit
narrowing) — see the conformance suite family README for why those are out of
scope here.

Coverage is stated in prose there rather than in a `verification_mode` field:
that field already carries a different axis in the suite (its existing value
`record` describes the nature of the verification), and a machine-readable
coverage field, if one is wanted, is the maintainer's to define.

## Layout (this repo)

```
generate-fixtures.ts        deterministic generator (tsx) — the UPSTREAM generator
vendor/insight/             Insight OracleSafetyCheck v2 (EIP-712 + ABI-keccak),
                            byte-identical copy of
                            github.com/imokokok/insight-aps
                            fixtures/vendor/insight/ @
                            8844e8b2f6bb099b8507bb01337f5a79627ae7d7
                            (pinned in-repo here; the conformance suite's
                            family SOURCE.md pins the same commit)
```

The generated `oracle-safety-check-v1/` output is a **development artifact and
is not committed here**. The committed vectors live in the conformance suite:

- **Vectors + runner:** `aps-conformance-suite`
  `fixtures/cross-stack/oracle-safety-check/` — verified there against the
  **published SDK package** (`agent-passport-system`, not deep imports into
  `src/`).
- `test-fixtures.ts` moved there as `verify.ts` (per review
  `aeoess/agent-passport-system#119`, the SDK repo does not host a fixture
  category on its own).

## Deterministic keypairs

Same public-seed convention as the rest of the suite (`docs/fixture-format.md`)
extended for the four roles this evidence type needs:

```
seed      = SHA-256("aps-oracle-safety-check-fixture-v1")
role_seed = SHA-256(seed_input || 0x00 || role)        role ∈ {principal, agent, gateway, evm-attester}
Ed25519   : private key = role_seed (RFC 8032 seed); public key = Ed25519 derivation
secp256k1 : private key = role_seed (scalar); address = keccak256(pubkey)[-20:]
```

No secret material anywhere; every implementation reproduces the same keys
from `seed_input`. `keypair.publicKeyHex` is the principal (delegation root)
key; the full per-role map is in `roles`.

## Generated vector contract

Each generated vector carries the inner-layer witness so a runner must
**truly verify the evidence, not treat it as opaque** (issue #26):

| Field | Meaning |
|---|---|
| `expected_sub_results` | the named negative/positive sub-results the runner must observe for this vector (e.g. `["decision_signature_invalid"]`). These live in the **data**: the runner never branches on a fixture's id or name |
| `expected` / `expectReasons` | the composite-gate outcome the runner MUST reproduce exactly (e.g. `halt` + `["HALT_ORACLE_EVIDENCE","UID_MISMATCH"]`) |
| `eip712_digest_hex` | the EIP-712 `hashTypedData` digest (`uid`) of the OracleSafetyCheck data |
| `secp256k1_signature_hex` | the 65-byte EIP-712 signature over that digest |
| `oracle_input` | the raw evidence inputs (verdict, asset ids, prices, provider observations with `timestamp`/`exclusionReason`, `checkedAt`) so a runner can recompute the 26 fields, the four ABI-keccak commitments, the digest and the signature |
| `revocation` | declared ledger-side revocation state (authority-delegation revocation is external, per upstream `DelegationStore`) |
| `verification_time` | the wall-clock instant the runner must evaluate at (drives `delegation-expired`) |

Runner requirements (enforced by `fixtures/cross-stack/oracle-safety-check/verify.ts`
in the conformance suite):

1. recompute the JCS canonical bytes and SHA-256 → `canonical_bytes_hex` / `canonical_sha256`;
2. verify the Ed25519 witness → `ed25519_signature_over_canonical_hex`;
3. verify both receipts (receipt id + signature + `prev` link + `delegation_ref`) and the delegation chain with the **published** APS SDK — each delegation's signature, `parent_delegation_id` linkage and issuer/subject continuity;
4. recompute the 26-field message **from `oracle_input`**, recompute the EIP-712
   digest → `eip712_digest_hex`, and verify the secp256k1 signature against
   `roles.evm_attester.address`;
5. derive the composite-gate reason set from the observable signals (verdict,
   policy deny, evidence digest, inner verification, revocation, delegation
   time window) and assert it **exactly equals** `expectReasons`;
6. assert `allowed ⇔ (derived reasons empty)`.
   Flipping `oracle_input.verdict`, emptying `revocation`, replacing
   `expectReasons`, or flipping `expected` on any vector FAILS the run.

`verify-consistency.ts` (same directory) is the deterministic comparison that
produces the "56/56" figure: the four ABI-keccak commitments rebuilt from
`oracle_input` (13 × 4) plus digest + secp256k1 verification on the positive
vectors (2 × 2).

## Vector catalog

| id | expected | what it exercises |
|---|---|---|
| pass / caution | allowed | clean PASS / CAUTION (both permitted verdicts) |
| danger / block | halt | negative oracle verdicts fail closed |
| expired-oracle | halt | validly signed but past the 600s window |
| tampered-oracle | halt | signed data modified after signing (UID mismatch) |
| wrong-signer | halt | attester address ≠ signer |
| authority-denied | halt | policy returned deny |
| sig-tampered | halt | decision receipt signature corrupted |
| digest-mismatch | halt | evidence_refs digest ≠ artifact |
| evidence-missing | halt | no oracle evidence ref at all |
| delegation-expired / delegation-revoked | halt | authority lapsed / revoked |

Replay / single-use enforcement is stateful and is **not** exercised by this
vector set: dispatch-time enforcement is out of scope for this family.

## Generating

```bash
npm run fixtures:oracle-safety-check   # regenerate oracle-safety-check-v1/ (dev artifact)
```

Publish / regenerate the committed vectors at
`aps-conformance-suite fixtures/cross-stack/oracle-safety-check/`, then run its
`verify.ts` and `verify-consistency.ts`.
