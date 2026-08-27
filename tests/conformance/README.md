# APS conformance golden negative-fixture package

A frozen set of fixtures a conformant APS verifier must agree on. The
package has two halves:

- **Golden valid fixture.** A clean `aps:action:v1` receipt that verifies
  under the shipped Ed25519 and RFC 8785 JCS code path. Its canonical JCS
  preimage and the SHA-256 of that preimage (the `receipt_id`) are pinned
  in the fixture, so a third-party implementation can byte-match without
  re-running the TypeScript signer.
- **Negative fixtures.** Each one is built to fail verification for
  exactly one stated reason. The reason travels with the fixture, so a
  conformance run asserts *why* the rejection happened, not only *that* it
  happened.

## Why negatives matter

A verifier that accepts the golden valid receipt has shown it can parse
and check a signature. It has not shown it rejects the receipts a real
attacker sends. The negatives below are the receipts an honest verifier
must turn away.

## Layers

Verification runs in two layers, in order:

1. **Crypto layer** (`verifyActionReceipt`). Closes three modes: wrong
   `claim_type`, `receipt_id` that does not match the canonical body
   (tampered or mismatched-hash), and an Ed25519 signature that does not
   verify under `signer_did`.
2. **Context layer** (`verifyReceiptContext`). The signature is sound but
   the receipt is being used outside the envelope it was issued for:
   expired delegation, revoked delegation, over budget, wrong principal,
   stale policy version, replay, or presented as a claim it never made.

A tampered or unsigned receipt is rejected at the crypto layer before any
context is consulted.

## Fixtures

| Fixture | Reason | Layer |
|---|---|---|
| `GOLD-VALID-001` | verifies clean | both |
| `NEG-SIGNATURE-INVALID` | `SIGNATURE_INVALID` | crypto |
| `NEG-MISMATCHED-HASH` | `RECEIPT_ID_MISMATCH` | crypto |
| `NEG-WRONG-CLAIM-TYPE` | `INVALID_CLAIM_TYPE` | crypto |
| `NEG-DELEGATION-EXPIRED` | `DELEGATION_EXPIRED` | context |
| `NEG-STALE-REVOCATION` | `DELEGATION_REVOKED` | context |
| `NEG-OVER-BUDGET` | `OVER_BUDGET` | context |
| `NEG-WRONG-PRINCIPAL` | `WRONG_PRINCIPAL` | context |
| `NEG-STALE-POLICY` | `STALE_POLICY` | context |
| `NEG-REPLAYED` | `REPLAYED` | context |
| `NEG-WRONG-CLAIM` | `WRONG_CLAIM` | context |
| `NEG-POLICY-NOT-EXECUTED` | `POLICY_NOT_EXECUTED` | context |
| `NEG-UNVERIFIED-EXTERNAL-EVIDENCE` | `WRONG_CLAIM` | context |
| `NEG-DELEGATION-ROOT-MISMATCH` | `DELEGATION_ROOT_MISMATCH` | context |

The on-disk JSON lives in `golden-fixtures/`. `INDEX.json` is the manifest
a cross-implementation harness reads first.

## Regenerating

```bash
npx tsx tests/conformance/write-fixtures.ts
```

The test suite (`conformance-negatives.test.ts`) re-derives every fixture
from `generate.ts` and asserts the on-disk JSON is byte-identical, so the
JSON can never silently drift from the code path that produced it.

## Scope of claim

Proves: the SDK verifier accepts the golden valid receipt and rejects
each negative for its cited reason, and the pinned `receipt_id` matches
its canonical preimage.

Does not prove: that the receipts describe real-world events, that a
signer's key was honestly held, or that any off-protocol side effect
actually occurred. A receipt is a signed declaration about what the
system observed, not a causal proof of agent cognition or outcome.
