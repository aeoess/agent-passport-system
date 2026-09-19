# APS decision inputs for the PriorSeal sibling adapter

Committed producer inputs for the composition discussed in
[agent-passport-system#163](https://github.com/aeoess/agent-passport-system/issues/163).
Four cases, `permit`, `narrow`, `deny` and `expired`, produced at the `v6.0.1` tag and
checked against `agent-passport-system@6.0.1` as installed from the npm registry.

An adapter loads these bytes, verifies them through the package root, and carries the
`decision_ref` of `policy-decision-receipt.json` as an opaque value. It does not regenerate them.
Nothing in the 6.0.1 package root constructs a bound `decision_ref`, which is why the
generator lives in this repository and the adapter only consumes its output.

## Files

| File | Content |
|---|---|
| `cases/<name>/action-intent-receipt.json` | The signed `aps:action-intent:v1` receipt, as its own file so the bytes can be verified as serialized. |
| `cases/<name>/policy-decision-receipt.json` | The signed `aps:policy-decision:v1` receipt carrying the bound `decision_ref`. |
| `cases/<name>/decision-evidence.json` | The `DecisionEvidenceV1` operand for `verifyReceiptWithDecisionV1`. |
| `cases/<name>/case.json` | Summary, `requested_call`, the `aps-action-ref-v2` input whose digest is `action_ref`, `effective_authority`, and `expected`. |
| `keys.json` | Public verification keys and the suggested reference time. |
| `MANIFEST.sha256` | SHA-256 of every file above, over the exact committed bytes. |
| `generate-fixtures.ts` | Producer side. Uses SDK internals. `--check` regenerates in memory and fails on any drift. |
| `verify-from-package-root.mjs` | Consumer side. Imports only `agent-passport-system`. |

## Keys

`keys.json` sits in the same repository as the artifacts it verifies and has the same author.
Verifying the cases against it shows that the set is internally consistent. It says nothing
about who is entitled to sign. An adapter copies the three public keys into its own pinned
configuration and resolves keys from there. `verify-from-package-root.mjs` does the same and
only checks `keys.json` against its pins.

## Record shapes

The receipts follow draft-pidlisnyi-aps-03 Section 5.3.

The action intent has `receipt_type` `aps:action-intent:v1`. The agent is both `issuer` and
`subject_agent` and signs with the agent key. `prev` and `decision_ref` are absent.
`result` is exactly `aps-action-intent-result-v1` with status `declared`.

The policy decision has `receipt_type` `aps:policy-decision:v1`. The enforcement boundary is
the `issuer` and signs with its own key. `prev` is the intent `receipt_id`. `result` is the
same `CoreDecisionOutputV1` object that appears in `decision_evidence.decision_output`.
This is the receipt to pass to `verifyReceiptWithDecisionV1`.

`delegation_ref` on both receipts is the `delegation_id` of one root `AuthorityDelegationV1`
record from `did:example:principal` to `did:example:agent`. The full record sits in
`authority_state.selected_chain` of the decision evidence and verifies with
`verifyAuthorityDelegationChain`. `authority_state` also carries the authority basis, one
revocation observation and the spend state, the four members Section 5.4 requires.

`verifyReceiptV1` in 6.0.1 checks the generic `ReceiptV1` shape and the signatures. It does
not enforce the per type rules of Section 5.3, so the consumer script asserts those itself.

## What each case returns

Reference time in `keys.json` is `2026-09-19T10:05:00.000Z`. Decision receipts are issued at
`2026-09-19T10:00:01.000Z`.

| Case | `verifyReceiptWithDecisionV1` | `valid_until` | Unexpired at reference time |
|---|---|---|---|
| `permit` | `valid: true` | `10:10:00.000Z` | yes |
| `narrow` | `valid: true` | `10:10:00.000Z` | yes |
| `deny` | `valid: false`, `decision_ref_bound: true`, errors `["valid_until_absent"]` | `null` | not applicable |
| `expired` | `valid: true` | `10:01:00.000Z` | no |

Two of these rows need a plain statement.

`deny` never returns `valid: true` from the 6.0.1 composite verifier. The signature holds and
the decision binds, then the temporal stage stops because a deny has no validity window. An
adapter that gates on `valid === true` rejects a deny at that gate. The binding result is
still available in `decision_ref_bound` for a report that wants to show the deny was
authentic.

`expired` returns `valid: true`. The composite verifier establishes that `valid_until` is
later than the receipt `issued_at`. It does not look at the current time. Whether the
decision is still current at the reference time is the adapter's check, and this case
exists to make that check fail.

## What these inputs do not establish

- The `narrow` constraint strings, `fixture:evm.to=...` and `fixture:evm.value_wei<=...`,
  are fixture-local. Receipt core treats constraints as opaque strings. It normalizes them to
  NFC, removes duplicates and sorts them. APS 6.0.1 assigns them no semantics, so any
  mapping to an exact-call predicate belongs to the adapter.
- Draft-03 Section 5.3.2 fixes the shape of `effective_authority_ref` and does not define
  its construction, so both forms used here are local to these inputs. For `permit` and
  `expired` the admitted authority is the leaf delegation unchanged, and the ref is the hex
  of its `delegation_id`, the same choice the `oracle-safety-check` fixtures in this
  repository make. For `narrow` the ref is SHA-256 over
  `APS-163-FIXTURE-EFFECTIVE-AUTHORITY-V1`, a zero byte, and the JCS bytes of the `value`
  object in `case.json`. Neither form is an APS rule.
- The scope grant and the action type are both `fixture:evm:call`. APS 6.0.1 defines no EVM
  scope namespace or action type.
- `action_ref` is not recomputed by the consumer script, because `computeActionRefV2` is not
  exported from the 6.0.1 package root. The generator computes it from the committed
  `action_reference_input`. `decision_ref` is recomputed, inside the composite verifier.
- The policy identifier, the policy input, the decision context and the spend state are
  synthetic. A matching `decision_ref` shows that the same component values were named. It
  does not show that a policy was correct or that its inputs were complete.
- Revocation is recorded as one `active` observation inside `authority_state`. Nothing here
  supports a claim about live revocation state.
- Verification does not consume `receipt_id` and does not enforce single use. Two
  authorizations can carry the same verified `decision_ref`.
- All keys are test keys derived from public labels in the generator. They protect nothing.

## Reproduce

Producer side, from the repository root at this commit:

```
NODE_ENV=development npm ci --include=dev
npx tsx fixtures/priorseal-decision-binding/generate-fixtures.ts --check
```

Consumer side, from any empty directory:

```
npm init -y
npm install --save-exact agent-passport-system@6.0.1
node /path/to/verify-from-package-root.mjs /path/to/fixtures/priorseal-decision-binding
```

The consumer script exits 0 only when every manifest digest matches, both receipts of every
case verify from their committed bytes, the Section 5.3.1 and 5.3.2 assertions hold, all four
cases return the results in the table, and the delegation chain verifies. It also runs four
negatives. An unresolved key and a wrong key fail at `receipt_invalid`, evidence from another
case fails at `decision_ref_mismatch`, and a duplicated member in the bytes fails at
`parse_error`.
