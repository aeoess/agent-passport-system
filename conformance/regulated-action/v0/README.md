# APS Regulated Action Profile v0 conformance vectors

Profile: `aps-regulated-action-v0`. Principle: Reconciled Action Attestation.

A regulated action (action class rank >= 3) reaches finality only when a pre-committed intent
reconciles against two anchors **outside the operator trust domain**: the IdP authority
(EMA, built on ID-JAG, an IETF draft) and the resource system of record. The verifier counts
trust **domains**, not signatures: an agent, its gateway, and its evidence store are one domain.

## What is here

- `vectors.json`: 33 frozen vectors. 31 are **verifier-surface** (they exercise the
  deterministic disposition function); 2 are **completeness-surface** (V20, V21) and are
  validated by the private gateway completeness layer, not the stateless verifier.
- `verify.mjs`: runs the verifier-surface vectors against the built SDK
  (`RegulatedActionV0.verifyRegulatedAction`). Build first: `npm run build`.
- `verify.py`: an independent, SDK-free reimplementation (pure Python standard library:
  vendored RFC 8032 Ed25519, RFC 8785 JCS, and the 12-guard disposition function). It is a
  cross-language conformance check, not a wrapper around the SDK.
- `generate.mts`: the deterministic generator that produced `vectors.json` with real Ed25519
  signatures and self-checks every vector before writing.

## Run

```
npm run build
node conformance/regulated-action/v0/verify.mjs
python3 conformance/regulated-action/v0/verify.py
```

Both report `31/31 verifier vectors pass`.

## The disposition function

The canonical truth-table is `RAPV0-FROZEN-CONTRACT.md` section B (amended guard order). It is
total, deterministic from explicit inputs, most-dangerous-first, first match wins, and pure
(no network, no wall-clock read, no replay state). It emits `violations[]` for every terminal
condition that held, `missing_evidence[]`, the computed `trust_domain_separation`, the
`authority_basis`, and `authority_replay: not_evaluated`.

Locked invariants the vectors pin:

- `reconciled` and `regulator_grade_for_class` require `computed_domains >= 2` AND `resource_ok`
  AND `temporal_consistent`. A receipt can never assert its way past this from inside one domain.
- A `boundary_attested_weak` resource confirmation can never satisfy `resource_present_valid`,
  even when two domains are presented (V33).
- `self_attested` is terminal: `intent_ok` and `policy_allow` do not override it (V32).
- An operator-anchored copy of an IdP key yields `authority_weak_basis`, never an external
  domain (V18); it is distinct from a forged or expired authority (`authority_invalid`).

## The one claim we make, and its limit

We attest authority, policy-conformance at action time, runtime integrity where measured,
external effect, and procedural regularity. We do not certify the correctness of a discretionary
judgment. `judgment_correctness` is always `not_claimed`.

A transparency anchor provides non-equivocation, not truth (it is SCITT-shaped, per
draft-ietf-scitt-architecture). It proves the log did not show different histories to different
parties; it does not prove the logged statement is true.

## Honest scope of v0

This is the public, stateless **verifier** and its conformance vectors. The reconciliation
engine, the forced chokepoint, the lifecycle state machine, the Boundary Attestation Node, the
transparency publisher, and the completeness/orphan layer are the private gateway and are not in
this repository. In the reference gateway build the BAN runs at level_1 (`boundary_attested_weak`),
so the live end-to-end honest path returns `intent_precommitted`, not `reconciled`. A `reconciled`
finality requires a level_2 BAN deployment (a separate signing principal the gateway uid cannot
ptrace), which is an enterprise deployment decision.
