# OM World — Composability

[OM World](https://github.com/omworldprotocol/om-world) is an open protocol for a decentralized intent economy. Its [Agent Mandate](https://github.com/omworldprotocol/om-world/blob/main/docs/agent-mandate.md) and [Execution Proof](https://github.com/omworldprotocol/om-world/blob/main/docs/execution-proof.md) primitives converged independently with `agent-passport-system` on two design rules. This document captures the mapping so implementations on either side can interoperate without re-deriving it.

> Drafted by OM World per the design dialogue in [agent-passport-system#28](https://github.com/aeoess/agent-passport-system/issues/28). `agent-passport-system` is listed as a Genesis Co-author of OM World's Agent Mandate spec ([CONTRIBUTORS.md](https://github.com/omworldprotocol/om-world/blob/main/CONTRIBUTORS.md)).

## 1. Canonical-form-as-identity (the load-bearing convergence)

Both systems compute a content-addressed identifier over the **RFC 8785 (JCS)** canonical form of a structured record, and both use that identifier as a dedup / linkage key.

| | agent-passport-system | OM World Execution Proof |
|---|---|---|
| Identifier | action identifier = `SHA-256(JCS(action tuple))` | step hash = `SHA-256(JCS(step_record_without_prev_hash))` |
| Doubles as | dedup key — a verifier tracking seen identifiers within the relevant window rejects duplicates | `prev_hash` linkage key — each step's record carries the prior step's hash |
| Canonicalization | RFC 8785 JCS | RFC 8785 JCS ([execution-proof.md §Canonicalization](https://github.com/omworldprotocol/om-world/blob/main/docs/execution-proof.md#canonicalization)) |
| Replay defense | seen-identifier set within validity window + delegation expiry | seen-identifier set + chained `prev_hash` |

The two arrived at the same rule — *the canonical form of the record IS its identity* — from different starting points (passport from action receipts, OM World from execution-proof step linkage). That is the strongest interop signal: a verifier implementing JCS-over-the-record once can check identity/dedup for both. OM World's [§Canonicalization](https://github.com/omworldprotocol/om-world/blob/main/docs/execution-proof.md#canonicalization) additionally pins an **absent-optional-fields rule** (a missing optional field is omitted from the JCS input, never serialized as `null`) — worth a cross-check against passport's action-tuple serialization to confirm the two produce bit-identical canonical forms for the shared fields.

## 2. Root identity + delegation chain

`agent-passport-system`'s model — a root Ed25519 identity issues scoped delegations; operational keys are short-lived delegated credentials; the receipt carries the delegation path so a verifier walks back to the root without the root key touching the hot path — shaped OM World's [Agent Mandate §Identity model](https://github.com/omworldprotocol/om-world/blob/main/docs/agent-mandate.md#identity-model--root--delegation-chain). OM World's mandate `agent` field is the durable root referent for slashing/reputation/audit; payload signatures chain back to it.

The **monotonic narrowing** invariant (authority strictly decreases per delegation step, enforced by a real scope-covering predicate rather than a set-membership shortcut) and the **issuance-vs-runtime split** (structural narrowing checked at issuance, runtime satisfaction checked per concrete action) shaped OM World's [§Scope narrowing](https://github.com/omworldprotocol/om-world/blob/main/docs/agent-mandate.md#scope-narrowing--monotonic-invariant--issuancevsruntime-split). Both are documented as load-bearing on the OM World side with attribution to passport-system's production experience.

## 3. Field mapping (passport action tuple ↔ OM World step record)

| passport action tuple | OM World Step record | Notes |
|---|---|---|
| action identifier (`SHA-256(JCS(...))`) | `step_hash` / `prev_hash` linkage | same construction; passport uses it as dedup key, OM World as chain linkage |
| delegation path on receipt | mandate `agent` root + delegation chain | OM World records the chain; verifier walks to root |
| validity window / delegation expiry | `tools_declared[*].expiry`, `mandate.deadline` | freshness on the authority side |
| returned-evidence reference | `output_hash` (+ `context_hash` for stateful tools) | OM World separates stateful-tool snapshot into `context_hash` |

## Cross-reference

- OM World Agent Mandate: [`docs/agent-mandate.md`](https://github.com/omworldprotocol/om-world/blob/main/docs/agent-mandate.md) — §Identity model, §Scope narrowing
- OM World Execution Proof: [`docs/execution-proof.md`](https://github.com/omworldprotocol/om-world/blob/main/docs/execution-proof.md) — §Canonicalization, §Related work (lists this project)
- IETF draft: [`draft-pidlisnyi-aps`](https://datatracker.ietf.org/doc/draft-pidlisnyi-aps/) — the 4-field preimage and canonical form
