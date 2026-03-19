# RFC: Cross-Engine Signed Execution Envelope

**Status:** Draft
**Author:** Tymofii Pidlisnyi (tima@aeoess.com)
**Created:** 2026-03-17
**SDK Reference:** `agent-passport-system` v1.13.0 (npm)

## Problem

Multiple governance engines are emerging for AI agent systems — CrewAI, AutoGen/Guardian, Agent Identity Protocol (AIP), Agent Passport System (APS), and others. Each implements its own decision and execution records. When agents from different frameworks interact, there's no way to exchange verifiable governance evidence across engine boundaries.

Three independent conversations arrived at the same conclusion in March 2026:

- **@Kelisi808** on [crewAIInc/crewAI#4560](https://github.com/crewAIInc/crewAI/issues/4560): proposed a shared signed execution envelope with 7 minimum fields
- **@xsa520** on [xsa520/guardian#2](https://github.com/xsa520/guardian/issues/2): proposed separating decision artifacts from execution receipts for independent verifiability
- **@ngallo** on [decentralized-identity/trustworthy-autonomous-agents#3](https://github.com/decentralized-identity/trustworthy-autonomous-agents/issues/3): raised Proof of Continuity vs Proof of Possession — what properties should the envelope guarantee?

This RFC proposes a minimal signed execution envelope that any governance engine can emit and any verifier can check, without requiring adoption of a specific trust backend.

## Design Principles

1. **Minimal fields.** Only what a verifier needs to independently check the governance chain.
2. **Engine-agnostic.** No dependency on any specific policy engine, trust model, or delegation scheme.
3. **Cryptographically verifiable.** Every envelope is signed. Verifiers need nothing beyond the public key and the envelope itself.
4. **Composable, not prescriptive.** Engines can embed additional engine-specific metadata. The envelope defines the interop surface, not the internal implementation.

## Envelope Schema (v0.1)

```json
{
  "schema": "execution-envelope.v0.1",

  "agent_did": "did:aps:abc123...",
  "run_id": "task-2026-03-17-001",
  "action_id": "action-purchase-widget",

  "capability_ref": {
    "manifest_hash": "sha256:9f86d08...",
    "scope": ["commerce:purchase", "commerce:checkout"],
    "delegation_chain_depth": 2,
    "revocation_status": "active"
  },

  "decision": {
    "decision_hash": "sha256:4e1bc7a...",
    "policy_ref": "floor-v0.2+commerce-gate-v1",
    "evaluation_method": "deterministic",
    "verdict": "permit",
    "narrowing": null,
    "evaluated_at": "2026-03-17T04:00:00Z",
    "evaluator_did": "did:aps:evaluator-001",
    "evaluator_signature": "base64:..."
  },

  "attestation": {
    "receipt_hash": "sha256:7c211e8...",
    "receipt_type": "PolicyReceipt",
    "chain_signatures": {
      "intent": "base64:...",
      "decision": "base64:...",
      "receipt": "base64:..."
    }
  },

  "timestamp": "2026-03-17T04:00:01Z",

  "signature": {
    "algorithm": "Ed25519",
    "public_key": "base64:...",
    "value": "base64:..."
  }
}
```

## Field Definitions

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `schema` | string | yes | Schema version identifier |
| `agent_did` | string | yes | DID of the agent that executed the action |
| `run_id` | string | yes | Unique identifier for the task/run context |
| `action_id` | string | yes | Unique identifier for this specific action |
| `capability_ref.manifest_hash` | string | yes | Hash of the capability manifest (delegation scope) at evaluation time |
| `capability_ref.scope` | string[] | yes | Delegation scopes that authorized this action |
| `capability_ref.revocation_status` | string | yes | `active` or `revoked` at execution time |
| `decision.decision_hash` | string | yes | Hash of the full policy decision object |
| `decision.policy_ref` | string | yes | Identifier + version of the policy that produced the decision |
| `decision.evaluation_method` | string | yes | `deterministic` or `probabilistic` — whether the decision is replayable |
| `decision.verdict` | string | yes | `permit`, `deny`, `narrow`, or `audit` |
| `decision.evaluated_at` | string | yes | ISO 8601 timestamp of evaluation |
| `decision.evaluator_signature` | string | yes | Signature of the evaluator over the decision |
| `attestation.receipt_hash` | string | yes | Hash of the execution receipt |
| `attestation.chain_signatures` | object | conditional | Full signature chain (if engine supports multi-signature) |
| `timestamp` | string | yes | ISO 8601 timestamp of envelope creation |
| `signature` | object | yes | Ed25519 (or compatible) signature over the canonical envelope |

## `evaluation_method` — The Critical Interop Field

This field determines what a verifier can and cannot do with the decision:

- **`deterministic`**: The decision can be replayed. Given the same intent, policy version, and context, the same verdict is guaranteed. Verifiers can independently recompute and confirm. (Example: APS FloorValidatorV1, YAML-based policy engines, Cedar/OPA evaluators)
- **`probabilistic`**: The decision was produced by a non-deterministic evaluator (e.g., LLM-based reasoning). The verdict is a good-faith assessment, not a reproducible computation. Verifiers can check the signature but cannot replay the evaluation. (Example: LLM-based advisory layer, F-006/F-007 in APS)

Different trust levels apply. A `deterministic` decision with a valid signature is independently verifiable. A `probabilistic` decision with a valid signature proves that *an evaluation happened*, but not that the same evaluation would produce the same result.

## Governance Gate Rules

Any system consuming these envelopes should enforce at minimum:

| Rule | Envelope check |
|------|---------------|
| No privileged action without verified governance | `signature.value` must verify against `signature.public_key` |
| No delegation on stale or revoked credentials | `capability_ref.revocation_status` must be `active` |
| No execution without policy evaluation | `decision.decision_hash` must be non-null and `decision.evaluator_signature` must verify |
| Deny on expired evaluation | `decision.evaluated_at` must be within acceptable time window |

## Mapping to Existing Implementations

### Agent Passport System (APS) — already ships all fields

| Envelope field | APS type | SDK function |
|---------------|----------|-------------|
| `agent_did` | `AgentPassport.agentId` | `createPassport()` |
| `run_id` | `TaskBrief.taskId` | `createTaskBrief()` |
| `action_id` | `ActionIntent.intentId` | `createActionIntent()` |
| `capability_ref.manifest_hash` | hash of `Delegation.scope` | `createDelegation()` |
| `capability_ref.revocation_status` | `validateChain()` result | `validateChain()` |
| `decision.decision_hash` | hash of `PolicyDecision` | `evaluateIntent()` |
| `decision.policy_ref` | `PolicyDecision.floorVersion` | `evaluateIntent()` |
| `decision.evaluation_method` | deterministic for F-001..F-005, probabilistic for F-006..F-008 | `FloorValidatorV1` |
| `decision.verdict` | `PolicyDecision.verdict` (`permit`/`deny`/`narrow`) | `evaluateIntent()` |
| `decision.evaluator_signature` | `PolicyDecision.signature` | `evaluateIntent()` |
| `attestation.chain_signatures` | `PolicyReceipt.chain` (intent + decision + receipt) | `createPolicyReceipt()` |
| `signature` | Ed25519 via `node:crypto` | `sign()` |

### Guardian (xsa520) — decision-artifact-centric model

| Envelope field | Guardian equivalent |
|---------------|-------------------|
| `action_id` | Action being evaluated |
| `decision.decision_hash` | Decision artifact hash |
| `decision.policy_ref` | Policy version/hash referenced in decision record |
| `decision.evaluation_method` | Deterministic (rule-based evaluation) |
| `attestation` | Evidence record referencing the decision |

Guardian's decision-artifact-centric model maps naturally: their independent decision record becomes the `decision` block, their evidence record becomes the `attestation` block.

### CrewAI / General MCP Agents — @Kelisi808's envelope

| Envelope field | Kelisi808's proposed field |
|---------------|--------------------------|
| `agent_did` | `agent_did` |
| `run_id` | `run_id` |
| `action_id` | `task_id` |
| `capability_ref.manifest_hash` | `capability_manifest_hash` |
| `decision.decision_hash` | `decision_hash` |
| `attestation` | `attestation_ref` |
| `timestamp` | `timestamp` |

The envelope in this RFC is a strict superset of Kelisi808's 7-field proposal, adding the decision metadata needed for independent verification.

## Open Questions

1. **Canonicalization:** RFC 8785 (JCS) for JSON canonicalization before signing? Or engine-specific? JCS is the standard choice but not all engines may support it. (Nanook/PDR uses RFC8785; APS uses custom sorted-key canonical form.)

2. **Signature format:** Raw Ed25519 detached signature (current APS approach) vs COSE/JWS wrapper? JWS is more portable; raw Ed25519 is simpler and faster. Could support both with a `signature.format` field.

3. **DID method:** The `agent_did` field assumes a DID. Should the spec mandate a specific DID method, or accept any resolvable identifier? Current implementations use `did:aps:`, `did:aip:`, `did:key:`, and plain public keys.

4. **Expiry semantics:** Should the envelope include a `decision.expires_at`? APS currently time-limits PolicyDecisions. If an envelope's decision has expired, should verifiers treat it as void or as stale-but-informative? (Same question Nanook raised for PDR score events.)

5. **Minimal vs full:** Is the `attestation.chain_signatures` block required, or only for engines that support multi-signature chains? Engines with a single evaluator signature would populate only `decision.evaluator_signature`.

6. **Non-deterministic environments:** As raised by @ngallo — can Proof of Continuity be defined when the execution environment is non-deterministic? The `evaluation_method` field acknowledges this split but doesn't resolve it.

## Next Steps

- [ ] Feedback on field definitions from Guardian, CrewAI, DIF TAA participants
- [ ] Reference implementation: `createExecutionEnvelope()` in APS SDK
- [ ] JSON Schema (formal, validatable)
- [ ] Test vector: signed envelope that any implementation can verify
- [ ] Cross-engine verification test: APS-generated envelope verified by Guardian, and vice versa

## Related Discussions

- [crewAIInc/crewAI#4560](https://github.com/crewAIInc/crewAI/issues/4560) — @Kelisi808's execution envelope proposal
- [xsa520/guardian#2](https://github.com/xsa520/guardian/issues/2) — Decision-artifact-centric governance model
- [decentralized-identity/trustworthy-autonomous-agents#3](https://github.com/decentralized-identity/trustworthy-autonomous-agents/issues/3) — PoC vs PoP, confused deputy, non-deterministic environments
- [microsoft/autogen#7372](https://github.com/microsoft/autogen/issues/7372) — Shared decision artifacts across governance engines
- [anthropics/claude-code#32514](https://github.com/anthropics/claude-code/issues/32514) — Runtime-injected identity (transport layer prerequisite)
