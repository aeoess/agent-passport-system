# Capability Token Specification (Draft)

**Status:** discussion draft, v0.1
**Scope:** wire-format specification for the APS-aware closure stack described in `docs/ENFORCEMENT-TRUST-ANCHOR.md` Components 1 through 4
**Target:** APS v3.0, no fixed date

## Overview

This document specifies the message formats, signing order, and failure semantics for the capability-token protocol that instantiates the APS-aware enforcement closure stack. It is the protocol-level companion to `ENFORCEMENT-TRUST-ANCHOR.md`.

The construction implements the architectural claim that the gateway must stop being the component that both describes the action and originates the usable authority for it. Four actors participate in every enforcement cycle: the delegator (mints authority), the subject (requests actions), the sink (defines canonical action semantics and witnesses effects), and the gateway (evaluates policy against the sink-defined action, consuming authority minted by the delegator).

The gateway retains its role as policy-evaluation layer. It loses its role as authority-issuance layer and its role as enforcement-witness layer. Those responsibilities move to the delegator and the sink respectively.

## Design Goals

**G1.** Make gateway self-attestation unnecessary for the within-scope enforcement-decision property. A compromised gateway with a valid signing key cannot produce a receipt that a verifier will admit as attestation of enforcement.

**G2.** Preserve cryptographic provenance guarantees of v2.x. Delegation chains, passport bindings, issuer signatures, monotonic narrowing, and cascade revocation all compose with the new protocol without regression.

**G3.** Require no changes to subject agent runtime beyond the ability to carry four small additional fields per action. Subjects already sign and forward authorization envelopes.

**G4.** Be honest at the wire-format level about what is closed versus witnessed versus unresolved. Typed epistemic receipts are enforced by schema, not by documentation convention.

**G5.** Degrade gracefully to the v2.x bilateral-receipt hardening path when one of the four actors (specifically the sink) cannot be upgraded. The same receipt format carries both classes of claim; the typed-epistemic labels distinguish which claims are structurally closed versus only witnessed.

## Actors and Trust Assumptions

**Delegator (D).** Issues delegations via the existing APS delegation chain. New in this protocol: mints `ConsumableAuthorityToken` objects at delegation time, bound to a Merkle root committed in the delegation envelope. The delegator's Ed25519 key is the authority root. Compromise of the delegator key is outside the threat model this protocol addresses; it is addressed by v2.x delegation chain mechanisms (rotation, revocation, succession).

**Subject (S).** The agent requesting actions. Holds its passport-bound Ed25519 key and the delegator-issued token set. New in this protocol: requests sink challenges, reveals consumable authority tokens for specific actions, forwards signed objects between the sink and the gateway. The subject's key compromise composes with gateway compromise as noted in the triple-collusion residual in `ENFORCEMENT-TRUST-ANCHOR.md`.

**Sink (K).** The resource server executing the action. New in this protocol: issues canonical action challenges, maintains a nullifier set of consumed token preimages, emits sink-signed effect receipts. The sink's Ed25519 key is the attestation root for the enforcement-boundary property (the property v1.1 of the trust-anchor doc identifies as not closed by v2.x). Sink compromise is the primary residual threat this protocol does not close.

**Gateway (G).** Evaluates policy against the sink-authored challenge. New in this protocol: signature over policy evaluation binds exactly to the sink's challenge hash, cannot unilaterally introduce semantic drift. The gateway's key compromise is the threat model this protocol addresses.

## Message Types

Four message types define the protocol. Each is an object with explicit schema; all signatures are Ed25519 over the JCS (RFC 8785) canonical serialization of the object excluding the signature field itself.

### M1: SinkChallenge (K → S)

Issued by the sink in response to a subject's action intent. Defines the canonical statement of the action.

```
{
  "type": "aps.capability.v1.SinkChallenge",
  "sink_id": "<sink DID>",
  "subject_id": "<subject DID>",
  "action": {
    "kind": "<canonical action type>",
    "target": "<resource URI>",
    "parameters": { ... },
    "resource_version": "<opaque sink-version identifier>"
  },
  "nonce": "<32-byte base64url>",
  "issued_at": "<ISO 8601 UTC>",
  "expires_at": "<ISO 8601 UTC>",
  "required_policy_freshness": {
    "max_age_seconds": <integer>,
    "beacon_hash_required": true | false
  },
  "sink_signature": "<Ed25519 over canonical serialization>"
}
```

**Verification.** Subject and gateway both verify `sink_signature` against the sink's JWKS-published public key. The challenge hash (SHA-256 over the canonical serialization excluding `sink_signature`) is the canonical action identifier used in all subsequent messages.

**Failure semantics.** An expired challenge is refused at the sink during redemption. An unsigned or malformed challenge cannot produce a valid `ChallengeReceipt` because the gateway's signature must bind to a specific hash. The sink's `resource_version` protects against stale actions where resource state changed between challenge issuance and redemption.

### M2: AuthorityEvaluationRequest (S → G)

Subject submits the signed challenge, the delegation chain, and reveals one consumable authority token to the gateway for policy evaluation.

```
{
  "type": "aps.capability.v1.AuthorityEvaluationRequest",
  "challenge": <SinkChallenge object>,
  "delegation_chain": [<DelegationEnvelope>, ...],
  "delegation_chain_root": "<32-byte hash>",
  "delegation_depth": <integer>,
  "authority_token": {
    "token_preimage": "<32-byte base64url>",
    "merkle_proof": [<sibling hash>, ...],
    "scope_class": "<canonical scope identifier>"
  },
  "freshness_beacon": {
    "delegator_id": "<delegator DID>",
    "beacon_timestamp": "<ISO 8601 UTC>",
    "beacon_signature": "<Ed25519>"
  },
  "subject_signature": "<Ed25519 over canonical serialization>"
}
```

**Verification.** Gateway verifies the subject's signature, validates the challenge signature, walks the delegation chain (v2.x mechanism, unchanged), verifies the Merkle proof of `token_preimage` against the `authority_token_merkle_root` committed in the delegation envelope, checks the freshness beacon against the challenge's `required_policy_freshness` constraint, and checks the delegation chain depth bounds.

**Failure semantics.** Any signature failure, chain walk failure, Merkle proof failure, or freshness failure causes the gateway to return a signed denial (M4 below with `epistemic_type: closed` and `decision: deny`) rather than a permit. A compromised gateway cannot forge a valid `ChallengeReceipt` against a scope class not covered by a minted token, because the token Merkle root was signed by the delegator at delegation time.

### M3: ChallengeReceipt (G → S → K)

Gateway emits a signed evaluation over the sink's exact canonical challenge. The subject forwards this to the sink as proof of authorization.

```
{
  "type": "aps.capability.v1.ChallengeReceipt",
  "challenge_hash": "<SHA-256 of the SinkChallenge canonical serialization>",
  "decision": "permit" | "deny",
  "deny_reason": "<string, present only when decision=deny>",
  "delegation_chain_root": "<32-byte hash>",
  "delegation_depth": <integer>,
  "authority_token_preimage": "<32-byte base64url, present only when decision=permit>",
  "evaluated_at": "<ISO 8601 UTC>",
  "policy_digest": "<SHA-256 of the policy bundle used in evaluation>",
  "epistemic_claims": {
    "policy_evaluated": "closed",
    "authority_consumed": "closed",
    "scope_within_bounds": "closed",
    "effect_occurred": "unresolved"
  },
  "gateway_signature": "<Ed25519 over canonical serialization>"
}
```

**Verification.** Sink verifies `gateway_signature` against the gateway's JWKS, confirms `challenge_hash` matches the challenge the sink originally issued, checks `authority_token_preimage` against its nullifier set (rejecting if already consumed), and applies its own policy-digest acceptance rules.

**Typed epistemic claims.** The `epistemic_claims` object is load-bearing. `policy_evaluated`, `authority_consumed`, and `scope_within_bounds` are labeled `closed` because they are verifiable from the receipt alone against the gateway's public key, the delegator's authority token Merkle root, and the canonical challenge. `effect_occurred` is labeled `unresolved` because no party has yet attested to the effect; only the sink's subsequent `EffectReceipt` (M4) can upgrade that label to `witnessed`. A verifier that treats `unresolved` claims as closed is violating the protocol semantics.

**Failure semantics.** A compromised gateway that fabricates a receipt for a challenge the sink never issued produces a receipt with a `challenge_hash` no sink will recognize. A gateway that fabricates a receipt with a token preimage not in the delegator's Merkle root produces a receipt that fails the sink's nullifier check only after the sink's verification of the token preimage against the delegation-chain-rooted authority Merkle root. The sink verifies this because the delegation chain is carried forward through the subject, not through the gateway alone.

### M4: EffectReceipt (K → S, optionally published)

After executing the authorized action, the sink emits a signed receipt binding the consumed token to the actual effect. This is the attestation that enforcement occurred.

```
{
  "type": "aps.capability.v1.EffectReceipt",
  "challenge_hash": "<SHA-256 of the SinkChallenge, unchanged from ChallengeReceipt>",
  "authority_token_preimage": "<32-byte base64url, unchanged from ChallengeReceipt>",
  "gateway_receipt_hash": "<SHA-256 of the ChallengeReceipt canonical serialization>",
  "effect": {
    "executed_at": "<ISO 8601 UTC>",
    "outcome": "success" | "failure" | "partial",
    "result_digest": "<SHA-256 of the effect result, opaque to APS>"
  },
  "epistemic_claims": {
    "effect_occurred": "closed",
    "effect_result_bound": "closed",
    "policy_evaluation_correct": "witnessed"
  },
  "sink_signature": "<Ed25519 over canonical serialization>"
}
```

**Verification.** Any verifier holding the `ChallengeReceipt` (M3) and `EffectReceipt` (M4) can establish: (a) the sink authored a canonical action challenge, (b) the gateway evaluated policy against that exact challenge under authority minted by the delegator, (c) the action was executed at the sink producing a bound result. The tuple `(SinkChallenge, ChallengeReceipt, EffectReceipt)` is the full attestation record.

**Typed epistemic claims.** `effect_occurred` is upgraded to `closed` because the sink has signed the effect. `effect_result_bound` is `closed` because `result_digest` is in the signed record. `policy_evaluation_correct` remains `witnessed` rather than `closed`: the sink has witnessed that a gateway signed a permit against this challenge, but it cannot by itself verify that the gateway's policy evaluation was semantically correct. Upgrading this claim to `closed` requires composition with a ZK proof of policy evaluation (future work, not in v3.0 scope) or with a replayable deterministic transcript that any verifier can re-execute.

**Failure semantics.** A `ChallengeReceipt` without a matching `EffectReceipt` is a permit that was never exercised; verifiers that require enforcement attestation (as opposed to authorization attestation) must reject these as insufficient. This is the correct behavior, not a bug: an unexercised permit does not attest to enforcement.

## Signing Order Summary

```
S → K:     action intent (unsigned)
K → S:     M1  SinkChallenge              [sink signs]
S → G:     M2  AuthorityEvaluationRequest [subject signs, carries challenge + delegation + token reveal]
G → S:     M3  ChallengeReceipt           [gateway signs]
S → K:     execution request + M3         [subject forwards]
K → S:     M4  EffectReceipt              [sink signs]
```

Four signatures total across the protocol cycle: sink (M1), subject (M2), gateway (M3), sink (M4). Each signs a different proposition. The gateway's M3 signature is not the enforcement attestation; it is the policy-evaluation attestation. M1 and M4 together constitute the enforcement attestation, authored by a party structurally distinct from the policy evaluator.

## Closure Argument

The protocol closes the within-scope forgery surface identified in `ENFORCEMENT-TRUST-ANCHOR.md` Section "The Gap" as follows.

**A compromised gateway cannot describe an action.** The sink issues the canonical challenge (M1). The gateway's M3 signature binds to the sink's challenge hash. A gateway that narrates a different action produces a receipt the sink will not admit.

**A compromised gateway cannot originate authority.** Consumable authority tokens are minted by the delegator and committed to a Merkle root in the delegation envelope. The gateway can only countersign the consumption of tokens the delegator already authorized. Token forgery requires the delegator's key, which is outside the gateway threat model.

**A compromised gateway cannot fake enforcement.** The sink's M4 EffectReceipt is the primary attestation of enforcement. A gateway-only M3 without a matching sink-signed M4 is provably insufficient per the protocol's typed epistemic claims. Verifiers that treat M3 alone as enforcement attestation are violating the protocol.

**What the protocol does not close.** Sink compromise (sink-side effect receipts lie), full three-party collusion among subject, gateway, and sink against an absent delegator, and the read-only residual where M4 has no observable effect to attest. These are documented in `ENFORCEMENT-TRUST-ANCHOR.md` as architectural limits.

## Degradation Path for Dumb Web2 Sinks

The same wire format carries bilateral-receipt hardening for sinks that cannot author canonical challenges or sign effect receipts.

For such deployments:

- M1 is replaced with a subject-authored `CanonicalActionStatement` signed by the subject, with the subject's `epistemic_claims.action_canonicalization` labeled `self-asserted`. This is honest: without the sink as action author, the subject is narrating.
- M2 and M3 are unchanged.
- M4 is replaced by a subject-signed `PostExecutionAcknowledgment` with `epistemic_claims.effect_occurred` labeled `witnessed-by-subject`. The subject attests to what it observed at the sink; this is weaker than sink-signed M4 but narrows the gap from gateway-alone to gateway-plus-subject.

The typed epistemic labels make the degradation explicit. A verifier reading a receipt with `effect_occurred: witnessed-by-subject` rather than `effect_occurred: closed` knows the deployment is using the dumb-sink hardening path and can apply its own risk-tolerance rules.

## Composition with Other APS Mechanisms

**Delegation chain (v2.x).** Unchanged. The `delegation_chain` field in M2 carries the v2.x delegation envelope with all its existing properties (monotonic narrowing, issuer-signed passports, scope tokens). The delegator's signature over `authority_token_merkle_root` is an additional field in the delegation envelope, bounded to a new optional block that does not break backward compatibility.

**Revocation (v2.x).** Cascade revocation mechanisms compose. A revoked delegation invalidates all descendant `AuthorityEvaluationRequest` attempts that reference the revoked delegation chain. The sink's nullifier set does not need to know about revocation; the gateway refuses to sign M3 against a revoked chain, and the subject has no M3 to forward.

**Passport grades (v2.x).** Unchanged. The passport grade of the subject is a property of the delegation chain, verifiable independently of this protocol.

**Behavioral Memory Objects (v2.x).** Compose as a forensic audit overlay per `ENFORCEMENT-TRUST-ANCHOR.md` Component E. BMO evidence can upgrade the sink's `epistemic_claims.policy_evaluation_correct` from `witnessed` to `corroborated` where subsequent behavior confirms the receipt's claimed scope. This is an audit-layer annotation, not a replacement for the cryptographic attestation.

**in-toto Decision Receipt predicate.** The M3 `ChallengeReceipt` and M4 `EffectReceipt` shapes are designed to be expressible as in-toto Decision Receipt predicates once the predicate specification stabilizes at `in-toto/attestation#549`. The `challenge_hash` field maps to the predicate's subject-binding hash; the `epistemic_claims` object maps to a predicate-specific extension. This is the integration path from v2.x bilateral to v3.0 sink-authored.

## Open Design Questions

Questions this draft does not resolve. Each affects the final wire format; each requires implementation input before v3.0 lock.

**Q1: Authority token minting granularity.** Should tokens be one-per-action, one-per-scope-class, or one-per-freshness-window? Finer granularity improves forgery resistance at the cost of delegation envelope size and minting ceremony overhead. Coarser granularity eases operations at the cost of broader consumption windows where a compromised gateway can batch-consume tokens before detection. Initial default proposal: one token per (scope-class, freshness-window), with window scoped to the delegation validity period subdivided by a configurable interval.

**Q2: Sink challenge format ownership.** The protocol assumes sinks can author canonical action challenges. For sinks that cannot, a thin APS proxy issues challenges on the sink's behalf. Where does the proxy sit in the trust topology? Options: (a) co-located with the sink, signed by a key distinct from the sink's operational keys but under the same operator (weak); (b) co-located with the delegator, signed by a delegator-operated service (strong, but re-introduces delegator synchrony); (c) hosted as a neutral third party with sink-specific keys derived via DKG (strongest, most operational complexity). The right answer likely varies per sink class.

**Q3: Offline subject graceful degradation.** Daemon agents acting while disconnected cannot forward M1 to the gateway in real time. Three options: (a) pre-fetched challenges with long expiry, consumed within the validity window, with `freshness_beacon` constraints relaxed per deployment policy; (b) subject-held batched acknowledgments that consume multiple challenges in sequence; (c) fallback to v2.x bilateral-receipt path for offline actions with explicit typed-epistemic labeling that the action did not use the sink-authored closure path. The draft does not yet choose; implementer input is required.

**Q4: Effect receipt publication semantics.** M4 can be returned to the subject only, or additionally published to a transparency log per `ENFORCEMENT-TRUST-ANCHOR.md` Component B. Published receipts support retroactive audit; subject-only receipts preserve privacy of the action pattern. The right default varies per scope class (commerce is typically private, governance is typically public). The protocol admits both; deployment policy chooses.

**Q5: ZK proof composition.** The draft leaves `policy_evaluation_correct` as a `witnessed` claim. Upgrading to `closed` requires attaching a ZK proof of policy evaluation, which is out of scope for v3.0. The wire format should reserve an optional `policy_evaluation_proof` field whose presence upgrades the epistemic label. The exact proof format is deferred pending zkRego and zkOPA maturity.

**Q6: Interop with adjacent protocols.** SINT (policy-bundle interop), AIP (Invocation-Bound Capability Tokens), and HDP (Human Delegation Provenance) each have overlapping constructs. Cross-protocol fixture tests at `fixtures/bilateral-delegation/` are the venue for reconciling the canonical forms. The open question is whether the four message types in this draft should adopt naming conventions from one of the adjacent protocols (for backward compatibility), use APS-specific naming (for namespace isolation), or define a shared vocabulary across the stack (for ecosystem coherence).

## References

- `docs/ENFORCEMENT-TRUST-ANCHOR.md`: the architectural companion to this specification.
- `fixtures/bilateral-delegation/`: canonical JSON fixture vectors used for cross-implementation verification.
- `in-toto/attestation#549`: in-toto Decision Receipt predicate proposal, future integration target.
- `sint-ai/sint-protocol#178`: SINT migrationAttestation structural-precondition proposal.
- `RFC 8785`: JSON Canonicalization Scheme (JCS), used for all signed object serialization.
- `draft-pidlisnyi-aps-00`: Agent Passport System IETF Internet-Draft, delegation envelope format.

## Revision History

**v0.1 (2026-04-23).** Initial draft. Four message types specified with wire formats and signing order. Composition with v2.x mechanisms described. Six open design questions named. No implementations exist. Intent is to circulate for implementer feedback before v3.0 design lock.
