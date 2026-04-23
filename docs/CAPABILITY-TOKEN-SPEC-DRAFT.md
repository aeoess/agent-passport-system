# Capability Token Specification (Draft)

**Status:** discussion draft, v0.2
**Scope:** wire-format specification for the APS-aware closure stack described in `docs/ENFORCEMENT-TRUST-ANCHOR.md` Components 1 through 4
**Target:** APS v3.0, no fixed date
**Supersedes:** v0.1 (2026-04-23), preserved in git history

## Overview

This document specifies the message formats, signing order, and failure semantics for the capability-token protocol that instantiates the APS-aware enforcement closure stack. It is the protocol-level companion to `ENFORCEMENT-TRUST-ANCHOR.md` v1.2.

The construction implements the architectural claim that the gateway must stop being the component that both describes the action and originates the usable authority for it. Four actors participate in every enforcement cycle: the delegator (mints authority), the subject (requests actions), the sink (defines canonical action semantics and witnesses effects), and the gateway (evaluates policy against the sink-defined action, consuming authority minted by the delegator).

The gateway retains its role as policy-evaluation layer. It loses its role as authority-issuance layer and its role as enforcement-witness layer. Those responsibilities move to the delegator and the sink respectively.

## Changelog from v0.1

v0.1 specified four message types, with M4 `EffectReceipt` doing double duty as both boundary event and post-effect record. That conflation obscured the architectural role of the sink's attestation.

v0.2 renames M4 from `EffectReceipt` to `FRCBE` (Final Refusal-Capable Boundary Event), adopting the naming Steven Kyle Hensley coined on `corpollc/qntm#7` and formalized on OWASP#817. The rename reflects that this message IS the boundary event in BBIS terms, not merely a post-event artifact.

v0.2 also splits the post-effect forensic responsibility out of M4 into a new optional message M5 `ExecutionReceipt`. M4 is the boundary event the sink emits at the moment of execution refusal-capability. M5 is an optional forensic trail for deployments that want a separate post-effect record. For most deployments, M4 alone suffices and M5 is omitted.

Vocabulary throughout the document is updated to match the BBIS grammar adopted by `ENFORCEMENT-TRUST-ANCHOR.md` v1.2: closed, bounded, partial, detectable-only, theater. The architectural claim is unchanged.

## Design Goals

**G1.** Make gateway self-attestation unnecessary for the within-scope enforcement-decision property. A compromised gateway with a valid signing key cannot produce a receipt that a verifier will admit as attestation of enforcement.

**G2.** Preserve cryptographic provenance guarantees of v2.x. Delegation chains, passport bindings, issuer signatures, monotonic narrowing, and cascade revocation all compose with the new protocol without regression.

**G3.** Require no changes to subject agent runtime beyond the ability to carry four small additional fields per action. Subjects already sign and forward authorization envelopes.

**G4.** Be honest at the wire-format level about what is closed versus bounded versus witnessed versus unresolved. Typed epistemic receipts are enforced by schema, not by documentation convention. Typed receipts are honesty discipline, not a path that upgrades a bounded claim into a closed claim; the BBIS grammar in the trust-anchor doc v1.2 governs this distinction.

**G5.** Degrade gracefully to the v2.x bilateral-receipt hardening path when one of the four actors (specifically the sink) cannot be upgraded. The same receipt format carries both classes of claim; the typed-epistemic labels distinguish which claims are structurally closed versus bounded versus only witnessed.

## Actors and Trust Assumptions

**Delegator (D).** Issues delegations via the existing APS delegation chain. New in this protocol: mints `ConsumableAuthorityToken` objects at delegation time, bound to a Merkle root committed in the delegation envelope. The delegator's Ed25519 key is the authority root. Compromise of the delegator key is outside the threat model this protocol addresses; it is addressed by v2.x delegation chain mechanisms (rotation, revocation, succession).

**Subject (S).** The agent requesting actions. Holds its passport-bound Ed25519 key and the delegator-issued token set. New in this protocol: requests sink challenges, reveals consumable authority tokens for specific actions, forwards signed objects between the sink and the gateway. The subject's key compromise composes with gateway compromise as noted in the triple-collusion residual in `ENFORCEMENT-TRUST-ANCHOR.md`.

**Sink (K).** The resource server executing the action. New in this protocol: issues canonical action challenges, maintains a nullifier set of consumed token preimages, emits sink-signed FRCBE messages at the moment of execution refusal-capability, optionally emits sink-signed ExecutionReceipt messages as post-effect forensic trail. The sink's Ed25519 key is the attestation root for the enforcement-boundary property (the property v1.x of the trust-anchor doc identifies as not closed by v2.x). Sink compromise is the primary residual threat this protocol does not close.

**Gateway (G).** Evaluates policy against the sink-authored challenge. New in this protocol: signature over policy evaluation binds exactly to the sink's challenge hash, cannot unilaterally introduce semantic drift. The gateway's key compromise is the threat model this protocol addresses.

## Message Types

Five message types define the protocol. M1 through M4 are required. M5 is optional and is emitted only by deployments that want post-effect forensic artifacts distinct from the boundary event. Each message is an object with explicit schema; all signatures are Ed25519 over the JCS (RFC 8785) canonical serialization of the object excluding the signature field itself.

### M1: SinkChallenge (K to S)

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

### M2: AuthorityEvaluationRequest (S to G)

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

**Failure semantics.** Any signature failure, chain walk failure, Merkle proof failure, or freshness failure causes the gateway to return a signed denial (M3 with `decision: deny`) rather than a permit. A compromised gateway cannot forge a valid `ChallengeReceipt` against a scope class not covered by a minted token, because the token Merkle root was signed by the delegator at delegation time.

### M3: ChallengeReceipt (G to S to K)

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

**Typed epistemic claims.** The `epistemic_claims` object is load-bearing. `policy_evaluated`, `authority_consumed`, and `scope_within_bounds` are labeled `closed` because they are verifiable from the receipt alone against the gateway's public key, the delegator's authority token Merkle root, and the canonical challenge. `effect_occurred` is labeled `unresolved` because no party has yet attested to the effect; only the sink's subsequent FRCBE (M4) can upgrade that label to `closed`. A verifier that treats `unresolved` claims as closed is violating the protocol semantics.

**Failure semantics.** A compromised gateway that fabricates a receipt for a challenge the sink never issued produces a receipt with a `challenge_hash` no sink will recognize. A gateway that fabricates a receipt with a token preimage not in the delegator's Merkle root produces a receipt that fails the sink's nullifier check only after the sink's verification of the token preimage against the delegation-chain-rooted authority Merkle root. The sink verifies this because the delegation chain is carried forward through the subject, not through the gateway alone.

### M4: FRCBE (K to S, optionally published)

At the moment of execution refusal-capability, the sink emits a signed boundary event binding the consumed token to the authorized action. This is the cryptographic instantiation of what BBIS names the Final Refusal-Capable Boundary Event. It is the boundary event itself, not a post-event record. A verifier who holds the tuple (M1, M3, M4) has the complete enforcement-boundary attestation.

The rename from v0.1 `EffectReceipt` to v0.2 `FRCBE` prevents the common misreading of this message as a post-effect log entry. It is not. M4 is the sink's sealed commitment that refusal was possible up to this point and is no longer possible past this point because the effect has been crossed under the authority and policy-evaluation carried by M1 through M3. Post-effect forensic trail, where a deployment wants one distinct from the boundary event, lives in M5.

```
{
  "type": "aps.capability.v1.FRCBE",
  "challenge_hash": "<SHA-256 of the SinkChallenge, unchanged from ChallengeReceipt>",
  "authority_token_preimage": "<32-byte base64url, unchanged from ChallengeReceipt>",
  "gateway_receipt_hash": "<SHA-256 of the ChallengeReceipt canonical serialization>",
  "boundary_event": {
    "crossed_at": "<ISO 8601 UTC>",
    "outcome": "success" | "failure" | "partial",
    "result_digest": "<SHA-256 of the effect result, opaque to APS>"
  },
  "epistemic_claims": {
    "boundary_crossed": "closed",
    "effect_bound_to_token": "closed",
    "policy_evaluation_correct": "witnessed"
  },
  "sink_signature": "<Ed25519 over canonical serialization>"
}
```

**Verification.** Any verifier holding the `ChallengeReceipt` (M3) and FRCBE (M4) can establish: (a) the sink authored a canonical action challenge, (b) the gateway evaluated policy against that exact challenge under authority minted by the delegator, (c) the refusal-capable boundary was crossed at the sink under that exact authority, producing a bound result. The tuple `(SinkChallenge, ChallengeReceipt, FRCBE)` is the full enforcement-boundary attestation record.

**Typed epistemic claims.** `boundary_crossed` is `closed` because the sink has signed the boundary event. `effect_bound_to_token` is `closed` because `result_digest` is in the signed record and is committed to the same token preimage that authorized the action. `policy_evaluation_correct` remains `witnessed` rather than `closed`: the sink has witnessed that a gateway signed a permit against this challenge, but it cannot by itself verify that the gateway's policy evaluation was semantically correct. Upgrading this claim to `closed` requires composition with a ZK proof of policy evaluation (future work, not in v3.0 scope) or with a replayable deterministic transcript that any verifier can re-execute.

**Failure semantics.** A `ChallengeReceipt` without a matching FRCBE is a permit that was never exercised; verifiers that require enforcement attestation (as opposed to authorization attestation) must reject these as insufficient. This is the correct behavior, not a bug: an unexercised permit does not attest to enforcement. Conversely, a FRCBE without a matching `ChallengeReceipt` is a sink signature binding a boundary event to a non-existent authorization and is inadmissible.

### M5: ExecutionReceipt (K to S, optional post-effect forensic trail)

Optional. Sinks emit M5 only when a deployment wants a post-effect forensic artifact distinct from the FRCBE boundary event. For most deployments, M4 suffices and M5 is omitted. M5 exists for cases where the boundary event and the post-effect forensic trail have different retention policies, different audiences (boundary event to policy auditors, post-effect to compliance officers), or different publication semantics (boundary event private, post-effect publishable to transparency log).

```
{
  "type": "aps.capability.v1.ExecutionReceipt",
  "frcbe_hash": "<SHA-256 of the FRCBE canonical serialization>",
  "execution_id": "<sink-chosen stable identifier>",
  "executed_at": "<ISO 8601 UTC>",
  "outcome": "success" | "failure" | "partial",
  "result_digest": "<SHA-256 of the effect result, MUST match the FRCBE's boundary_event.result_digest>",
  "epistemic_claims": {
    "post_effect_trail_bound_to_boundary_event": "closed"
  },
  "sink_signature": "<Ed25519 over canonical serialization>"
}
```

**Verification.** Verifier consuming M5 holds M4 as well. `frcbe_hash` binds M5 to the boundary event it forensically documents. `result_digest` MUST match the value carried in M4; a mismatch is a protocol violation and renders both messages inadmissible.

**Typed epistemic claims.** `post_effect_trail_bound_to_boundary_event` is `closed` because the sink has signed both M4 and M5, and M5's `frcbe_hash` + `result_digest` structurally commit M5 to the exact boundary event. M5 does not re-attest the boundary crossing; M4 carries that attestation.

**Failure semantics.** M5 without a matching M4 is inadmissible. M5 with a `result_digest` that disagrees with M4's `boundary_event.result_digest` is inadmissible and indicates sink misbehavior or sink compromise.

**When to omit M5.** Most deployments. The common case is: the sink emits M4 at the boundary event, the subject and any relevant audit systems retain M4, and there is no separate post-effect forensic artifact. M5 exists for deployments with explicit post-effect forensic requirements (financial compliance, regulated health data, multi-retention-tier compliance) where splitting the boundary event from the post-effect trail is operationally useful.

## Signing Order Summary

```
S -> K:     action intent (unsigned)
K -> S:     M1  SinkChallenge              [sink signs]
S -> G:     M2  AuthorityEvaluationRequest [subject signs, carries challenge + delegation + token reveal]
G -> S:     M3  ChallengeReceipt           [gateway signs]
S -> K:     execution request + M3         [subject forwards]
K -> S:     M4  FRCBE                      [sink signs, THE boundary event]
K -> S:     M5  ExecutionReceipt           [sink signs, OPTIONAL post-event forensic trail]
```

Four signatures required across the protocol cycle: sink (M1), subject (M2), gateway (M3), sink (M4). A fifth signature (M5, sink) is optional. Each signature signs a different proposition. The gateway's M3 signature is not the enforcement attestation; it is the policy-evaluation attestation. M1 and M4 together constitute the enforcement-boundary attestation, authored by a party structurally distinct from the policy evaluator. M5, where present, is the post-effect forensic trail, not the boundary event.

## Closure Argument

The protocol closes the within-scope forgery surface identified in `ENFORCEMENT-TRUST-ANCHOR.md` Section "The Gap" as follows. All references to the architectural-doc components use the BBIS grammar adopted in v1.2.

**A compromised gateway cannot describe an action.** The sink issues the canonical challenge (M1). The gateway's M3 signature binds to the sink's challenge hash. A gateway that narrates a different action produces a receipt the sink will not admit. This achieves bounded end-to-end governance on the semantic-drift axis (Component 1 in the architectural doc).

**A compromised gateway cannot originate authority.** Consumable authority tokens are minted by the delegator and committed to a Merkle root in the delegation envelope. The gateway can only countersign the consumption of tokens the delegator already authorized. Token forgery requires the delegator's key, which is outside the gateway threat model. This achieves bounded end-to-end governance on the authority-origination axis (Component 2 in the architectural doc).

**A compromised gateway cannot fake enforcement.** The sink's M4 FRCBE is the boundary event. A gateway-only M3 without a matching sink-signed FRCBE is provably insufficient per the protocol's typed epistemic claims. Verifiers that treat M3 alone as enforcement attestation are violating the protocol. This achieves closed / strongly admissible classification for positive-effect actions (Component 3 in the architectural doc).

**Typed epistemic claims are honesty discipline, not a class upgrade.** M3 and M4 both carry `epistemic_claims` objects that explicitly label each claim as `closed`, `bounded`, `witnessed`, or `unresolved`. The labeling makes the classification machine-readable and prevents overclaiming. It does not convert a bounded claim into a closed claim; the construction itself determines the class, and the label reports it honestly. This is the wire-format implementation of the "Honesty Discipline vs Admissibility Upgrade" section of the architectural doc.

**What the protocol does not close.** Sink compromise (sink-side boundary events lie), full three-party collusion among subject, gateway, and sink against an absent delegator, and the read-only residual where M4 has no observable boundary to attest. These are documented in `ENFORCEMENT-TRUST-ANCHOR.md` as architectural limits.

## Degradation Path for Dumb Web2 Sinks

The same wire format carries bilateral-receipt hardening for sinks that cannot author canonical challenges or sign FRCBE messages. In BBIS terms this path delivers partial governance, not bounded end-to-end governance; the typed epistemic labels make that explicit.

For such deployments:

- M1 is replaced with a subject-authored `CanonicalActionStatement` signed by the subject, with the subject's `epistemic_claims.action_canonicalization` labeled `self-asserted`. This is honest: without the sink as action author, the subject is narrating.
- M2 and M3 are unchanged.
- M4 FRCBE is replaced by a subject-signed `PostExecutionAcknowledgment` with `epistemic_claims.boundary_crossed` labeled `witnessed-by-subject` rather than `closed`. The subject attests to what it observed at the sink; this is weaker than sink-signed M4 but narrows the gap from gateway-alone to gateway-plus-subject.
- M5 is not applicable in this path.

The typed epistemic labels make the degradation explicit. A verifier reading a receipt with `boundary_crossed: witnessed-by-subject` rather than `boundary_crossed: closed` knows the deployment is using the dumb-sink hardening path (partial governance in BBIS grammar) and can apply its own risk-tolerance rules.

## Composition with Other APS Mechanisms

**Delegation chain (v2.x).** Unchanged. The `delegation_chain` field in M2 carries the v2.x delegation envelope with all its existing properties (monotonic narrowing, issuer-signed passports, scope tokens). The delegator's signature over `authority_token_merkle_root` is an additional field in the delegation envelope, bounded to a new optional block that does not break backward compatibility.

**Revocation (v2.x).** Cascade revocation mechanisms compose. A revoked delegation invalidates all descendant `AuthorityEvaluationRequest` attempts that reference the revoked delegation chain. The sink's nullifier set does not need to know about revocation; the gateway refuses to sign M3 against a revoked chain, and the subject has no M3 to forward.

**Passport grades (v2.x).** Unchanged. The passport grade of the subject is a property of the delegation chain, verifiable independently of this protocol.

**Behavioral Memory Objects (v2.x).** Compose as a forensic audit overlay per `ENFORCEMENT-TRUST-ANCHOR.md` Component E (detectable-only / witnessed governance). BMO evidence can upgrade the sink's `epistemic_claims.policy_evaluation_correct` from `witnessed` to `corroborated` where subsequent behavior confirms the receipt's claimed scope. This is an audit-layer annotation, not a replacement for the cryptographic attestation.

**in-toto Decision Receipt predicate.** The M3 `ChallengeReceipt` and M4 FRCBE shapes are designed to be expressible as in-toto Decision Receipt predicates once the predicate specification stabilizes at `in-toto/attestation#549`. The `challenge_hash` field maps to the predicate's subject-binding hash; the `epistemic_claims` object maps to a predicate-specific extension. This is the integration path from v2.x bilateral to v3.0 sink-authored.

**AgentGraph CTEF v0.3.** The `delegation_chain_root` field in M2 and M3 is the composition field that AgentGraph CTEF v0.3 accepts as the cross-ecosystem canonical binding. APS emits `delegation_chain_root` natively; CTEF v0.3 consumes it; cross-test vectors live at `fixtures/bilateral-delegation/` alongside APS's existing cross-ecosystem fixtures.

## Crosswalk: Architectural Components to Wire-Format Messages

This section cross-references the components defined in `ENFORCEMENT-TRUST-ANCHOR.md` v1.2 to the wire-format messages defined here. The crosswalk is normative: future revisions of either document must preserve this mapping.

| Architectural Component | BBIS Class | Wire-Format Message |
|---|---|---|
| Component 1: Sink-Authored Canonical Challenge | bounded end-to-end governance | M1 SinkChallenge |
| Component 2: Consumable Authority Tokens | bounded end-to-end governance | M2 authority_token field + delegation envelope extensions |
| Component 3: Sink-Signed Effect Receipt (the FRCBE) | closed / strongly admissible | M4 FRCBE |
| Component 4: Typed Epistemic Receipts | honesty discipline (not a classification upgrade) | `epistemic_claims` objects on M3 and M4 (and M5 where present) |
| Gateway policy evaluation (unnumbered in v1.2) | unchanged from v2.x | M3 ChallengeReceipt |
| Optional post-effect forensic trail | composition primitive | M5 ExecutionReceipt |

**FRCBE primitive name.** The M4 FRCBE message is the wire-format instantiation of the Final Refusal-Capable Boundary Event primitive named by Steven Kyle Hensley at `corpollc/qntm#7` in the comment consolidating the BBIS architectural invariant across AgentGraph, APS, and AgentID. Adopting the name at the wire-format level aligns APS with BBIS vocabulary and with the cross-ecosystem shared language that OWASP#817 is converging on. The structural claim (sink signs the boundary event, not the gateway) is unchanged from v0.1; only the name changes, and the responsibility split between boundary event and post-effect trail is now explicit via the M4-plus-optional-M5 structure.

## Open Design Questions

Questions this draft does not resolve. Each affects the final wire format; each requires implementation input before v3.0 lock.

**Q1: Authority token minting granularity.** Should tokens be one-per-action, one-per-scope-class, or one-per-freshness-window? Finer granularity improves forgery resistance at the cost of delegation envelope size and minting ceremony overhead. Coarser granularity eases operations at the cost of broader consumption windows where a compromised gateway can batch-consume tokens before detection. Initial default proposal: one token per (scope-class, freshness-window), with window scoped to the delegation validity period subdivided by a configurable interval.

**Q2: Sink challenge format ownership.** The protocol assumes sinks can author canonical action challenges. For sinks that cannot, a thin APS proxy issues challenges on the sink's behalf. Where does the proxy sit in the trust topology? Options: (a) co-located with the sink, signed by a key distinct from the sink's operational keys but under the same operator (weak); (b) co-located with the delegator, signed by a delegator-operated service (strong, but re-introduces delegator synchrony); (c) hosted as a neutral third party with sink-specific keys derived via DKG (strongest, most operational complexity). The right answer likely varies per sink class.

**Q3: Offline subject graceful degradation.** Daemon agents acting while disconnected cannot forward M1 to the gateway in real time. Three options: (a) pre-fetched challenges with long expiry, consumed within the validity window, with `freshness_beacon` constraints relaxed per deployment policy; (b) subject-held batched acknowledgments that consume multiple challenges in sequence; (c) fallback to v2.x bilateral-receipt path for offline actions with explicit typed-epistemic labeling that the action did not use the sink-authored closure path. The draft does not yet choose; implementer input is required.

**Q4: FRCBE and ExecutionReceipt publication semantics.** M4 FRCBE can be returned to the subject only, or additionally published to a transparency log per `ENFORCEMENT-TRUST-ANCHOR.md` Component B. M5 ExecutionReceipt, where present, has its own independent publication decision. Published boundary events support retroactive audit; subject-only boundary events preserve privacy of the action pattern. The right default varies per scope class (commerce is typically private, governance is typically public). The protocol admits both; deployment policy chooses independently for M4 and M5.

**Q5: ZK proof composition.** The draft leaves `policy_evaluation_correct` as a `witnessed` claim. Upgrading to `closed` requires attaching a ZK proof of policy evaluation, which is out of scope for v3.0. The wire format should reserve an optional `policy_evaluation_proof` field whose presence upgrades the epistemic label. The exact proof format is deferred pending zkRego and zkOPA maturity.

**Q6: Interop with adjacent protocols.** SINT (policy-bundle interop), AIP (Invocation-Bound Capability Tokens), HDP (Human Delegation Provenance), and AgentGraph CTEF v0.3 each have overlapping constructs. Cross-protocol fixture tests at `fixtures/bilateral-delegation/` are the venue for reconciling the canonical forms. The open question is whether the five message types in this draft should adopt naming conventions from one of the adjacent protocols (for backward compatibility), use APS-specific naming (for namespace isolation), or define a shared vocabulary across the stack (for ecosystem coherence). The FRCBE rename in v0.2 is a first concrete step toward shared vocabulary; whether the rest of the message names follow is an open question.

**Q7: BBIS bounded_scope at wire format versus deployment manifest.** Open in the architectural doc v1.2 as well. If bounded end-to-end governance is declared at the wire format (per-receipt `bounded_scope` token on M3 and M4), receipts become self-describing and verifiers reject overclaims mechanically. If declared at the deployment manifest level, receipts stay compact and the bounded-scope declaration lives in a separate signed artifact. v0.3 makes this choice in coordination with trust-anchor v1.3 once Hensley answers on OWASP#817.

## References

- `docs/ENFORCEMENT-TRUST-ANCHOR.md` v1.2: the architectural companion to this specification, with the BBIS classification grammar.
- `fixtures/bilateral-delegation/`: canonical JSON fixture vectors used for cross-implementation verification.
- `in-toto/attestation#549`: in-toto Decision Receipt predicate proposal, future integration target.
- `sint-ai/sint-protocol#178`: SINT migrationAttestation structural-precondition proposal.
- `corpollc/qntm#7`: consolidation thread where Hensley coined the FRCBE primitive name.
- `OWASP/www-project-top-10-for-large-language-model-applications#817`: BBIS classification grammar discussion; source for the closed / bounded / partial / detectable-only / theater ladder adopted in this draft.
- `RFC 8785`: JSON Canonicalization Scheme (JCS), used for all signed object serialization.
- `draft-pidlisnyi-aps-00`: Agent Passport System IETF Internet-Draft, delegation envelope format.

## Revision History

**v0.2 (2026-04-23).** M4 renamed from `EffectReceipt` to `FRCBE` (Final Refusal-Capable Boundary Event) per Hensley's qntm#7 coinage and OWASP#817 consolidation. New optional M5 `ExecutionReceipt` split out from M4 for deployments that want a post-effect forensic trail distinct from the boundary event; most deployments omit M5. Signing order updated. Closure Argument rewritten in BBIS vocabulary. New normative crosswalk section mapping architectural components to wire-format messages and citing the FRCBE primitive name. New open design question on bounded_scope wire-format versus manifest-level declaration (Q7), parallel to the open question in trust-anchor v1.2. Vocabulary throughout aligned with BBIS grammar adopted by trust-anchor v1.2.

**v0.1 (2026-04-23).** Initial draft. Four message types specified with wire formats and signing order. Composition with v2.x mechanisms described. Six open design questions named. No implementations exist. Intent was to circulate for implementer feedback before v3.0 design lock. M4 `EffectReceipt` in v0.1 is superseded by M4 FRCBE plus optional M5 ExecutionReceipt in v0.2.
