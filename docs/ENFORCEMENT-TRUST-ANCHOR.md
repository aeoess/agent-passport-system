# Enforcement Trust Anchor: The Single-Gateway Attestation Gap

**Status:** v1.1, sink-awareness reorganization after adversarial architectural review
**Scope:** specification document describing a boundary the APS reference deployment does not currently close, and the closure paths available to it under realistic deployment constraints
**Supersedes:** v1.0 (2026-04-22), preserved in git history

---

## Changelog from v1.0

v1.0 identified four closure paths (bilateral receipts, tamper-evident log, TEE-backed gateway, multi-gateway quorum) and committed to bilateral receipts as primary. That framing was the ecosystem's consensus on this problem and was incomplete in a specific way: all four paths preserve the gateway as the attestation root and dilute single-party lying through honesty assumptions on other parties.

v1.1 reorganizes around the sink-awareness boundary and adopts a five-bucket taxonomy (full closure, subset closure, detection / deterrence, composition primitive, architectural limit) that honestly classifies which constructions close what.

The architectural claim v1.1 commits to is this: **the gateway must stop being the component that both describes the action and originates the usable authority for it.** This is the surviving output of sustained hostile review across all primitives considered.

---

## Scope

### What APS closes today

APS closes cryptographic provenance through the boundary:

- **Delegation chain integrity.** Every hop from the root principal to the acting agent is Ed25519-signed. Monotonic narrowing is enforced at verification time. No hop can grant more authority than its parent.
- **Issuer-signed passports.** The subject-to-public-key binding is signed by the issuing principal and independently verifiable against the principal's JWKS without touching the gateway.
- **Scope-token attribution.** Action tuples reference delegation scope tokens whose signatures chain back to the root.
- **Passport grades and attestation tiers.** The evidence ladder (infrastructure > behavioral > self-declared) is itself signed by the grader and re-verifiable offline.

An external auditor holding only the passport, the delegation chain, and the root principal's JWKS can verify everything above without trusting the gateway.

### What APS does not close today

APS does not close single-gateway forged-attestation resistance at the enforcement boundary.

The gateway is both judge and executor. In the current reference deployment, it is also the sole signer of the `PolicyReceipt` that attests the enforcement decision occurred. That final attestation is a single-party assertion. There is no independent witness for the decision and no external commitment that fixes the receipt in time before it becomes citable.

---

## The Gap

**Formal statement:** In the current reference deployment, a compromised gateway can emit a cryptographically valid `PolicyReceipt` attesting to an enforcement decision that did not actually occur. APS's upstream provenance layer remains intact in this scenario; the gap is at the final enforcement-boundary attestation.

### What upstream evidence still survives gateway compromise

A compromised gateway cannot rewrite history upstream of itself. The following remain verifiable end-to-end without the gateway's participation:

- **The delegation chain.** Signatures are held by each delegator's key. A gateway does not hold those keys and cannot forge new hops into the chain without breaking Ed25519.
- **The passport binding.** The subject DID to public-key binding is signed by the issuing principal, not by the gateway.
- **The root principal's authority.** JWKS publication is out-of-band (did:web, IPFS, institutional PKI). The gateway does not mediate principal identity.
- **Out-of-scope forgeries.** If a gateway fabricates a receipt authorizing an action whose scope exceeds the delegation's leaf-hop scope, a third-party verifier with the chain in hand detects the mismatch immediately. Monotonic narrowing is a mechanical check, not a trust-in-the-gateway check.

### What is undetectable without composition

The residual forgery surface is the set of receipts that fabricate a **within-scope** enforcement decision. A gateway that forges a `PolicyReceipt` saying "I decided ALLOW for action X within scope Y" cannot be caught by chain re-verification, because both the action and the decision fall inside what the delegation chain already authorized. The only thing that did not happen is the actual decision event at the gateway.

Closing this surface requires changing who gets to define the action, who gets to create usable authority, or who witnesses the effect. Every construction that survived adversarial review implements at least one of these three shifts.

---

## The Architectural Constraint: Sink-Awareness

Closure depends on what the target resource (the sink) can verify. APS targets divide into two classes, and the honest closure story differs per class.

**APS-aware sinks.** Resources that can verify delegation-bound authorization tokens natively. This includes our own MCP server, agent-to-agent communication with APS-compatible agents, and downstream services that integrate APS verification (AgentGraph, MolTrust, OATR, SINT-integrated agents). Full structural closure is available for this class.

**Dumb Web2 sinks.** Resources that accept ordinary HTTP requests and do not evaluate delegation semantics. This includes the commerce rails (Stripe, AWS billing, Shopify), model provider APIs (OpenAI, Anthropic), and most of the external surface area APS must interact with in 2026. Full structural closure is not available for this class at the protocol layer. Hardening layers narrow the gap and raise forgery cost, but the architectural limit is real.

A third axis cuts across both classes: **read-only actions**. Actions with no observable state change at the sink (informational queries, passport lookups, capability enumeration) have no external effect to witness. These are handled as an orthogonal residual.

This document's organization reflects this split: a closure stack for APS-aware sinks, a hardening stack for dumb sinks, and a specific treatment for the read-only residual.

---

## Taxonomy of Constructions

Every construction in this document is classified into one of five buckets. This taxonomy is the single biggest revision from v1.0, which used a flat "closure paths" framing that conflated full closure with partial and detection-only primitives.

**1. Full closure for the stated threat model.** The construction removes the gateway from the critical path for the attested property, or makes the attested property structurally impossible to forge. No honesty assumption on the gateway is required.

**2. Subset closure.** The construction closes a specific sub-problem (for example, semantic drift between described and executed action, or widening of static scope), but leaves other aspects of the attestation gap open. Useful as a component, not as standalone closure.

**3. Detection / deterrence.** The construction makes forgery detectable after the fact, or raises the cost of undetected forgery, without preventing forgery at the moment of attack. Useful for accountability and economic bounds on fraud, not for synchronous correctness.

**4. Composition primitive.** The construction is a building block that strengthens other constructions but does not by itself close any meaningful sub-problem. Examples: canonical hashing, timestamp witnesses, log inclusion proofs.

**5. Architectural limit.** Under the stated threat model, closure by this path is not available with deployable primitives in 2026. Naming these explicitly prevents the doc from becoming a wish list.

---

## Closure Stack for APS-Aware Sinks

For targets that can verify delegation-bound tokens natively, the following composition provides full closure of the within-scope forgery surface.

### Component 1: Sink-Authored Canonical Challenge

**Bucket:** subset closure (closes semantic drift between described and executed action).

**Description.** The sink, not the gateway, defines the canonical statement of what action is being requested. A subject first asks the sink for an action challenge containing the canonicalized effect object (action type, target, parameters, resource version, nonce, expiry), signed by the sink. The gateway's role is reduced to: evaluating policy against the sink-authored challenge and signing an evaluation receipt bound to the exact challenge hash. The sink accepts the resulting token only if it binds to its own previously-issued challenge.

**What it closes.** "Receipt describes one action, system executed another." The gateway loses the ability to narrate action semantics. A forged receipt for a different action fails sink admission because the challenge hash does not match.

**Residual.** Does not close stale-policy-state fraud or dynamic-invariant violations. Component 2 and Component 4 address these.

### Component 2: Consumable Authority Tokens

**Bucket:** subset closure (closes authority invention by the gateway).

**Description.** Authority is represented as a finite set of cryptographic consumable tokens minted by the delegator (not the gateway) at delegation time. Each token is bound to a narrow action class and a nullifier. The gateway's role is to evaluate policy against a sink-authored challenge and countersign the consumption of a specific token against that challenge. The sink maintains a nullifier set and rejects double-spends. A compromised gateway cannot invent tokens; it can only consume tokens the delegator already minted.

**What it closes.** Gateway-originated authority inflation. Widening beyond what was minted requires forging the delegator's signature, which is outside the threat model. Replay of previously-consumed tokens fails at the sink nullifier check.

**Residual.** Pre-hoarding attacks where a subject extracts receipts for many tokens before a delegator revokes. Mitigation: strict expiry per token, or binding tokens to challenge freshness such that expired challenges invalidate the consumption.

### Component 3: Sink-Signed Effect Receipt

**Bucket:** full closure for positive-effect actions (truth comes from the sink, not the gateway).

**Description.** After executing the authorized action, the sink emits its own signed receipt binding the redeemed token to the actual effect. This receipt is the primary attestation that enforcement occurred. The gateway's prior evaluation receipt becomes corroborating metadata, not the authoritative record. A forged gateway receipt for an action the sink never executed has no matching sink receipt and is inadmissible to any verifier that requires both.

**What it closes.** "Gateway claimed it enforced, but the action never reached the sink." The attestation root moves to the component that actually witnessed the effect.

**Residual.** Sink compromise (the sink must be in a trust domain distinct from the gateway), read-only actions with no observable effect, actions with out-of-band alternate paths the sink does not mediate.

### Component 4: Typed Epistemic Receipts

**Bucket:** hygiene discipline, not a cryptographic closure.

**Description.** Receipts explicitly label each claim they carry as `closed` (cryptographically verifiable without honesty assumption), `witnessed` (verified by an external party under a stated threat model), or `unresolved` (asserted but not externally attested). A verifier consuming the receipt can reject unresolved claims per policy, refuse to cite them as enforcement evidence, or treat them as provisional.

**What it closes.** Overclaiming. A receipt that mixes closed and unresolved claims without typing smuggles self-assertion into a record that looks cryptographically strong. Typed epistemic receipts make the honesty visible at the wire format level.

**Residual.** Social pressure to collapse the type system. Downstream consumers (investors, auditors, compliance bodies) may ignore the distinction and cite all signed claims as equivalent. This is a governance discipline problem, not a cryptographic one.

### The Composed Closure

Together, Components 1 through 4 implement the architectural claim: the sink defines the action (not the gateway), the delegator originates authority (not the gateway), the sink witnesses the effect (not the gateway), and the receipt honestly labels what is closed versus unresolved. The gateway's role collapses to policy evaluation against an externally-defined action, under externally-minted authority, with externally-witnessed effect. A compromised gateway retains the ability to deny actions it should have permitted (a liveness failure, not an integrity failure) and to approve within-scope actions that the delegator would have preferred it deny (the triple-collusion residual, named below).

---

## Hardening Stack for Dumb Web2 Sinks

For targets that accept ordinary HTTP requests and cannot evaluate delegation semantics, structural closure of the within-scope forgery surface is not available at the protocol layer. This is not a failure of imagination. It is a consequence of the fact that whoever holds the connection to a dumb sink has absolute power over the sink. No amount of gateway-side cryptography forces a sink that does not read cryptography to respect it.

What is available is hardening. The following constructions narrow the gap and raise forgery cost, but none provides structural closure for dumb sinks. Deployers using APS against dumb sinks must accept residual gateway-compromise risk and layer defense-in-depth accordingly.

### Component A: Bilateral Receipts

**Bucket:** subset closure (narrows the attestation surface from gateway-alone to gateway-plus-subject).

**Description.** Gateway and subject both sign the canonical action tuple, pre-execution (gateway) and post-execution (subject). The in-toto Decision Receipt predicate at `in-toto/attestation#549` is the current ecosystem-level effort. A forged receipt requires collusion with the subject's signer.

**What it closes.** Single-party gateway fabrication, against a non-colluding subject.

**Residual.** Subject-gateway collusion. When the subject's signing key lives on the same machine as the gateway under the same operator, both compromises are one compromise. This is the widest residual in the dumb-sink hardening stack.

### Component B: Tamper-Evident Log with Pre-Effect Commitment

**Bucket:** detection / deterrence.

**Description.** Gateway commits each receipt to a public append-only log before the receipt is citable. Silent forgery after the fact becomes detectable as log divergence. Does not prevent forgery at the moment of attack but makes sustained fraud visible.

**What it closes.** Retroactive fabrication where the gateway attempts to backdate or rewrite decisions. Also enables third-party audit without requiring sink cooperation.

**Residual.** Live forgery within the current window. An honest log does not make a dishonest decision honest.

### Component C: Homomorphic State Commitments for Arithmetic Invariants

**Bucket:** subset closure (closes arithmetic-invariant forgery).

**Description.** For stateful policy invariants (spend caps, rate limits, reserve ratios), the gateway maintains a public homomorphic accumulator over per-subject counters. Every receipt includes a proof that updating the accumulator by the receipt's delta does not violate the declared invariant. A forged receipt that would breach the cap produces a detectable commitment mismatch at any verifier with the public accumulator root.

**What it closes.** Gateway forgery that violates arithmetic invariants. For commerce delegations specifically (spend caps, budget tracking), this is load-bearing.

**Residual.** Does not close forgery that stays within arithmetic bounds but violates discretionary policy.

### Component D: MPC-TLS Network Binding for High-Value Transactions

**Bucket:** detection / deterrence (with narrow full-closure applicability).

**Description.** For specific high-value transactions where latency of seconds is acceptable (institutional transfers, bonded commerce authorizations), MPC-TLS constructions (DECO, TLSNotary, zkTLS variants) produce a proof that the gateway transmitted a specific payload over the TLS tunnel. Does not prevent the transmission; produces evidence after the fact that can be used in fraud proofs.

**What it closes.** Gateway narration of what was sent to the sink. Compromised gateway cannot claim it sent Payload A when the MPC proof attests Payload B.

**Residual.** Write-mode verification paradox: the target executes before the proof is checked. The prover network is a new trust root that can collude with the gateway. TLS 1.3 compatibility is partial. Latency is prohibitive for interactive agent workflows. MPC-TLS survives as a forensic tool for specific high-value transactions, not as a primary closure.

### Component E: BMO Ground-Truthing as Forensic Audit Overlay

**Bucket:** detection (APS-native).

**Description.** APS already emits Behavioral Memory Objects tracking subject behavior under delegations. A receipt claiming scope Y for delegation D can be marked `behaviorally confirmed` only when subsequent BMO evidence demonstrates the subject actually exercised scope Y. Forged receipts for scope never exercised by the subject produce receipts without behavioral support.

**What it closes.** Catches a specific fraud class not addressed by other layers: fabricated receipts for unexercised scope in long-lived delegations. Because APS already has the BMO substrate, this layer costs little to add.

**Residual.** Passive fraud (forged denial for an action the subject would have taken) is undetectable. Spurious confirmation (subject happens to exercise the forged scope by chance) produces false positives. BMO is an audit layer, not prevention.

### The Composed Hardening

For deployments against dumb sinks, the honest guidance is: compose A (bilateral receipts) as primary, B (tamper-evident log) as accountability baseline, C (homomorphic commitments) for stateful invariants where applicable, D (MPC-TLS) for specific high-value transactions where latency permits, and E (BMO audit) as always-on forensic overlay. The composition narrows the gap substantially but does not close it. The residual is named below as an architectural limit.

---

## The Read-Path Residual

Actions with no observable state change at the sink are an orthogonal residual that neither the APS-aware stack nor the dumb-sink hardening stack fully addresses.

### Attribute-Based Encryption at Source

**Bucket:** subset closure in narrow deployment bands.

**Description.** For read-only actions against a data source in a trust domain distinct from the gateway, the source encrypts responses under a CP-ABE predicate tied to the delegation's attributes. The subject holds credentials whose attribute set satisfies the predicate; any other party receives ciphertext it cannot decrypt. The gateway is entirely removed from the read path. Its receipts for reads are advisory only; what governs is whether the subject can decrypt.

**What it closes.** Gateway forgery of permitted reads, when the source is genuinely in a distinct trust domain, policy is stable enough for encryption cycles to track, and the attribute authority is distributed (DKG or delegator-operated, not gateway-operated).

**Residual.** Attribute revocation is a known hard problem in CP-ABE. Policies that change faster than encryption cycles force re-encryption services that re-create the attestation gap. Applies only to stable-scope reads where the source cooperates. Does not apply to general Web2 reads.

### Accepted Residual

For deployments where ABE-at-source is not available (most Web2 cases), the honest position is: read-only actions remain within the gateway's attestation surface. Deployers should either accept the residual, compose with bilateral receipts (Component A) to narrow it, or restructure to produce observable state at the sink where possible (for example, logging reads to a tamper-evident access log at the resource).

---

## Universal Hygiene

Independent of which closure stack applies, three practices are recommended for all APS deployments.

**Typed epistemic receipts (Component 4 above).** Apply regardless of sink class. Receipts must explicitly distinguish closed from witnessed from unresolved claims.

**Delegator liveness beacons.** Delegators emit signed beacons at frequency f containing `{delegation_id, policy_digest_current, timestamp, nonce}`. Receipts must embed the most recent beacon within a freshness window W. Provides revocation finality: when a delegator revokes or goes silent, receipts become inadmissible within W without requiring per-action delegator synchrony. Does not close the attestation gap, closes a specific revocation-finality subproblem.

**Canonical hashing discipline.** All signed objects use JCS (RFC 8785) canonical JSON with documented edge-case handling for nested null, key ordering, recursive sort, string escape behavior, and numeric representation. Cross-implementation fixture vectors at `fixtures/bilateral-delegation/` define the normative canonicalization. Without this, all signature-level closure degrades to "signed against the canonical form the signer computed" which is not a verifiable property.

---

## Named Residuals (Architectural Limits)

The following are not implementation gaps. They are limits of what any architecture can close under the stated threat model with deployable primitives in 2026. Naming them explicitly is a commitment to honesty about scope.

**Synchronous three-party collusion.** When the subject, the gateway, and the sink all collude against an absent delegator within a bilateral-receipt deployment, every signature on the record is genuine. The delegator's only recourse is revocation (which future actions respect via liveness beacons), not retroactive invalidation of actions taken during the collusion. No architecture closes this without making the delegator synchronous to every action, which defeats delegation.

**Full sink compromise.** When the sink is in the same trust domain as the gateway (same operator, same cloud tenant, same admin plane), sink-side closure constructions reduce to gateway-side closure constructions with extra ceremony. This is a deployment-topology limit. Operators running APS should deploy sinks in trust domains genuinely distinct from gateways where the security property matters.

**Dumb Web2 sinks.** For Web2 targets that cannot verify delegation semantics, structural closure is not available. The hardening stack narrows but does not close the gap. Deployments using APS against Web2 targets must accept residual gateway-compromise risk. This is a property of 2026's Web2 surface area, not of APS.

**Read-only fraud in non-ABE deployments.** Forged receipts for permitted reads that the subject never exercises are not detectable by any observable-state construction, and ABE-at-source is available only in narrow deployment bands. This residual is narrower than the dumb-sink residual (it applies only to reads) but real.

---

## Commitment

**APS v2.3.x:** Ships bilateral receipt support in the Dumb Web2 sink hardening stack (Component A). Emission adopts the in-toto Decision Receipt predicate once the predicate specification stabilizes upstream. This remains the ecosystem-level primary integration path.

**APS v3.0 (research target, no fixed date):** Implements the full APS-aware closure stack (Components 1 through 4): sink-authored canonical challenge, consumable authority tokens, sink-signed effect receipt, typed epistemic receipts. Draft wire-format specification at `docs/CAPABILITY-TOKEN-SPEC-DRAFT.md`. This is a protocol-level architectural change, not a patch to v2.x. Scope, compatibility with v2.x deployments, and integration with adjacent protocols (SINT, AIP, HDP) are all open design work.

**Universal hygiene layers (typed receipts, delegator beacons, canonical hashing):** Land incrementally in v2.3 through v2.5 without waiting for v3.0.

No fixed dates. Integration work on v3.0 begins when the in-toto Decision Receipt predicate is stable enough to pin and when at least one APS-aware sink implementation (MolTrust, AgentGraph, OATR, SINT-integrated agent, or our own MCP) commits to a parallel implementation track. We do not ship the closure stack unilaterally; composition requires adoption.

---

## V4 Research Directions

Named, not scoped. Directions that emerged from adversarial review as architecturally interesting but which are not on any v3 roadmap.

**Negative capability architecture.** The default state of every agent is unable-to-act; enforcement is controlled removal of independently-held blockers rather than issuance of permits. This inverts the trust geometry and maps cleanly onto BBIS's admissibility-under-structural-impossibility framing. Survived adversarial review in narrow form (reduces to sink-enforced one-shot blocker release), but the full architectural claim is worth a paper-level writeup before committing to scope.

**Stateless-invariant structurally-enforcing credentials.** BBS+ or anonymous credentials with zero-knowledge proof of attribute narrowing, where scope attenuation is enforced by the signature scheme rather than by policy engine evaluation. Survived narrowly for static-scope use cases. The pairing-based crypto ecosystem is narrow and post-quantum migration is unresolved, but for specific high-value use cases this may be the right construction in the 2028 timeframe.

**BBIS admissibility semantics as primary framing.** Steven Kyle Hensley's BBIS framework (at `OWASP/www-project-top-10-for-large-language-model-applications#817`) uses language that maps more cleanly onto the surviving architectural claim than our current "enforcement boundary" vocabulary. A cross-walk between APS's closure-stack vocabulary and BBIS's admissibility-under-composition vocabulary would sharpen both specifications and make cross-implementation verification easier.

---

## Open Design Questions

These are real questions on the APS-aware closure stack. They are not rhetorical.

1. **Where does the subject's signature come from for non-human subjects in the bilateral-receipt hardening path?** Agent's own delegated key (circular for certain threat models), issuer's key (reintroduces the issuer as trust anchor), or behavioral-attestation proxy from a distinct trust provider (pushes the anchor to the provider). The right answer may be "all three, declared in the receipt's typed-epistemic labeling."

2. **How does bilateral-receipt verification fail gracefully for offline subjects?** Daemon agents that act while disconnected cannot co-sign in real time. Options: pre-signed batched acknowledgments scoped to a time window, delegated co-signing through a subject-controlled service, or tolerating a single-signature receipt with a reduced-trust grade and explicit `co_signature_deferred` typing.

3. **What is the canonical action tuple for pre-execution denial?** A deny-receipt has no post-execution half because the action never occurred. Counterfactual denial witnesses (denial registered with an external witness service before challenge expiry) are one answer. Log-inclusion (Component B) is another. The choice affects the shape of the typed-epistemic labeling on deny receipts.

4. **How does the sink-authored challenge (Component 1) handle sinks that cannot be upgraded?** The APS-aware closure stack presupposes sinks that can author challenges. For sinks that can be instrumented with a thin APS proxy but cannot be rewritten, where does the proxy sit in the trust topology, and how is proxy compromise distinguished from sink compromise?

5. **What is the revocation semantics of consumable authority tokens (Component 2) when a delegator revokes mid-flight?** Tokens already issued to the subject remain cryptographically valid. The sink's nullifier set does not know about revocation. Does revocation propagate via liveness beacon invalidation (which then invalidates the challenge freshness requirement), or via an explicit revocation-of-tokens mechanism that the sink consults?

These are the questions v3.0 design work must answer. Several are addressed in preliminary form in `docs/CAPABILITY-TOKEN-SPEC-DRAFT.md`.

---

## Process Note

This document synthesizes multiple rounds of adversarial architectural review. Every construction labeled as full closure or subset closure survived hostile-destruction analysis against the stated threat model. Every construction labeled as detection / deterrence, composition primitive, or architectural limit failed to survive as standalone closure and is categorized accordingly.

Claims were not softened to preserve prior architectural positions. v1.0's "four closure paths" framing was superseded because it conflated full closure with partial and detection-only primitives; the sink-awareness reorganization and five-bucket taxonomy in v1.1 are the convergent output of the review process.

---

## Revision History

**v1.1 (2026-04-23).** Sink-awareness reorganization after adversarial architectural review. Five-bucket taxonomy introduced. APS-aware closure stack (Components 1-4) and dumb-sink hardening stack (Components A-E) separated explicitly. Architectural limits named as such, not as implementation gaps. v3.0 research target added. BMO ground-truthing, MPC-TLS network binding, ABE-at-source, and delegator liveness beacons added as typed components. Forward-secure chained keys considered and excluded (equivocation attack). MPC-TLS correctly reframed as detection substrate rather than primary closure. v1.0's four paths retained in spirit under the new organization: Path 1 (bilateral) becomes Component A, Path 2 (tamper-evident log) becomes Component B, Path 3 (TEE) absorbed into the discussion of tiny attested releasers for future scope, Path 4 (quorum) split into receipt-cosigning quorum (weak, as originally described) and effect-token threshold issuance (strong, the distinction was load-bearing and went unnamed in v1.0).

**v1.0 (2026-04-22).** Initial specification. Four closure paths: bilateral receipts, tamper-evident log, TEE-backed gateway, multi-gateway quorum. Primary integration path committed to bilateral receipts via the in-toto Decision Receipt predicate. Retained in git history for reference.
