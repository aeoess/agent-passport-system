# Enforcement Trust Anchor: The Single-Gateway Attestation Gap

**Status:** v1.2, BBIS classification grammar adopted after OWASP#817 convergence
**Scope:** specification document describing a boundary the APS reference deployment does not currently close, and the closure paths available to it under realistic deployment constraints
**Supersedes:** v1.1 (2026-04-23), preserved in git history

---

## Changelog from v1.1

v1.1 introduced a five-bucket taxonomy (full closure, subset closure, detection / deterrence, composition primitive, architectural limit) that honestly classified which constructions close what. That taxonomy was APS-internal vocabulary.

v1.2 adopts the BBIS classification grammar from Steven Kyle Hensley's OWASP#817 thread (comment 4306306... and the surrounding consolidation). The BBIS vocabulary (closed / bounded / partial / detectable-only / theater, with composition primitive and architectural limit preserved as orthogonal categories) is more precise than the v1.1 labels and is becoming the cross-ecosystem shared language across APS, BBIS, AgentGraph CTEF, AgentID, and the A2A governance layer. Aligning here removes a translation surface at cross-implementation verification time.

The architectural claim v1.1 committed to is unchanged in v1.2: **the gateway must stop being the component that both describes the action and originates the usable authority for it.** v1.2 sharpens two framings on top of that claim. First, Class B (bounded) constructions are the correct classification for several APS components and must not be presented as path upgrades via typed epistemic receipts. Typed epistemic receipts are an honesty discipline over bounded claims, not a promotion from bounded to closed. Second, the sink-authored challenge plus sink-signed effect receipt pair is the cryptographic instantiation of what Hensley named the Final Refusal-Capable Boundary Event (FRCBE) on qntm#7. v1.2 adopts that naming and credits the coinage.

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

## Classification Grammar

Every construction in this document is classified per the BBIS grammar introduced by Steven Kyle Hensley at `OWASP/www-project-top-10-for-large-language-model-applications#817`. BBIS is the cross-ecosystem shared vocabulary that APS, BBIS, AgentGraph CTEF, AgentID, and the A2A governance layer are converging on. Using it here reduces translation overhead at cross-implementation verification time and prevents the kind of overclaiming that a more permissive vocabulary invites.

The classes below are not a ladder where each construction aspires to climb. They are honest labels. A bounded construction is bounded; adding honesty discipline on top does not make it closed.

**Closed / strongly admissible.** The construction removes the compromised party from the critical path for the attested property, or makes the attested property structurally impossible to forge under the stated threat model. No honesty assumption on the compromised party is required. In APS's case, this means: the gateway is not the party whose signature carries the attested property, and a compromised gateway key does not produce a receipt a verifier will admit as evidence of that property.

**Bounded end-to-end governance.** The construction closes a specific refusal boundary from one structurally distinct endpoint to another (for example, sink authors the canonical action and sink witnesses the effect, making semantic drift and fake-enforcement both inadmissible). The closure holds end-to-end for the bounded property, but does not extend past the bounded scope to cover every facet of the broader attestation claim. Bounded constructions are the workhorse of the APS-aware closure stack. They are correctly labeled bounded, not closed, because other axes of the broader attestation claim remain unresolved.

**Partial governance.** The construction preserves some refusal boundaries but not the refusal boundaries that reach the true irreversible authority. Bilateral receipts are the canonical case: a second signature raises the forgery cost from one-party compromise to two-party collusion, which is a real refusal boundary, but the authority being attested is still narrated by one of the two parties rather than structurally emitted by the independent endpoint that actually executed the effect. Partial is stronger than detectable-only and weaker than bounded.

**Detectable-only / witnessed governance.** The construction makes forgery detectable after the fact, or raises the cost of undetected forgery, without preventing forgery at the moment of attack. Useful for accountability and economic bounds on fraud, not for synchronous correctness. Tamper-evident logs and BMO forensic overlays sit here. A detectable-only construction that is presented as closure is governance theater.

**Governance theater (anti-pattern).** A construction that claims closure while delivering at most partial or detectable-only governance. This is named explicitly as a class so that documents, receipts, and audit reports can refuse to classify constructions into it by accident. Our Class B framing in v1.1 skirted this line by suggesting typed epistemic receipts upgraded bounded claims; v1.2 corrects that explicitly in the "Honesty Discipline vs Admissibility Upgrade" section below.

**Composition primitive.** Orthogonal to the closure ladder. A building block (canonical hashing, timestamp witnesses, Merkle proofs, log inclusion proofs) that strengthens other constructions but does not by itself close any meaningful sub-problem.

**Architectural limit.** Also orthogonal to the ladder. Under the stated threat model, closure by this path is not available with deployable primitives in 2026. Naming architectural limits explicitly prevents the doc from becoming a wish list.

Credit: the closed / bounded / partial / detectable-only / theater classification is Hensley's BBIS grammar from OWASP#817. Composition primitive and architectural limit are APS additions that compose with the BBIS ladder without interfering with it. The remainder of this document applies the grammar to each APS construction.

---

## Closure Stack for APS-Aware Sinks

For targets that can verify delegation-bound tokens natively, the following composition closes the within-scope forgery surface.

### Component 1: Sink-Authored Canonical Challenge

**Class:** bounded end-to-end governance (closes semantic drift between described and executed action).

**Description.** The sink, not the gateway, defines the canonical statement of what action is being requested. A subject first asks the sink for an action challenge containing the canonicalized effect object (action type, target, parameters, resource version, nonce, expiry), signed by the sink. The gateway's role is reduced to: evaluating policy against the sink-authored challenge and signing an evaluation receipt bound to the exact challenge hash. The sink accepts the resulting token only if it binds to its own previously-issued challenge.

**What it closes.** "Receipt describes one action, system executed another." The gateway loses the ability to narrate action semantics. A forged receipt for a different action fails sink admission because the challenge hash does not match.

**Residual.** Does not close stale-policy-state fraud or dynamic-invariant violations. Component 2 and Component 4 address these.

### Component 2: Consumable Authority Tokens

**Class:** bounded end-to-end governance (closes authority invention by the gateway).

**Description.** Authority is represented as a finite set of cryptographic consumable tokens minted by the delegator (not the gateway) at delegation time. Each token is bound to a narrow action class and a nullifier. The gateway's role is to evaluate policy against a sink-authored challenge and countersign the consumption of a specific token against that challenge. The sink maintains a nullifier set and rejects double-spends. A compromised gateway cannot invent tokens; it can only consume tokens the delegator already minted.

**What it closes.** Gateway-originated authority inflation. Widening beyond what was minted requires forging the delegator's signature, which is outside the threat model. Replay of previously-consumed tokens fails at the sink nullifier check.

**Residual.** Pre-hoarding attacks where a subject extracts receipts for many tokens before a delegator revokes. Mitigation: strict expiry per token, or binding tokens to challenge freshness such that expired challenges invalidate the consumption.

### Component 3: Sink-Signed Effect Receipt (the FRCBE)

**Class:** closed / strongly admissible for positive-effect actions (truth comes from the sink, not the gateway).

**Description.** After executing the authorized action, the sink emits its own signed receipt binding the redeemed token to the actual effect. This receipt is the primary attestation that enforcement occurred. The gateway's prior evaluation receipt becomes corroborating metadata, not the authoritative record. A forged gateway receipt for an action the sink never executed has no matching sink receipt and is inadmissible to any verifier that requires both.

**What it closes.** "Gateway claimed it enforced, but the action never reached the sink." The attestation root moves to the component that actually witnessed the effect.

**Residual.** Sink compromise (the sink must be in a trust domain distinct from the gateway), read-only actions with no observable effect, actions with out-of-band alternate paths the sink does not mediate.

### Final Refusal-Capable Boundary Event (FRCBE)

The pair (sink-authored canonical challenge, sink-signed effect receipt) is the cryptographic instantiation of what Steven Kyle Hensley named the **Final Refusal-Capable Boundary Event (FRCBE)** on `corpollc/qntm#7`. The FRCBE is the point where refusal is still mechanically possible and where, once the boundary is crossed, the effect is attested by the party that executed it rather than the party that evaluated policy. BBIS uses FRCBE as the primitive around which closed-class constructions are defined; APS uses the same primitive and adopts the name.

At wire format, the FRCBE is materialized in `docs/CAPABILITY-TOKEN-SPEC-DRAFT.md` v0.2 as the M4 message, renamed from EffectReceipt to FRCBE in that revision. M4 is the boundary event (sink-signed, refusal-capable). Any post-effect forensic artifact is a separate optional M5 ExecutionReceipt, not the boundary event itself. The rename is not cosmetic: it prevents readers from treating M4 as a post-event record when structurally it is the boundary event that closes the gap.

Credit: Hensley coined FRCBE in the consolidation at `corpollc/qntm#7`. The APS instantiation is Components 1 and 3 composed; the naming and the reason-to-split-from-post-effect-forensic are BBIS.

### Component 4: Typed Epistemic Receipts

**Class:** honesty discipline (not a closure class, not a classification upgrade).

**Description.** Receipts explicitly label each claim they carry as `closed` (cryptographically verifiable without honesty assumption), `bounded` (closed for the bounded scope declared in the receipt, unresolved past that scope), `witnessed` (verified by an external party under a stated threat model), or `unresolved` (asserted but not externally attested). A verifier consuming the receipt can reject unresolved claims per policy, refuse to cite them as enforcement evidence, or treat them as provisional.

**What it closes.** Overclaiming. A receipt that mixes closed, bounded, and unresolved claims without typing smuggles self-assertion into a record that looks cryptographically strong. Typed epistemic receipts make the honesty visible at the wire format level.

**Residual.** Social pressure to collapse the type system. Downstream consumers (investors, auditors, compliance bodies) may ignore the distinction and cite all signed claims as equivalent. This is a governance discipline problem, not a cryptographic one.

### Honesty Discipline vs Admissibility Upgrade

Typed epistemic receipts are an honesty discipline over bounded and partial claims. They are not a path that upgrades a bounded construction into a closed construction, and v1.2 says so explicitly.

A Component 1 + Component 2 receipt is bounded end-to-end governance. Adding `epistemic_claims` fields labeled `closed`, `bounded`, and `unresolved` to that receipt does not change its BBIS classification: the constructions it carries are still bounded, and the receipt is now simply honest about which facets are bounded versus unresolved. The admissibility label moves from "bounded but silently overclaimed" to "bounded and correctly labeled." That is progress on the honesty axis. It is not a class upgrade.

Upgrading to closed requires a structural change to the construction itself (adding Component 3 for positive-effect actions, adding an independent witness for effects the sink cannot sign, or moving the attestation root off the gateway by another mechanism). No amount of typing or labeling creates this upgrade.

This distinction matters because governance theater frequently smuggles itself in as "we added typed claims, therefore the receipt is now admissible." The BBIS grammar refuses that move, and v1.2 adopts the refusal.

### The Composed Closure

Together, Components 1 through 4 implement the architectural claim: the sink defines the action (not the gateway), the delegator originates authority (not the gateway), the sink witnesses the effect (not the gateway), and the receipt honestly labels what is closed versus bounded versus unresolved. The gateway's role collapses to policy evaluation against an externally-defined action, under externally-minted authority, with externally-witnessed effect. A compromised gateway retains the ability to deny actions it should have permitted (a liveness failure, not an integrity failure) and to approve within-scope actions that the delegator would have preferred it deny (the triple-collusion residual, named below).

---

## Hardening Stack for Dumb Web2 Sinks

For targets that accept ordinary HTTP requests and cannot evaluate delegation semantics, structural closure of the within-scope forgery surface is not available at the protocol layer. This is not a failure of imagination. It is a consequence of the fact that whoever holds the connection to a dumb sink has absolute power over the sink. No amount of gateway-side cryptography forces a sink that does not read cryptography to respect it.

What is available is hardening. The following constructions narrow the gap and raise forgery cost, but none provides structural closure for dumb sinks. Deployers using APS against dumb sinks must accept residual gateway-compromise risk and layer defense-in-depth accordingly.

### Component A: Bilateral Receipts

**Class:** partial governance (some refusal boundaries survive, but not all the way to the true irreversible authority).

**Description.** Gateway and subject both sign the canonical action tuple, pre-execution (gateway) and post-execution (subject). The in-toto Decision Receipt predicate at `in-toto/attestation#549` is the current ecosystem-level effort. A forged receipt requires collusion with the subject's signer.

**What it closes.** Single-party gateway fabrication, against a non-colluding subject.

**Residual.** Subject-gateway collusion. When the subject's signing key lives on the same machine as the gateway under the same operator, both compromises are one compromise. This is the widest residual in the dumb-sink hardening stack. Partial rather than bounded because the co-signer (the subject) is the party that requested the action, not the party that executed the effect at the true irreversible authority (the sink).

### Component B: Tamper-Evident Log with Pre-Effect Commitment

**Class:** detectable-only / witnessed governance.

**Description.** Gateway commits each receipt to a public append-only log before the receipt is citable. Silent forgery after the fact becomes detectable as log divergence. Does not prevent forgery at the moment of attack but makes sustained fraud visible.

**What it closes.** Retroactive fabrication where the gateway attempts to backdate or rewrite decisions. Also enables third-party audit without requiring sink cooperation.

**Residual.** Live forgery within the current window. An honest log does not make a dishonest decision honest.

### Component C: Homomorphic State Commitments for Arithmetic Invariants

**Class:** bounded end-to-end governance (closes arithmetic-invariant forgery).

**Description.** For stateful policy invariants (spend caps, rate limits, reserve ratios), the gateway maintains a public homomorphic accumulator over per-subject counters. Every receipt includes a proof that updating the accumulator by the receipt's delta does not violate the declared invariant. A forged receipt that would breach the cap produces a detectable commitment mismatch at any verifier with the public accumulator root.

**What it closes.** Gateway forgery that violates arithmetic invariants. For commerce delegations specifically (spend caps, budget tracking), this is load-bearing. Bounded because the arithmetic invariant is the bounded scope; forgery within the invariant but outside the arithmetic is not addressed by this component.

**Residual.** Does not close forgery that stays within arithmetic bounds but violates discretionary policy.

### Component D: MPC-TLS Network Binding for High-Value Transactions

**Class:** detectable-only / witnessed governance, with narrow bounded applicability for specific payload-narration claims.

**Description.** For specific high-value transactions where latency of seconds is acceptable (institutional transfers, bonded commerce authorizations), MPC-TLS constructions (DECO, TLSNotary, zkTLS variants) produce a proof that the gateway transmitted a specific payload over the TLS tunnel. Does not prevent the transmission; produces evidence after the fact that can be used in fraud proofs.

**What it closes.** Gateway narration of what was sent to the sink. Compromised gateway cannot claim it sent Payload A when the MPC proof attests Payload B.

**Residual.** Write-mode verification paradox: the target executes before the proof is checked. The prover network is a new trust root that can collude with the gateway. TLS 1.3 compatibility is partial. Latency is prohibitive for interactive agent workflows. MPC-TLS survives as a forensic tool for specific high-value transactions, not as a primary closure.

### Component E: BMO Ground-Truthing as Forensic Audit Overlay

**Class:** detectable-only / witnessed governance (APS-native).

**Description.** APS already emits Behavioral Memory Objects tracking subject behavior under delegations. A receipt claiming scope Y for delegation D can be marked `behaviorally confirmed` only when subsequent BMO evidence demonstrates the subject actually exercised scope Y. Forged receipts for scope never exercised by the subject produce receipts without behavioral support.

**What it closes.** Catches a specific fraud class not addressed by other layers: fabricated receipts for unexercised scope in long-lived delegations. Because APS already has the BMO substrate, this layer costs little to add.

**Residual.** Passive fraud (forged denial for an action the subject would have taken) is undetectable. Spurious confirmation (subject happens to exercise the forged scope by chance) produces false positives. BMO is an audit layer, not prevention.

### The Composed Hardening

For deployments against dumb sinks, the honest guidance is: compose A (bilateral receipts) as primary, B (tamper-evident log) as accountability baseline, C (homomorphic commitments) for stateful invariants where applicable, D (MPC-TLS) for specific high-value transactions where latency permits, and E (BMO audit) as always-on forensic overlay. The composition narrows the gap substantially but does not close it. The residual is named below as an architectural limit. In BBIS grammar, the composed dumb-sink stack remains partial governance (A) reinforced by detectable-only governance (B, D, E) with one bounded arithmetic guarantee (C), never closed.

---

## The Read-Path Residual

Actions with no observable state change at the sink are an orthogonal residual that neither the APS-aware stack nor the dumb-sink hardening stack fully addresses.

### Attribute-Based Encryption at Source

**Class:** bounded end-to-end governance in narrow deployment bands.

**Description.** For read-only actions against a data source in a trust domain distinct from the gateway, the source encrypts responses under a CP-ABE predicate tied to the delegation's attributes. The subject holds credentials whose attribute set satisfies the predicate; any other party receives ciphertext it cannot decrypt. The gateway is entirely removed from the read path. Its receipts for reads are advisory only; what governs is whether the subject can decrypt.

**What it closes.** Gateway forgery of permitted reads, when the source is genuinely in a distinct trust domain, policy is stable enough for encryption cycles to track, and the attribute authority is distributed (DKG or delegator-operated, not gateway-operated).

**Residual.** Attribute revocation is a known hard problem in CP-ABE. Policies that change faster than encryption cycles force re-encryption services that re-create the attestation gap. Applies only to stable-scope reads where the source cooperates. Does not apply to general Web2 reads.

### Accepted Residual

For deployments where ABE-at-source is not available (most Web2 cases), the honest position is: read-only actions remain within the gateway's attestation surface. Deployers should either accept the residual, compose with bilateral receipts (Component A) to narrow it, or restructure to produce observable state at the sink where possible (for example, logging reads to a tamper-evident access log at the resource).

---

## Universal Hygiene

Independent of which closure stack applies, three practices are recommended for all APS deployments.

**Typed epistemic receipts (Component 4 above).** Apply regardless of sink class. Receipts must explicitly distinguish closed from bounded from witnessed from unresolved claims. As the "Honesty Discipline vs Admissibility Upgrade" section makes clear, typing is honesty discipline, not a classification upgrade.

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

**APS v2.3.x:** Ships bilateral receipt support in the Dumb Web2 sink hardening stack (Component A, partial governance). Emission adopts the in-toto Decision Receipt predicate once the predicate specification stabilizes upstream. This remains the ecosystem-level primary integration path.

**APS v3.0 (research target, no fixed date):** Implements the full APS-aware closure stack (Components 1 through 4): sink-authored canonical challenge, consumable authority tokens, sink-signed FRCBE, typed epistemic receipts. Draft wire-format specification at `docs/CAPABILITY-TOKEN-SPEC-DRAFT.md` (v0.2 and later). This is a protocol-level architectural change, not a patch to v2.x. Scope, compatibility with v2.x deployments, and integration with adjacent protocols (SINT, AIP, HDP, AgentGraph CTEF) are all open design work.

**Universal hygiene layers (typed receipts, delegator beacons, canonical hashing):** Land incrementally in v2.3 through v2.5 without waiting for v3.0.

No fixed dates. Integration work on v3.0 begins when the in-toto Decision Receipt predicate is stable enough to pin and when at least one APS-aware sink implementation (MolTrust, AgentGraph, OATR, SINT-integrated agent, or our own MCP) commits to a parallel implementation track. We do not ship the closure stack unilaterally; composition requires adoption.

---

## V4 Research Directions

Named, not scoped. Directions that emerged from adversarial review as architecturally interesting but which are not on any v3 roadmap.

**Negative capability architecture.** The default state of every agent is unable-to-act; enforcement is controlled removal of independently-held blockers rather than issuance of permits. This inverts the trust geometry and maps cleanly onto BBIS's admissibility-under-structural-impossibility framing. Survived adversarial review in narrow form (reduces to sink-enforced one-shot blocker release), but the full architectural claim is worth a paper-level writeup before committing to scope.

**Stateless-invariant structurally-enforcing credentials.** BBS+ or anonymous credentials with zero-knowledge proof of attribute narrowing, where scope attenuation is enforced by the signature scheme rather than by policy engine evaluation. Survived narrowly for static-scope use cases. The pairing-based crypto ecosystem is narrow and post-quantum migration is unresolved, but for specific high-value use cases this may be the right construction in the 2028 timeframe.

**BBIS admissibility semantics as wire-format-level grammar.** v1.2 adopts BBIS classification labels in prose. A further step is adopting BBIS labels at the wire-format level (per-receipt bounded_scope tokens, per-receipt refusal_boundary declarations) so that verifiers can enforce classification machine-readably. This is one of the open design questions below; it becomes research once a concrete wire-format proposal exists.

---

## Open Design Questions

These are real questions on the APS-aware closure stack. They are not rhetorical.

1. **Where does the subject's signature come from for non-human subjects in the bilateral-receipt hardening path?** Agent's own delegated key (circular for certain threat models), issuer's key (reintroduces the issuer as trust anchor), or behavioral-attestation proxy from a distinct trust provider (pushes the anchor to the provider). The right answer may be "all three, declared in the receipt's typed-epistemic labeling."

2. **How does bilateral-receipt verification fail gracefully for offline subjects?** Daemon agents that act while disconnected cannot co-sign in real time. Options: pre-signed batched acknowledgments scoped to a time window, delegated co-signing through a subject-controlled service, or tolerating a single-signature receipt with a reduced-trust grade and explicit `co_signature_deferred` typing.

3. **What is the canonical action tuple for pre-execution denial?** A deny-receipt has no post-execution half because the action never occurred. Counterfactual denial witnesses (denial registered with an external witness service before challenge expiry) are one answer. Log-inclusion (Component B) is another. The choice affects the shape of the typed-epistemic labeling on deny receipts.

4. **How does the sink-authored challenge (Component 1) handle sinks that cannot be upgraded?** The APS-aware closure stack presupposes sinks that can author challenges. For sinks that can be instrumented with a thin APS proxy but cannot be rewritten, where does the proxy sit in the trust topology, and how is proxy compromise distinguished from sink compromise?

5. **What is the revocation semantics of consumable authority tokens (Component 2) when a delegator revokes mid-flight?** Tokens already issued to the subject remain cryptographically valid. The sink's nullifier set does not know about revocation. Does revocation propagate via liveness beacon invalidation (which then invalidates the challenge freshness requirement), or via an explicit revocation-of-tokens mechanism that the sink consults?

6. **In BBIS classification, does bounded end-to-end governance require the scope boundary to be declared at the wire-format level (per-receipt `bounded_scope` token) or at the deployment-manifest level?** A wire-format declaration makes each receipt self-describing and rejects overclaims mechanically at verification time. A manifest-level declaration keeps receipts compact and puts the bounded-scope declaration in a separate signed artifact that verifiers fetch once per deployment. Both are viable; the choice affects verifier ergonomics and the density of typed-epistemic fields on receipts. v1.3 decides once Hensley answers the question on OWASP#817.

These are the questions v3.0 design work must answer. Several are addressed in preliminary form in `docs/CAPABILITY-TOKEN-SPEC-DRAFT.md`.

---

## Process Note

This document synthesizes multiple rounds of adversarial architectural review plus cross-ecosystem vocabulary convergence on the BBIS grammar. Every construction labeled closed or bounded survived hostile-destruction analysis against the stated threat model. Every construction labeled partial, detectable-only, composition primitive, or architectural limit failed to survive as standalone closure and is categorized accordingly.

Claims were not softened to preserve prior architectural positions. v1.0's "four closure paths" framing was superseded in v1.1 because it conflated full closure with partial and detection-only primitives. v1.1's APS-internal five-bucket taxonomy is superseded in v1.2 by Hensley's BBIS grammar (closed / bounded / partial / detectable-only / theater, with composition primitive and architectural limit preserved as orthogonal categories) because the BBIS vocabulary is the cross-ecosystem shared language and because naming governance theater explicitly prevents a class of overclaim that the v1.1 vocabulary permitted.

---

## Revision History

**v1.2 (2026-04-23).** Classification grammar switched from APS-internal five-bucket taxonomy to Hensley's BBIS grammar (closed / bounded / partial / detectable-only / theater) per OWASP#817. New Classification Grammar section added. Component labels updated per BBIS. Class B framing tightened: Component 4 explicitly relabeled as honesty discipline, not a classification upgrade. New "Honesty Discipline vs Admissibility Upgrade" subsection. Sink-authored challenge plus sink-signed effect receipt pair identified as the cryptographic FRCBE (Final Refusal-Capable Boundary Event), crediting Hensley's qntm#7 coinage. New FRCBE subsection. New open design question on wire-format-level vs manifest-level bounded-scope declaration. V4 research entry on BBIS wire-format-level grammar added. Cross-references to CAPABILITY-TOKEN-SPEC-DRAFT.md updated to point at v0.2 M4 FRCBE naming.

**v1.1 (2026-04-23).** Sink-awareness reorganization after adversarial architectural review. Five-bucket taxonomy introduced. APS-aware closure stack (Components 1-4) and dumb-sink hardening stack (Components A-E) separated explicitly. Architectural limits named as such, not as implementation gaps. v3.0 research target added. BMO ground-truthing, MPC-TLS network binding, ABE-at-source, and delegator liveness beacons added as typed components. Forward-secure chained keys considered and excluded (equivocation attack). MPC-TLS correctly reframed as detection substrate rather than primary closure. v1.0's four paths retained in spirit under the new organization: Path 1 (bilateral) becomes Component A, Path 2 (tamper-evident log) becomes Component B, Path 3 (TEE) absorbed into the discussion of tiny attested releasers for future scope, Path 4 (quorum) split into receipt-cosigning quorum (weak, as originally described) and effect-token threshold issuance (strong, the distinction was load-bearing and went unnamed in v1.0).

**v1.0 (2026-04-22).** Initial specification. Four closure paths: bilateral receipts, tamper-evident log, TEE-backed gateway, multi-gateway quorum. Primary integration path committed to bilateral receipts via the in-toto Decision Receipt predicate. Retained in git history for reference.
