# Enforcement Trust Anchor — The Single-Gateway Attestation Gap

**Status:** acknowledged gap, closure paths enumerated, primary path targeted for v2.3.x
**Scope:** specification document describing a boundary the APS reference deployment does not currently close

---

## Scope

### What APS closes today

APS closes cryptographic provenance through the boundary:

- **Delegation chain integrity.** Every hop from the root principal to the acting agent is Ed25519-signed. Monotonic narrowing is enforced at verification time — no hop can grant more authority than its parent.
- **Issuer-signed passports.** The subject-to-public-key binding is signed by the issuing principal and independently verifiable against the principal's JWKS without touching the gateway.
- **Scope-token attribution.** Action tuples reference delegation scope tokens whose signatures chain back to the root.
- **Passport grades and attestation tiers.** The evidence ladder (infrastructure > behavioral > self-declared) is itself signed by the grader and re-verifiable offline.

An external auditor holding only the passport, the delegation chain, and the root principal's JWKS can verify everything above without trusting the gateway.

### What APS does not close today

APS does not close single-gateway forged-attestation resistance at the enforcement boundary.

The gateway is both judge and executor. In the current reference deployment, it is also the sole signer of the `PolicyReceipt` that attests the enforcement decision occurred. That final attestation is a single-party assertion. There is no independent witness for the decision and no external commitment that fixes the receipt in time before it becomes citable.

This document names that gap, explains what still survives gateway compromise, and maps the four closure paths.

---

## The Gap

**Formal statement:** In the current reference deployment, a compromised gateway can emit a cryptographically valid `PolicyReceipt` attesting to an enforcement decision that did not actually occur. APS's upstream provenance layer remains intact in this scenario; the gap is at the final enforcement-boundary attestation.

The forgery surface is narrower than it first appears, but it is real.

### What upstream evidence still survives gateway compromise

A compromised gateway cannot rewrite history upstream of itself. The following remain verifiable end-to-end without the gateway's participation:

- **The delegation chain.** Signatures are held by each delegator's key. A gateway does not hold those keys and cannot forge new hops into the chain without breaking Ed25519.
- **The passport binding.** The subject DID ↔ public-key binding is signed by the issuing principal, not by the gateway.
- **The root principal's authority.** JWKS publication is out-of-band (did:web, IPFS, institutional PKI). The gateway does not mediate principal identity.
- **Out-of-scope forgeries.** If a gateway fabricates a receipt authorizing an action whose scope exceeds the delegation's leaf-hop scope, a third-party verifier with the chain in hand detects the mismatch immediately. Monotonic narrowing is a mechanical check, not a trust-in-the-gateway check.

### What is undetectable without composition

The residual forgery surface is the set of receipts that fabricate a **within-scope** enforcement decision — i.e., a decision the gateway *could* have legitimately made. A gateway that forges a `PolicyReceipt` saying "I decided ALLOW for action X within scope Y" cannot be caught by chain re-verification, because both the action and the decision fall inside what the delegation chain already authorized. The only thing that did not happen is the actual decision event at the gateway.

Closing this surface requires an independent witness to the decision or a pre-commitment that fixes the receipt before it is citable. Every closure path below implements one of those two primitives.

---

## Closure Paths

Four independent paths close the gap. They are not mutually exclusive; Paths 1 and 2 compose cleanly, and 3 and 4 are complementary to both. Our priority order reflects integration readiness and external momentum, not theoretical strength.

### Path 1 — Bilateral Receipts

**Description.** The gateway signs the pre-execution decision over a canonical action tuple. The subject (the acting agent, or a party authorized to speak for it) signs the post-execution acknowledgment over the same tuple. Verifiers require both signatures. A forged receipt requires collusion with the subject's signer or theft of the subject's key; the gateway acting alone cannot produce a valid receipt.

This replaces a single-party assertion with a two-party commitment. The failure mode narrows from "gateway is compromised" to "gateway and subject are both compromised against the same target at the same time."

**Status.** External implementation shipping. APS integration slated for v2.3.x, gated on the predicate specification landing upstream.

**External references.**

- arian-gogani's Microsoft AGT PR #1333, merged: https://github.com/microsoft/agent-governance-toolkit/pull/1333
- in-toto Decision Receipt predicate proposal: https://github.com/in-toto/attestation/pull/549

**Our integration posture.** Primary closure path. Once the in-toto predicate stabilizes, we emit `PolicyReceipt` in that exact shape so Microsoft AGT and any other in-toto consumer can verify APS receipts with the same tooling they verify everything else. We contribute to the predicate thread rather than forking a parallel format.

### Path 2 — Tamper-Evident Log

**Description.** The gateway commits each receipt to a public append-only log before the receipt is citable as authority. A verifier checks the log-inclusion proof alongside the receipt signature. A forged receipt that was never committed to the log fails inclusion and is rejected.

This converts "the receipt is signed" into "the receipt was signed *and published at time T*," making silent forgery after the fact structurally impossible. It does not require the gateway to be honest; it requires the log's append-only property to hold.

**Status.** External partner implementation. Integration in design, no committed date.

**External reference.**

- MolTrust's Base L2 bridge: https://moltrust.com

**Our integration posture.** Complementary to Path 1. The bilateral receipt answers "who witnessed this decision"; the log answers "when was this decision fixed in time." Compose both and the forgery surface collapses to "gateway + subject collude *and* the log is broken" — three independent compromises.

### Path 3 — TEE-Backed Gateway

**Description.** The gateway runs inside a hardware trusted execution environment (Intel SGX, AMD SEV-SNP, AWS Nitro, Azure Confidential Computing). Receipts carry a remote-attestation quote proving the code that signed them is the code the operator claims is running. A compromised host can no longer silently swap gateway binaries.

**Status.** Roadmap. No prototype.

**Our integration posture.** Standard industry pattern, deferred behind Paths 1 and 2. A TEE closes the "malicious host" attack but not the "malicious operator with legitimate TEE" attack — a TEE attests to which binary ran, not to whether that binary was honest. Bilateral receipts (Path 1) close the harder problem; TEE is an orthogonal hardening layer we will adopt when the ecosystem converges on a remote-attestation verification format we can consume cleanly.

### Path 4 — Multi-Gateway Quorum

**Description.** K-of-N co-signature from independent gateway operators. A verifier requires at least K valid signatures over the same canonical receipt. No single operator compromise produces a valid receipt.

**Status.** Design space. No prototype.

**Our integration posture.** Lowest priority closure path due to operational complexity. Multi-operator quorum requires operator discovery, signature aggregation, threshold key management, partition-tolerance behavior, and — critically — a consistent view of "the same receipt" across operators who do not share state. These are solvable, but each is its own spec. Paths 1 and 2 close the same gap with lower coordination cost. We keep this path in the design space so that high-value deployments (institutional, regulated) can opt into it later without a protocol break.

---

## Commitment

**Target:** v2.3.x of the SDK ships bilateral-receipt integration built on the in-toto Decision Receipt predicate. `PolicyReceipt` emission adopts the predicate shape. Verification accepts both legacy single-signature receipts (warning emitted) and bilateral receipts (validated end-to-end).

**Gating condition:** integration work begins when the in-toto Decision Receipt predicate specification lands in a form stable enough to pin. We contribute to that thread rather than building against a moving target.

**No fixed date.** This is honest. The predicate is under active discussion upstream. We ship when the predicate is stable, not before.

---

## Open Questions

These are real design questions on the bilateral-receipt path. They are not rhetorical.

1. **Where does the subject's signature come from for non-human subjects?** The agent's own delegated key is the obvious answer, but that key was itself issued through the gateway being audited. Does the agent sign with its passport key (circular for certain threat models), with its issuer's key (reintroduces the issuer as trust anchor), or with a behavioral-attestation proxy from a distinct trust provider (pushes the anchor to the provider)? Each choice has different residual-compromise semantics, and the right answer may be "all three, declared in the receipt."

2. **How does bilateral-receipt verification fail gracefully for offline subjects?** Daemon agents that act while disconnected from their signing infrastructure cannot co-sign in real time. Options: pre-signed batched acknowledgments scoped to a time window; delegated co-signing through a subject-controlled co-signer service; tolerating a single-signature receipt with a reduced-trust grade and an explicit `co_signature_deferred` flag that the verifier can reject per policy. The choice affects which deployments can adopt v2.3.x without architectural changes on their side.

3. **What is the canonical action tuple when the gateway denies pre-execution?** A deny-receipt has no post-execution half because the action never occurred. A bilateral receipt with only the pre-execution signature is not forgery-resistant in the same way. The candidate is a symmetrical two-signature structure where the subject signs a deny-acknowledgment (either as part of the policy hook or via a separate ack flow), but this adds a round-trip to every denial. An alternative is to require Path-2 log inclusion for deny-receipts, on the premise that logged-and-timestamped is sufficient when there is no subject-side action to witness.

4. **How does receipt expiration interact with retroactive verification?** An auditor inspecting a receipt years later needs the log-inclusion proof (Path 2) or the subject's public key at signing time (Path 1). Key rotation and log sunset are both real. The receipt format should carry enough material that a future verifier can reconstruct the verification context without live access to the original gateway, subject, or log operator. This is a canonicalization decision that needs to land with the predicate, not after.

---

## Revision notes

This document acknowledges a gap in the APS reference deployment that a technical critique named correctly. Publishing the acknowledgment is the honest position, and it clarifies what integrating partners can and cannot assume about the current enforcement boundary. Closure is active work; this document updates as the paths land.
