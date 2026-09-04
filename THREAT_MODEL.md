# Agent Passport System threat model

This document states what APS defends, who it defends against, and where its protections stop. It is written for the verifier: the party who receives a receipt and has to decide whether to act on it. APS gives a verifier signed declarations to reason over. It does not make the decision for the verifier, and it does not see the world outside the protocol envelope.

The language here is deliberate. APS receipts are signed declarations about what the system observed. They are not causal proofs of agent cognition or of off-protocol outcomes. Read every protection below with that boundary in mind.

## Actors

- **Principal.** A human or organization that holds root authority and issues delegations. Accountable at the root of every chain.
- **Agent.** A program acting under a delegation. Holds a key, signs intents and receipts, may sub-delegate within its scope.
- **Gateway.** The enforcement point. Evaluates intents against policy and current state, permits or denies, and is both judge and executor on the actions it mediates.
- **Verifier.** Any party that receives a receipt and decides whether to rely on it. May be a counterparty, an auditor, another gateway, or a settlement system.
- **Issuer.** A party that signs attestations about agents or wallets (identity, behavioral, sybil signals). Independent issuers stand on their own signatures.
- **Attacker.** Anyone trying to get a verifier to act on a receipt the verifier should refuse, or to act outside the authority a principal granted.

## Assets

- **Authority.** The right to take a scoped action under a delegation. The thing every attack is ultimately trying to widen.
- **Receipts.** Signed records of intents, decisions, actions, custody, contests. The evidentiary substrate.
- **Keys.** Ed25519 private keys held by principals, agents, gateways, and issuers.
- **Delegation state.** Who currently holds what scope, and what has been revoked or expired.
- **Funds and side effects.** The real-world consequences a payment or action causes outside the protocol.

## Trust boundaries

1. **Principal to agent.** The principal trusts the agent only within the delegated scope. Authority can only decrease at each transfer point. Sub-delegation narrows, never widens.
2. **Agent to gateway.** The agent cannot self-permit. Every gated action passes through the gateway's evaluation. The agent cannot skip the check.
3. **Gateway to verifier.** The verifier does not have to trust the gateway's word. The receipt carries a signature and a scope of claim the verifier checks independently.
4. **Issuer to verifier.** The verifier decides which issuers it trusts. APS carries the attestations; it does not adjudicate issuer reputation.
5. **Protocol to world.** The boundary APS cannot cross. A receipt says a payment was authorized on a rail. Whether the goods shipped is outside the protocol.

## Attacker capabilities (assumed)

The model assumes an attacker who can:

- Submit arbitrary receipts to a verifier, including syntactically valid, correctly signed ones obtained legitimately.
- Replay receipts it has seen.
- Tamper with receipt bodies and resubmit.
- Hold a real key for a real low-scope delegation and try to use it beyond scope.
- Race revocation: act in the window between a revocation event and a verifier learning about it.
- Present a sound receipt of one type as evidence for a claim it does not make.
- Self-attest external facts and present them as independently observed.

The model does NOT assume an attacker who can:

- Forge an Ed25519 signature without the private key.
- Find a SHA-256 preimage or collision for a receipt body.
- Compromise the verifier's own evaluation code.

## What APS prevents

- **Forgery.** A receipt body is signed over its RFC 8785 JCS canonical form. Altering any signed field breaks the signature. The `receipt_id` is the SHA-256 of the canonical body, and the signature covers the `receipt_id`, so post-signing tampering is detectable as either a signature failure or a hash mismatch.
- **Silent scope escalation.** Delegation chains narrow monotonically. A sub-delegation that tries to widen scope is invalid. The gateway evaluates the action against the chain, not against the agent's assertion.
- **Self-permitting.** An agent cannot produce a valid policy decision for its own action. The decision is signed by the policy evaluator, a separate signature in the chain.
- **Authority that outlives its grant.** Expiry and revocation are first-class. A verifier that consults current delegation state rejects receipts issued under an expired or revoked chain, even when the receipt itself is older than the revocation event.
- **Replay, when the verifier tracks it.** A receipt carries a stable `receipt_id`. A verifier that records accepted ids in its window rejects a resubmission.
- **Claim laundering.** A receipt declares its own `scope_of_claim`. A sound receipt of one type presented as proof of a different claim is rejected by a verifier that checks the claim it is being asked to support.

## What APS does not prevent

- **Off-protocol outcomes.** A receipt that an action was authorized is not a receipt that it succeeded, or that the world changed the way the principal intended. A payment receipt does not prove delivery.
- **Key compromise.** If an attacker holds a valid private key, it can sign valid receipts within that key's scope. APS limits the blast radius to the key's scope and makes the activity auditable; it does not detect that the human behind the key changed.
- **A correctly scoped but unwise action.** APS enforces the boundary the principal set. If the principal granted too much, APS will faithfully enforce too much. Scope design is the principal's responsibility.
- **Bad policy.** APS runs the policy it is given and signs the verdict. It does not judge whether the policy was the right one.
- **Honesty of self-attested evidence.** A `self_attested` receipt is exactly as trustworthy as the signer. APS marks it as self-attested so a verifier can weight it accordingly; it does not independently confirm the underlying fact.
- **A compromised or lazy verifier.** Every protection above is conditional on the verifier actually running both verification layers. APS provides the checks; it cannot force the verifier to run them.

## Verifier responsibilities

A verifier relying on an APS receipt MUST, at minimum:

1. **Run the crypto layer.** Confirm the `claim_type` is the one expected, recompute the `receipt_id` from the canonical body and confirm it matches, and verify the Ed25519 signature under the signer's key.
2. **Run the context layer.** Confirm the delegation chain is current (not expired, not revoked), the action is within budget and scope, the accountable principal is the expected one, the policy version evaluated is the active one, and the `receipt_id` has not been seen before in the window.
3. **Check the scope of claim.** Read `asserts` and `does_not_assert`. Do not rely on a receipt for anything it explicitly does not assert. Weight `self_attested` evidence accordingly.
4. **Decide issuer trust explicitly.** For attestations, decide which issuers you trust before relying on their signatures. APS does not make this call for you.
5. **Match payments end to end.** For payment receipts, confirm amount, currency, and recipient match across intent, decision, and receipt. See the Payment Safety Profile.

The conformance package under `tests/conformance/` ships a golden valid fixture and a negative fixture for each rejection a verifier must make, so an implementation can prove it discharges these responsibilities.

## Assurance argument

The security expectations above hold because of design choices that map to
standard secure-design principles, and countermeasures against the common ways
implementations fail.

Design principles, as instantiated here:

- **Least privilege.** Delegation scope narrows monotonically at every
  transfer. No operation widens authority downstream.
- **Complete mediation.** Every gated action passes the gateway's evaluation;
  an agent cannot self-permit, and the decision carries its own signature.
- **Fail-safe defaults, for the verifiers where it is established.** The
  authority-aware verifiers named in `docs/verification-boundary.md` fail
  closed: a malformed or unreadable input yields an explicit invalid result
  rather than a pass, and the top-level verifier's never-throws contract is
  guarded by test. What establishes that is the 6.0.0 suite: table-driven
  timestamp tests over those verifiers, an attacker-side test for each defect
  the 6.0.0 advisory lists that the fixed implementation refuses, and
  adversarial tests written against the repaired code after the fix. Some
  lower-level helpers authenticate an artifact against a key the artifact
  carries; they establish integrity, not signer authority, and an integrity-only
  result must not be used as an authorization decision.
- **Economy of mechanism.** One signature suite (Ed25519), pinned canonical
  byte forms covered by conformance fixtures, and two runtime dependencies.
- **Separation of privilege.** Principal, agent, gateway, and issuer sign with
  distinct keys in distinct roles; no signature stands in for another's.

Common implementation weaknesses, as countered:

- **Untrusted input.** Decoders bound declared lengths against the bytes
  actually present. The parsers are fuzzed continuously (seven Jazzer.js
  harnesses via ClusterFuzzLite, with found-bug inputs kept as regression seeds)
  and property-tested with fast-check. The claim is scoped to what those runs
  cover: validation before use is established for the verifiers named in
  `docs/verification-boundary.md` and for the parsers under the fuzz harnesses,
  not for every externally supplied structure the package accepts. Before 6.0.0
  several verifiers read a timestamp they could not parse and treated it as no
  bound at all.
- **Injection and dynamic execution.** No eval, no dynamic code loading. Only
  the CLI invokes external programs, by explicit exec of fixed binaries; the
  library spawns nothing.
- **Memory safety.** TypeScript and Rust only; no C or C++.
- **Known vulnerability classes.** CodeQL with the security-extended query set
  runs on every change; OpenSSF Scorecard runs on schedule.
- **Supply chain.** Dependencies locked and monitored, CI actions pinned to
  commit hashes, releases published with SLSA build provenance through OIDC
  Trusted Publishing.

Scope of claim: this section argues the design; the conformance fixtures and
CI runs are what exercise it.

## Scope of claim for this document

Proves: this document specifies the actors, boundaries, and the verification a conformant verifier must perform. It is matched by the conformance fixtures, which a verifier can run.

Does not prove: that any particular deployment is correctly configured, that the verifier runs the checks, or that any off-protocol outcome occurred. This is a specification of the boundary, not a guarantee about the world beyond it.
