# Security review, 2026

Scope, method, findings, and residual risk for the Agent Passport System TypeScript reference implementation. This review considers the security requirements and the security boundary stated in THREAT_MODEL.md.

## Scope and boundary

The requirements reviewed are the ones THREAT_MODEL.md commits to: forgery resistance over RFC 8785 canonical bytes, monotonic narrowing of delegation scope, no self-permitting, expiry and revocation as first-class, replay rejection under verifier tracking, and claim-scope discipline (a receipt is evidence only for what it asserts). The boundary reviewed is that document's trust-boundary list; anything past boundary five (protocol to world) is out of scope by design.

## Methods

* Static analysis: CodeQL with the security-extended query set on every change (.github/workflows/codeql.yml).
* Dynamic analysis: seven coverage-guided fuzz harnesses (Jazzer.js) over the parsers and verifiers with a history of load-bearing byte-exactness, run per pull request and on a scheduled batch via ClusterFuzzLite (fuzz/, .github/workflows/cflite_pr.yml, cflite_batch.yml), plus fast-check property tests for canonicalization determinism.
* Adversarial testing: hand-authored attack suites across the protocol layers, including cross-algorithm mismatch, replay, escalation, and claim-laundering cases.
* Supply chain: committed lockfiles for npm and cargo, with npm and GitHub Actions dependencies monitored by Dependabot; npm audit in the release gate; CI actions pinned to commit hashes; SLSA build provenance on npm releases.
* Cross-implementation checks: JCS equivalence tests against a second implementation (tests/cross-impl/).

## Findings

Two findings in this cycle, both from the fuzzing campaign, both fixed in 3.2.0 and kept as corpus regression seeds (fuzz/FINDINGS.md, CHANGELOG.md):

1. Unbounded CBOR map length hung decodeQntmInvite: a declared entry count was used as a loop bound without checking it fits the remaining bytes. Fixed by bounding declared lengths and making out-of-bounds reads hard errors.
2. verifyPassport threw on a non-array delegations field instead of returning an invalid result, violating its never-throws contract. Fixed with an explicit array guard.

No externally reported vulnerabilities were received in this cycle.

## Residual risk

The residual risks are the ones THREAT_MODEL.md names as outside protocol scope: key compromise (blast radius limited to the key's scope, activity auditable, compromise itself not detected), badly designed principal scopes faithfully enforced, and verifiers that skip the checks the protocol requires of them. The conformance fixtures under tests/conformance/ exist so a verifier can prove it runs those checks.

## Review record

Performed by the maintainer across the 3.2.0 cycle, with each fuzzing finding verified fixed by re-running the finding's own fuzz target against the fix. Next review: within twelve months, or upon any externally reported vulnerability, whichever comes first.
