# Build Spec: Execution Boundary Specification (MITRE Co-Authorship)

## Context
MITRE atlas-data #11. QueBallSharken accepted co-authorship. We committed to drafting §1-§3 this week. QueBallSharken takes §4 + Drift case study.

## What
A tightly bounded RFC 2119 document. Four sections, normative language, test vectors as appendix.

## Where
- New repo: `aeoess/execution-boundary-spec` (public, Apache 2.0)
- Co-authors: aeoess + QueBallSharken
- Format: single Markdown file, under 2000 words normative text

## Structure

### §1 Mutation Authority Separation (our section)

**Normative:** The component that executes the irreversible primitive MUST be the component that evaluates admissibility.

**Reference impl:** `ProxyGateway.execute()` in APS — the evaluator IS the executor. Single atomic boundary.

**Test vector:** JSON showing delegation → evaluation → execution as one atomic unit. Verify that separating evaluation from execution creates a TOCTOU window.

### §2 Boundary Integrity at Commit (our section)

**Normative:** The authorization envelope MUST be re-derived from live state at the moment of execution. Cached authorization is NOT admissible at the mutation boundary.

**Reference impl:** `compoundDigest` binding in APS gateway — constraint hash re-derived from live delegation state at commit time. Any divergence from the cached authorization = reject.

**Test vector:** JSON showing state drift between authorization and execution. Verify that stale authorization is rejected even though it was valid when issued.

### §3 Continuity / Anti-Interleaving (our section)

**Normative:** The signed receipt MUST be produced inside the atomic execution boundary. No temporal gap between "policy permits" and "action fires" is permissible.

**Reference impl:** `PolicyReceipt` in APS — signed INSIDE the atomic boundary, captures live state at exact moment of execution.

**Test vector:** JSON showing interleaved action between check and execute. Verify that the interleaved action is rejected or that the receipt captures the interleaving.

### §4 Enforceability Classification (QueBallSharken's section)

Three tiers:
- **Strong:** Mutation authority co-located with evaluator (atomic path)
- **Bounded:** Version-anchored envelope re-verified at commit
- **Detectable-only:** Post-hoc behavioral anomaly detection

**Normative:** Implementations MUST declare their enforceability tier.

### Appendix A: Reference Implementation
Point to APS ProxyGateway test suite. Don't embed full code — reference specific test files.

### Appendix B: Test Vectors
3 JSON test vectors per section (12 total). Each vector: input state, action, expected outcome, rationale.

### Appendix C: Drift Protocol Case Study
Map the 4 points to the Drift/Solana $285M failure. Show exactly where each invariant was violated.

## How to build
1. Create repo `aeoess/execution-boundary-spec`
2. Write `spec.md` with §1-§3 (normative text + test vectors)
3. Leave §4 as a placeholder for QueBallSharken
4. Extract test vectors from existing APS test suite into JSON format
5. Post on MITRE #11 when draft is ready for QueBallSharken's review

## Timeline
This week. QueBallSharken is waiting.
