# Roadmap

What this project intends to do, and not do, over the next twelve months. The
dated build history lives at https://agent-passport.org/roadmap. This file
states direction, not dates.

## Next twelve months

- Progress the protocol through the IETF Internet-Draft process
  (draft-pidlisnyi-aps, plus the joint action-ref draft), folding review into
  the spec and its conformance vectors.
- Grow the conformance suite: more negative fixtures, and cross-implementation
  parity across the SDK implementations and the Rust verifier core.
- Hold the canonical core frozen: signed-bytes stability for everything labeled
  Canonical, with breaking changes only through a versioned migration path.
- Continue interop adapters and crosswalks with adjacent agent frameworks
  through the open vocabulary registry (agent-governance-vocabulary).
- Keep the security posture running: fuzzing, CodeQL, Scorecard, and release
  provenance in CI; vulnerability response per SECURITY.md.

## Non-goals

- The reference gateway implementation stays a separate private product. This
  repository defines what governance is; how well a particular gateway performs
  is out of scope here.
- No algorithm proliferation. One well-reviewed signature suite, replaced
  deliberately if broken, never negotiated at runtime.
- Receipts will not claim off-protocol truth. A receipt states what the system
  observed; delivery, outcomes, and world state stay outside the envelope.
- No adjudication of issuer reputation. Verifiers decide whom to trust.
- No CLA.
