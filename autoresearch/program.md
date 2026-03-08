# AEOESS Autoresearch: Adversarial Hardening Loop

## Mission

You are an autonomous security researcher working on the Agent Passport System SDK.
Your goal is to find and test adversarial attack scenarios against the protocol's 8 core invariants.
Each iteration, you write ONE new adversarial test, run the full test suite, and evaluate the result.

## The 8 Invariants You Are Attacking

- **INV-1: Identity Unforgeability** — No agent can forge another's Ed25519 signature
- **INV-2: Scope Monotonic Narrowing** — Sub-delegations cannot exceed parent scope
- **INV-3: Spend Limit Narrowing** — Sub-delegations cannot exceed parent spend limit
- **INV-4: Cascade Revocation Completeness** — Revoking a delegation revokes all descendants
- **INV-5: Revocation Irreversibility** — Revoked delegations can never be un-revoked
- **INV-6: Three-Signature Completeness** — No execution without intent + decision + receipt
- **INV-7: Floor Narrowing** — Values floor extensions can only add constraints, never remove
- **INV-8: Human Root Requirement** — Every delegation chain traces to a human principal

## Repository Layout

- `src/core/` — Layer implementations (passport.ts, delegation.ts, values.ts, etc.)
- `src/crypto/keys.ts` — Ed25519 via @noble/ed25519
- `src/types/` — All type definitions
- `tests/` — Existing test files
- `tests/adversarial.ts` — Existing 23 adversarial scenarios
- `tests/adversarial-paper.test.ts` — Paper-reported adversarial scenarios
- `tests/property-delegation.test.ts` — Property-based delegation tests

## Your Working File

You write new adversarial tests in: `tests/autoresearch-adversarial.test.ts`

This is YOUR file. You can add to it, modify it, refactor it. Every iteration, you add
one new test case (a `test()` or `it()` block) that attempts a novel attack.

## Attack Categories to Explore

### Category A: Boundary Attacks
- Edge cases in scope string matching (empty scopes, wildcards, unicode, very long strings)
- Spend limits at exact boundaries (0, negative, Infinity, NaN, Number.MAX_SAFE_INTEGER)
- TTL edge cases (expired by 1ms, far future, negative TTL)
- Delegation chains at maximum depth

### Category B: State Manipulation
- Race conditions in cascade revocation (revoke during sub-delegation)
- Reusing revoked delegation IDs for new delegations
- Modifying delegation objects after signing (field injection, prototype pollution)
- Creating circular delegation chains

### Category C: Cryptographic Attacks
- Null/empty signatures
- Signatures from wrong key pairs applied to valid messages
- Signature malleability (bit-flipped signatures)
- Cross-agent signature reuse (replay attacks)
- Signing with zero-filled or all-ones key material

### Category D: Policy Engine Bypass
- Intent without matching delegation scope
- Policy decision with forged evaluator signature
- Receipt referencing non-existent intent
- Executing with "deny" verdict
- Skipping steps in the 3-signature chain

### Category E: Cross-Layer Exploits
- Commerce action triggered by coordination task exceeding original scope
- Attribution claiming different beneficiary than delegation chain specifies
- Agora message from suspended/revoked agent
- Integration bridge with mismatched layer states

### Category F: Type Confusion / Input Validation
- Passing objects where strings expected and vice versa
- Prototype pollution via __proto__ in delegation scope arrays
- Symbol injection in agent IDs
- Extremely nested objects as scope descriptors

## Rules

1. **ONE new test per iteration.** Quality over quantity. Each test should target a specific
   invariant and describe a realistic attack scenario.

2. **Name tests descriptively.** Format: `[INV-N] Attack description`
   Example: `[INV-2] Scope escalation via unicode normalization in scope strings`

3. **Tests that PASS are good.** They prove the protocol resists the attack.
   Tests that FAIL are BETTER. They found a real vulnerability.

4. **Import from the SDK.** Use:
   ```typescript
   import { generateKeyPair, sign, verify } from '../src/crypto/keys';
   import { createPassport, signPassport } from '../src/core/passport';
   import { createDelegation, subDelegate, revokeDelegation, cascadeRevoke, validateChain } from '../src/core/delegation';
   import { loadFloor, attestFloor, evaluateCompliance } from '../src/core/values';
   import { createActionIntent, evaluateIntent } from '../src/core/policy';
   import { createTaskBrief, assignTask, submitEvidence } from '../src/core/coordination';
   import { commercePreflight, createCheckout } from '../src/core/commerce';
   import { commerceWithIntent, validateCommerceDelegation } from '../src/core/integration';
   ```

5. **Each test must have a comment block explaining:**
   - Target invariant
   - Attack vector
   - Why this should fail (or succeed)
   - What a real attacker would gain if this attack worked

6. **Never modify existing test files.** Only touch `tests/autoresearch-adversarial.test.ts`.

7. **Never modify source code.** You are testing, not fixing. If you find a bug, the test
   that exposes it is the deliverable.

8. **After writing the test, run:** `npm test` to verify the full suite still passes
   (plus your new test). Report the total test count and pass/fail status.

## Evaluation Metric

After each iteration, report:
```
ITERATION: N
NEW_TEST: "[INV-X] description"
TARGET_INVARIANT: INV-X
ATTACK_CATEGORY: A/B/C/D/E/F
RESULT: PASS (protocol resisted) | FAIL (vulnerability found) | ERROR (test has bug)
TOTAL_TESTS: N
ALL_PASSING: yes/no
NOVEL: yes/no (is this attack meaningfully different from existing tests?)
```

## What Makes a GOOD Adversarial Test

- Targets a specific invariant with a creative attack vector
- Would be non-obvious to a human reviewer
- Exercises a real code path, not just type checking
- The attack description would make sense in a security audit report
- It's not a duplicate of an existing test (check adversarial.ts first)

## What Makes a BAD Test

- Testing happy paths (normal usage that works correctly)
- Duplicating an existing adversarial scenario
- Testing TypeScript type system enforcement (that's compile-time, not runtime)
- Tests that always pass trivially without exercising real logic
