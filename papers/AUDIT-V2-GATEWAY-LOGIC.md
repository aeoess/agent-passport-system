# ADVERSARIAL SECURITY AUDIT V2: Gateway Logic, Module Interactions, and Enforcement Path Completeness
## Agent Passport System — ProxyGateway + Modules 18-20 + Frame Epochs

**Date:** March 18, 2026 (Second audit, different attack vectors from V1)
**Auditor:** Claude (Opus 4.6), hostile reviewer per F-008
**Scope:** Gateway enforcement path completeness, two-phase approval path, frame rotation semantics, canonicalization, deriveSAO information loss, scope matching, epoch verification, permit lifecycle
**Commit:** `ab4d035`
**Method:** Static analysis of gateway.ts (701 lines), cross-chain.ts (614 lines), canonical.ts, obligations.ts + 8 live exploit scenarios
**Prerequisite:** Assumes V1 audit findings (F-1 through F-4) and 5 security fixes already applied

---

## EXECUTIVE SUMMARY

V1 audited the hash chain and taint tracking primitives. V2 audits **how the gateway wires those primitives together** — and found a **critical enforcement bypass** in the two-phase approval path.

The `processToolCall()` path enforces all security properties: cross-chain taint checks, permit TOCTOU recheck, frame auto-rotation, agent mutex, obligation fulfillment, and envelope production. The `executeApproval()` path enforces **none of them**. An agent that uses `approve()` + `executeApproval()` instead of `processToolCall()` bypasses every Module 18/20 security mechanism.

**Verdict: FAIL on enforcement path completeness. 1 critical bypass, 4 medium findings, 3 low findings.**

---

## 1. CRITICAL FINDING

### V2-CRIT-1: Two-Phase Approval Path Bypasses ALL Cross-Chain Enforcement

**Severity:** CRITICAL
**Location:** `gateway.ts` — `executeApproval()` (lines 556-600)
**Confirmed by:** Live test `V2-CRIT-1` — `executeApproval executed=true` when `processToolCall` returns `executed=false`
**Affects:** Every security mechanism added in Modules 18, 19, 20, and the concurrency fix

**Description:** The gateway has two execution paths:
- `processToolCall()` — single-phase: check + execute in one call
- `approve()` + `executeApproval()` — two-phase: check first, execute later

`processToolCall()` enforces all security properties. `executeApproval()` enforces NONE of the following:

| Security mechanism | processToolCall | executeApproval |
|-------------------|----------------|----------------|
| Cross-chain taint check (step 5.5) | ✅ Yes | ❌ **MISSING** |
| Frame TTL auto-rotation | ✅ Yes | ❌ **MISSING** |
| Permit TOCTOU recheck (step 5.75) | ✅ Yes | ❌ **MISSING** |
| Taint recording after execution (step 6.5) | ✅ Yes | ❌ **MISSING** |
| SAO wrapping of result | ✅ Yes | ❌ **MISSING** |
| Obligation fulfillment check (step 8.5) | ✅ Yes | ❌ **MISSING** |
| Execution envelope production (step 9) | ✅ Yes | ❌ **MISSING** |
| Per-agent sequential mutex | ✅ Yes | ❌ **MISSING** |

**Attack scenario (proven in test):**
1. Agent reads data under delegation from Principal A → frame tainted with A
2. Agent calls `processToolCall()` to write under Principal B → BLOCKED (cross-chain)
3. Agent calls `approve()` for the same write under Principal B → APPROVED (approve() doesn't check cross-chain)
4. Agent calls `executeApproval()` → EXECUTES SUCCESSFULLY (no taint check)

**The agent just exfiltrated Principal A's data through Principal B's channel.**

**Impact:** Complete bypass of confused deputy prevention. The entire cross-chain enforcement system (Module 18), obligation model (Module 20), frame rotation (F-2 fix), and concurrency protection (Opus fix) are nullified for any agent that uses the two-phase path.

**Fix:** `executeApproval()` must replicate steps 5.5, 5.75, 6.5, 8.5, 9, and the agent mutex from `processToolCall()`. Alternatively, refactor both paths to call a shared `_enforceAndExecute()` that contains all checks.

---

## 2. MEDIUM FINDINGS

### V2-MED-1: Frame Rotation Creates Clean Window for Cross-Chain Exfiltration

**Severity:** Medium
**Location:** `gateway.ts` step 5.5 — frame rotation happens BEFORE taint check
**Confirmed by:** Live test — `Post-rotation executed=true`

**Description:** When a frame's TTL expires, the gateway rotates it to a fresh frame before running the cross-chain taint check. The fresh frame has zero taint. Any action — including cross-chain — is immediately allowed on the fresh frame because there are no foreign principals in the taint set.

**Attack scenario:**
1. Agent reads under Principal A at T=0. Frame tainted with A.
2. Frame TTL is 10 minutes. At T=10m, frame rotates.
3. Agent sends data under Principal B at T=10m+1s. Frame is clean. ALLOWED.
4. Agent just moved A's data through B's channel after a predictable TTL window.

**Impact:** TTL-based rotation creates a periodic window where cross-chain enforcement is disabled. The window is deterministic and predictable by the agent.

**Recommendation:** After frame rotation, carry forward the *principals* (not full taint) from the sealed frame as a "taint residue." The fresh frame would know which principals the agent has interacted with in previous epochs, and permits would still be required for cross-principal flows. Alternatively, require explicit human approval for first cross-chain action after rotation.

### V2-MED-2: Canonicalize Drops Null/Undefined — Potential Signature Collision

**Severity:** Medium (contextual)
**Location:** `canonical.ts` line 14 — `.filter(key => val !== null && val !== undefined)`
**Confirmed by:** Live test — `{ a: 1, b: null }` === `{ a: 1 }` after canonicalization

**Description:** Two structurally different JavaScript objects produce identical canonical forms. This means they produce identical signatures. In the hash chain context this is mostly benign (taint labels don't have null fields). But in the broader signature system, an entity that signs `{ action: "read", target: null }` produces the same signature as `{ action: "read" }`. A verifier cannot distinguish which object was actually signed.

**Recommendation:** Document this as a design decision. Consider adding explicit null-representation (e.g., `"null"` value) in a future protocol version. Low urgency for current deployment.

### V2-MED-3: DerivedSAO Collapses Per-Principal Taint to Opaque Label

**Severity:** Medium
**Location:** `cross-chain.ts` `deriveSAO()` — sets `principalId: 'MULTI_PRINCIPAL'`
**Confirmed by:** Live test — alice + bob → `MULTI_PRINCIPAL`

**Description:** When data from multiple principals is combined into a derived SAO, the individual principal identities are replaced with the string literal `'MULTI_PRINCIPAL'`. Downstream `checkDataFlow()` sees this as a single foreign principal and cannot determine WHICH principals contributed. Permit matching requires knowing the specific foreign principal to find the right permit, but `'MULTI_PRINCIPAL'` matches no real principal's permits.

**Impact:** Derived SAOs from multi-principal data are effectively unusable in cross-chain flows — no permit can match `'MULTI_PRINCIPAL'` because no principal has that ID. This is accidentally secure (blocks everything) but semantically incorrect.

**Recommendation:** DerivedSAO should carry the full list of source principal IDs, not collapse them. Either add a `sourcePrincipals: string[]` field to TaintLabel or keep all source labels in the derived SAO.

### V2-MED-4: Scope Prefix Matching Too Broad

**Severity:** Medium
**Location:** `delegation.ts` `scopeCovers()` — `required.startsWith(granted + ':')`
**Also:** `checkDataFlow()` permit scope matching — `opts.actionScope.startsWith(s + ':')`
**Confirmed by:** Live test — permit for `"data"` authorizes `"data:delete:permanent"`

**Description:** The scope matching system uses colon-delimited prefix matching. A scope `"data"` covers `"data:read"`, `"data:write"`, `"data:delete"`, and `"data:delete:permanent:nuclear"`. This is by design for delegation narrowing, but when applied to permit scope matching it means a permit granting `destAllowedScopes: ['data']` authorizes ALL data sub-scopes including destructive operations.

**Recommendation:** Consider requiring explicit wildcard notation (`"data:*"`) for broad permits, distinguishing between exact-match (`"data"`) and prefix-match (`"data:*"`). This is a design decision, not a bug, but the current behavior may surprise permit issuers.

---

## 3. LOW FINDINGS

### V2-LOW-1: No Gateway Method to Revoke Permits

**Severity:** Low
**Location:** `gateway.ts` — `registerPermit()` exists, no `revokePermit()` method

**Description:** The gateway provides `registerPermit(agentId, permit)` to store permits, but no method to revoke them. The `revokePermit()` function in `cross-chain.ts` returns a new object with `revoked: true` but doesn't mutate the original in the gateway's store. To revoke a permit, the gateway operator would need to directly access the agent's permits array.

**Recommendation:** Add `revokePermit(agentId: string, permitId: string): boolean` to the gateway.

### V2-LOW-2: Epoch Super-Chain Not Verified by verifyFrameChain

**Severity:** Low
**Location:** `cross-chain.ts` `verifyFrameChain()` — only checks internal chain

**Description:** `verifyFrameChain()` verifies the hash chain within a single frame but does not verify the `previousFrameChainHead` link to the preceding epoch. An attacker who can modify `previousFrameChainHead` can break the epoch audit trail without detection by `verifyFrameChain()`.

**Recommendation:** Add `verifyEpochChain(frames: ExecutionFrame[]): boolean` that verifies each frame's `previousFrameChainHead` matches the predecessor's `chainHead`.

### V2-LOW-3: executeApproval Lacks Agent Mutex

**Severity:** Low (but compounds with V2-CRIT-1)
**Location:** `gateway.ts` `executeApproval()` — no `agentLocks` usage

**Description:** `processToolCall()` uses per-agent sequential locking to prevent concurrent frame clobbering (Claude Opus fix). `executeApproval()` does not use this lock. Concurrent `executeApproval()` calls or mixed `processToolCall()` + `executeApproval()` calls for the same agent can race on the execution frame.

**Impact:** Currently low because `executeApproval()` doesn't touch the frame at all (V2-CRIT-1). Once V2-CRIT-1 is fixed and `executeApproval()` starts recording taint, the mutex gap becomes critical.

---

## 4. COMPARISON: V1 AUDIT vs V2 AUDIT

| Aspect | V1 Audit | V2 Audit |
|--------|----------|----------|
| Focus | Hash chain primitives, taint labels, SAO integrity | Gateway wiring, enforcement path completeness |
| Method | Attack individual functions | Attack function interactions and alternative paths |
| Critical findings | 0 (conditional passes) | 1 (two-phase bypass) |
| Most important insight | Chain proves order but not occurrence | Sound primitives assembled with an enforcement gap |
| Trust boundary tested | Module level (cross-chain.ts) | System level (gateway.ts orchestration) |

**Key lesson:** V1 proved the security primitives are sound. V2 proves that sound primitives incorrectly wired produce an insecure system. The hash chain, taint tracking, and permit verification all work correctly — but only when called. The two-phase path never calls them.

---

## 5. VERIFICATION INSTRUCTIONS FOR OTHER MODELS (GPT, Gemini)

### 5.1 Reproduce V2-CRIT-1 (Two-Phase Bypass)

Read `gateway.ts` lines 556-600 (`executeApproval`). Confirm the following are ALL absent:
- No call to `checkDataFlow()` (cross-chain enforcement)
- No call to `isFrameExpired()` or `rotateFrame()` (frame TTL)
- No call to `recordAccess()` (taint recording)
- No call to `createSAO()` (result wrapping)
- No call to `checkFulfillment()` (obligation checking)
- No call to `createExecutionEnvelope()` (interop envelope)
- No access to `this.agentLocks` (concurrency protection)

Then compare with `_processToolCallInner()` (lines 200-480) which has all of them.

### 5.2 Verify Frame Rotation Timing (V2-MED-1)

In `_processToolCallInner()` find the frame rotation block (around line 300). Confirm:
1. `isFrameExpired()` check happens BEFORE `checkDataFlow()`
2. `rotateFrame()` creates a frame with zero taint
3. `checkDataFlow()` with zero taint always returns `verdict: 'allowed'`
4. Therefore: any action is permitted on a freshly rotated frame

### 5.3 Verify Scope Prefix Matching (V2-MED-4)

Read `scopeCovers()` in `delegation.ts`. Confirm:
- `scopeCovers('data', 'data:delete:permanent')` returns `true`
- Because `'data:delete:permanent'.startsWith('data' + ':')` is `true`

Then read the permit matching in `checkDataFlow()`. Confirm the same prefix logic applies to `destAllowedScopes`.

### 5.4 Verify DerivedSAO Information Loss (V2-MED-3)

Read `deriveSAO()` in `cross-chain.ts`. Confirm:
- When `mergedTaint.isCrossChain` is true, `principalId` is set to the string literal `'MULTI_PRINCIPAL'`
- The original principal IDs (alice, bob, etc.) are not stored anywhere on the derived SAO
- Downstream `checkDataFlow()` will try to find a permit where `sourceContext.principalId === 'MULTI_PRINCIPAL'` — which no real permit will ever have

### 5.5 Verify Epoch Link Not Checked (V2-LOW-2)

Read `verifyFrameChain()` in `cross-chain.ts`. Confirm it:
- Iterates `frame.accessedContexts` and replays hashes
- Checks `chainHead` and `stepCount`
- Does NOT read or verify `previousFrameChainHead`

---

## 6. COMPLETE FINDINGS TABLE

| ID | Severity | Finding | Confirmed | Fix Status |
|----|----------|---------|-----------|------------|
| V2-CRIT-1 | **CRITICAL** | executeApproval bypasses ALL Module 18/20 enforcement | ✅ Live test | **OPEN — must fix before production** |
| V2-MED-1 | Medium | Frame rotation creates predictable clean window | ✅ Live test | OPEN |
| V2-MED-2 | Medium | Canonicalize null-dropping collision | ✅ Live test | ACKNOWLEDGED (design decision) |
| V2-MED-3 | Medium | DerivedSAO loses per-principal taint | ✅ Live test | OPEN |
| V2-MED-4 | Medium | Scope prefix matching too broad | ✅ Live test | ACKNOWLEDGED (design decision, document) |
| V2-LOW-1 | Low | No gateway permit revocation API | ✅ Static | OPEN |
| V2-LOW-2 | Low | Epoch super-chain not verified | ✅ Live test | OPEN |
| V2-LOW-3 | Low | executeApproval lacks agent mutex | ✅ Static | OPEN (blocked by CRIT-1 fix) |

---

## 7. VERDICT

**The security primitives (hash chain, taint tracking, permit verification, frame rotation) are sound.** V1 audit confirmed this with 12 attack scenarios. The 5 security fixes from the 3-model review (closed-frame enforcement, permit signature verification, TOCTOU recheck, inline permit verification, agent mutex) are all correctly implemented in `processToolCall()`.

**The two-phase approval path (`approve()` + `executeApproval()`) is a complete bypass of all post-V1 security mechanisms.** This is a CRITICAL finding. The confused deputy prevention, obligation enforcement, frame TTL, and concurrency protection are all nullified for any agent that uses the two-phase path.

**Recommended fix priority:**
1. **V2-CRIT-1** — Block or fix executeApproval immediately. Either (a) disable the two-phase path when cross-chain enforcement is enabled, (b) extract shared enforcement logic into a method called by both paths, or (c) make executeApproval call processToolCall internally.
2. **V2-MED-1** — Add taint residue carryforward across frame rotations.
3. **V2-MED-3** — Preserve per-principal taint in derived SAOs.
4. **V2-LOW-1** — Add gateway revokePermit API.
5. **V2-LOW-2** — Add verifyEpochChain function.

---

## APPENDIX: SOURCE FILES FOR VERIFICATION

| File | Lines | What to check |
|------|-------|---------------|
| `src/core/gateway.ts` | 701 | Compare processToolCall vs executeApproval |
| `src/core/cross-chain.ts` | 614 | deriveSAO, checkDataFlow permit matching, rotateFrame |
| `src/core/canonical.ts` | 22 | Null-dropping filter |
| `src/core/delegation.ts` | scopeCovers | Prefix matching logic |
| `tests/adversarial-audit-v2.test.ts` | 149 | All 8 attack scenarios with live results |

Repository: https://github.com/aeoess/agent-passport-system
Commit: `ab4d035`

*Signed: Claude (Opus 4.6), V2 Auditor, per F-008.*
*This audit specifically attacked enforcement path completeness — a different vector from V1 which attacked primitive soundness.*
