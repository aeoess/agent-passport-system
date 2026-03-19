# Invariant Maturity Table — Paper Honesty Contract
# Source of truth for what the paper can claim
# Frozen at: v1.16.0, commit af78ef9, 862 tests
# Date: March 19, 2026

---

## INV-1: Delegation Attenuation
**Informal:** Authority can only decrease at each delegation transfer.
**Math:** A_{i+1} ⊆ A_i for all delegation chains

| Claim | Status | Evidence |
|-------|--------|----------|
| Scope narrowing enforced at SDK level | ✅ Implemented, tested | scopeCovers(), V3-CRIT-1 fixed |
| Scope narrowing enforced at gateway level | ✅ Implemented, tested | gateway Step 2, integration-invariants.test.ts |
| Cascade revocation invalidates all downstream | ✅ Implemented, tested | cascade.test.ts, 23 adversarial scenarios |
| Replay protection | ✅ Implemented, tested | TTL-based Map pruning (NW-001) |
| Key rotation with identity continuity | ✅ Implemented, tested | M22 identity.ts, M26 reanchor.ts |
| Cross-chain taint tracking | ✅ Implemented, tested | M18 cross-chain.ts, gateway integration |
| Hierarchical scope matching (wildcard) | ✅ Implemented, tested | scopeAuthorizes() with * support |

**Limitations:** Scope semantics are string-based, not ontological.

---

## INV-2: Governance Attenuation
**Informal:** Governance artifacts can only strengthen; weakening requires higher-order authorization.
**Math:** G_{i+1} ⪰ G_i where weakening requires |approvals| ≥ threshold

| Claim | Status | Evidence |
|-------|--------|----------|
| Governance artifacts signed + versioned | ✅ Implemented, tested | M21 governance.ts, 20+ tests |
| Content-hash integrity verification | ✅ Implemented, tested | hashContent() + verifyGovernanceArtifact() |
| Weakening detected via classifyGovernanceChange | ✅ Implemented, tested | governance.test.ts |
| Differential approval thresholds (1 weak, 2 removal) | ✅ Implemented, tested | loadGovernanceArtifact() policy |
| Gateway blocks weakening without approval | ✅ Implemented, tested | gateway-governance.test.ts (14 tests) |
| Gateway blocks stale governance attestation | ✅ Implemented, tested | Step 2.5 + executeApproval recheck |
| Agent re-attestation after governance update | ✅ Implemented, tested | reattestGovernance() |
| Policy conflict detection | ✅ Implemented, tested | M30 policy-conflict.ts (13 tests) |
| Values Floor F-001 through F-008 | ✅ Implemented, tested | floor.yaml, values.ts |

**Limitations:** "Higher-order authorization" is currently multi-party approval count,
not cryptographic proof of organizational hierarchy. No formal policy composition algebra.

---

## INV-3: Disclosure Attenuation
**Informal:** Audit views reveal only the minimum necessary subset of data.
**Math:** D_{viewer} ⊆ D_{committed}

| Claim | Status | Evidence |
|-------|--------|----------|
| Merkle commitment of receipt batches | ✅ Implemented, tested | attribution.ts buildMerkleRoot() |
| Selective disclosure via Merkle proof | ✅ Implemented, tested | generateMerkleProof(), integration-invariants.test.ts |
| Proof verification without full tree | ✅ Implemented, tested | verifyMerkleProof() |
| E2E encrypted messaging (X25519 + XSalsa20) | ✅ Implemented, tested | M19 encrypted-messaging.ts (13 tests) |
| Audit records for encrypted channels (no content) | ✅ Implemented, tested | M29 messaging-audit.ts (12 tests) |
| Receipt ledger with Merkle chaining | ✅ Implemented, tested | M23 receipt-ledger.ts |

| Claim | Status | Evidence |
|-------|--------|----------|
| Zero-knowledge proofs (BBS+) | ❌ Future work | Designed, not implemented |
| Privacy-preserving audit (full ZKP) | ❌ Future work | Fundamental tradeoff acknowledged |
| Selective disclosure by attribute | ❌ Future work | Current: per-receipt, not per-field |

**Limitations:** Current selective disclosure is per-receipt (reveal or hide entire receipt),
not per-field. BBS+ would enable attribute-level disclosure. The audit-vs-privacy tradeoff
is acknowledged but not resolved — full auditability and data minimization are in tension.

---

## INV-4: Exception Attenuation
**Informal:** Escalation creates bounded, temporary, challengeable expansion — not open-ended authority.
**Math:** E_active ⊆ E_precommitted with TTL + spend ceiling

| Claim | Status | Evidence |
|-------|--------|----------|
| Escalation grants with pre-committed ceiling | ✅ Implemented, tested | M27 escalation.ts |
| Gateway fallback when delegation insufficient | ✅ Implemented, tested | gateway Step 2.1, 11 tests |
| TTL-based expiry of escalation | ✅ Implemented, tested | isEscalationActive(), TTL test |
| Scope check on escalated actions | ✅ Implemented, tested | checkEscalatedAction() |
| Spend tracking during escalation | ✅ Implemented, tested | spentDuringEscalation field |
| Human approval signature verification | ✅ Implemented, tested | V5-HIGH-3 fix in activateEscalation |
| Revocation of active escalation | ✅ Implemented, tested | revokeEscalation(), gateway test |
| Max concurrent escalations enforced | ✅ Implemented, tested | maxConcurrentEscalations config |
| viaEscalation audit flag on receipts | ✅ Implemented, tested | ToolCallResult.viaEscalation |
| Reversibility taxonomy (tentative/compensable/irreversible) | ✅ Implemented, tested | Step 2.6, 3 tests |
| Oracle witness diversity scoring | ✅ Implemented, tested | M28 oracle-witness.ts (19 tests) |

| Claim | Status | Evidence |
|-------|--------|----------|
| Multi-witness trigger verification | ❌ Designed only | Type exists, no gateway integration |
| Challenge economics / compensation | ❌ Future work | Described in gap analysis |
| Saga orchestrator for state reversion | ❌ Future work | Taxonomy defined, orchestrator not built |
| Precedent-based bounded escalation | ⚠️ Partial | M25 precedent.ts exists, not wired to escalation |

**Limitations:** v1 escalation is human_authorized only. Multi-witness triggers
are typed but not enforced. Challenge economics are designed but not implemented.
Precedent accumulation exists but doesn't yet feed into escalation decisions.

---

## COMPOSITION: Invariants Reinforce Each Other

| Composition | Status | Evidence |
|-------------|--------|----------|
| INV-2 > INV-4: governance staleness blocks even with escalation | ✅ Tested | integration-invariants.test.ts COMPOSITION test |
| INV-1 feeds INV-3: delegation scope bounds disclosure scope | ✅ Architectural | Merkle proofs reference delegation chains |
| INV-4 under INV-1: escalation scope ⊆ grant ceiling ⊆ principal scope | ✅ Tested | verifyEscalationGrant() checks ceiling vs granter scope |
| INV-2 gates INV-1: delegation templates are governance artifacts | ✅ Implemented | GovernanceArtifact type 'delegation-template' |

**The thesis sentence:** "These four invariants are not independent properties but
mutually reinforcing: governance weakening is handled as an exception to governance
attenuation, subject to exception attenuation. The framework is self-referential by design."

---

## CLAIMS TO MAKE vs CLAIMS TO AVOID

### Make:
- APS implements four attenuation invariants with running code and 862 tests
- The invariants compose (governance > escalation, delegation > disclosure)
- Gateway is the enforcement boundary — not the SDK
- Honest AIVSS coverage: 5 strong, 3 partial, 2 weak
- Cross-engine interop matrix demonstrates architectural robustness
- Reproducibility: `npm install && npm test` verifies all claims

### Avoid:
- "Collusion-proof" — impossible in open systems (Lampson 1973)
- "Deterministic LLM evaluation" — temperature-0 is not reproducible
- "Privacy AND full auditability" — real tradeoff exists
- "Universal root trust" — bottoms out in governance, not crypto
- "Proved" / "Verified" / "Guaranteed" — always use "specified" / "tested" / "validated"
- Speed-of-execution flex ("35 modules in 30 days")
- AI collaborator methodology
