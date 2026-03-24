# Paper 2 v3: Compliance-Complete Adversarial Patterns
# in Cryptographic Agent Governance
# FINAL OUTLINE — Incorporates 3 hostile reviews + 3-model elicitation data
# Status: Ready for LaTeX drafting after evaluation scenarios run

## Tima Aeoess — AEOESS — signal@aeoess.com

---

## THE PAPER IN ONE SENTENCE

Cryptographic agent governance amplifies compliance-complete failures
by producing verifiable false evidence of safety — the stronger the
proofs, the harder it becomes to detect or contest harmful outcomes.

---

## FORMAL DEFINITIONS (must appear early, exactly once)

**Compliance-complete failure:** A failure is compliance-complete when
all governance-layer validation artifacts (identity verification,
delegation chain validation, scope checking, policy evaluation,
receipt generation) evaluate to success while the resulting
system-level outcome is harmful.

**Amplification effect:** In an ungoverned system, harmful outcome H
occurs with no compliance evidence. In a cryptographically governed
system, the same H occurs with valid evidence set
E = {identity, delegation, policy_pass, receipt}. E raises posterior
confidence that the system behaved correctly, despite H. Therefore
the governance layer increases the difficulty of detecting or
contesting H. Stronger: the governance layer provides a documented
explanation for why there was no failure, actively suppressing
investigation.

**Two forms of amplification:**
- False positive safety evidence (Patterns 1, 3, 4, 5): governance
  produces a receipt that looks safe
- Safety evidence absence (Pattern 2): governance produces nothing
  about the collective, and absence of negative evidence is mistaken
  for safety

---

## PRIOR-ART ADJACENCY TABLE (Section 2, must be in paper)

| Pattern | Nearest Prior Art | Why Prior Art Is Insufficient |
|---------|------------------|-------------------------------|
| Semantic Gap | Specification gaming (Krakovna), ambient authority (Miller/Shapiro) | Cryptographic receipt creates contest-resistant false evidence of correct behavior; gaming becomes legally defensible |
| Emergent Collective Harm | Flash crash (Kirilenko 2017), cascading failures (OWASP) | Perfect per-agent authorization produces no evidence about collective; the governance layer is blind by architecture, not oversight |
| Reputation Arbitrage | Delayed defection, Sybil (Douceur 2002) | Reputation unlocks machine-enforced authority tiers and spend limits, not just social capital; defection blast radius is operationally larger |
| Compositional Scope Escalation | Confused deputy (Hardy 1988), compositional security (McCullough 1988) | No deputy is confused; every agent acts correctly; violation exists only in pipeline composition and is invisible to per-agent checks |
| Temporal Context Drift | TOCTOU (classic) | Authorization remains valid across hours/days (delegation TTL), not milliseconds; drift is environmental, not race-condition |

---

## MULTI-MODEL CONVERGENCE EVIDENCE (Section 3)

Discovery method: structured threat elicitation across 3 frontier
models (Claude Opus 4, GPT, Gemini). Each given full protocol spec.
8-10 sequential adversarial questions. No cross-talk between models.

Convergence results:
- All 3 independently identified the semantic gap / authorization-effect divide
- All 3 independently identified emergent collective harm from compliant agents
- All 3 independently identified reputation/trust accumulation as attack vector
- All 3 independently identified compositional scope escalation via pipelines
- All 3 independently confirmed the amplification thesis
- 2/3 identified temporal exploitation (GPT + Gemini; Claude addressed under policy migration)

Additional patterns surfaced (not in core 5, noted as future work):
- Implicit capability accumulation (GPT): agent knowledge grows unbounded while permissions stay governed
- Scope boundary probing as intelligence gathering (GPT): mapping ecosystem permission topology through authorized testing
- Attestation leadership as governance capture (GPT): becoming the enforcer to shape exceptions
- Delegation hoarding across principals (Gemini): 50 tiny delegations from 50 principals, aggregate capability dangerous
- Context window poisoning via authorized observation (GPT): building manipulation model from legitimate task inputs

---

## FIVE PATTERNS (Section 4)

### Pattern 1: Semantic Gap Exploitation

Scoping sentence (per reviewer feedback): "A semantic gap becomes a
compliance-complete governance failure when the authorization artifact
remains valid and contest-resistant even though the action's effect
diverges from the authorizer's intended semantics."

Adversary model: Can arbitrarily choose content, framing, and context
of authorized actions. Cannot forge signatures, exceed scope, or
bypass policy checks.

Safety property violated: Outcome alignment.

Three examples (not just the report):
1. 5,000-page report burying critical risk on page 3,411 (information drowning)
2. Authorized email with context-sensitive harmful recipient effect
3. Authorized summarization that preserves truth while strategically suppressing salience

Spectrum table: Narrow → Medium → Wide → Unbridgeable

APS modules: effect-enforcement, effect-sampling, semantic-scoping
Residual: HIGH — mitigations narrow gap, cannot eliminate it

---

### Pattern 2: Emergent Collective Harm

Terminology fix: "The adversarial object is the architecture, not a
malicious agent. This pattern requires no adversary — it requires only
the absence of population-level governance in a system with
individual-level governance."

Formal gap: The composition function f is not modeled by the protocol
and CANNOT be — it depends on external environment state. This is a
representational impossibility, not an implementation gap.

GPT's stronger scenario: convergence via information cascades from
publicly observable behavior, not shared training data. Shannon
entropy across reasoning looks normal. Convergence is in outputs only.

APS modules: emergence (Shannon entropy), cascade-correlation
Residual: CRITICAL — detection only, no enforcement. Population-level
governance requires fundamentally different trust architecture.

---

### Pattern 3: Reputation Arbitrage

Bridge sentence (per reviewer): "In cryptographic governance,
accumulated trust is not merely social capital — it becomes
machine-enforceable authority, budget ceilings, and autonomy unlocks.
This makes delayed defection operationally stronger than in ordinary
reputation systems."

GPT addition: the critical missing piece is complexity verification
at promotion time. Volume ≠ capability. 1,000 trivial tasks ≠
proof of handling 1 complex dangerous task.

APS modules: reputation-gated authority, cryptographic scarring,
promotion reviews with complexity distribution, hysteresis
Residual: MEDIUM — blast radius bounded by delegation scope.
Single action before automatic demotion.

---

### Pattern 4: Compositional Scope Escalation ("Authority Laundering")

Academic name first, informal label in parentheses (per reviewer).

Formal condition: ∀i: action(aᵢ) ∈ scope(dᵢ), but
pipeline(a₁ ∘ a₂ ∘ ... ∘ aₖ) ∉ scope(dⱼ) for any j.

Distinguishing from confused deputy: no deputy is confused. Each
acts correctly. Violation exists only in composition.

GPT addition: intent binding fails when agents legitimately
transform the intent. "Research competitors" → "draft briefing" →
"send to leadership" = three legitimate transformations. Original
intent doesn't specify prohibited composite outcomes.

Gemini addition: variant via breadth not depth — 50 tiny delegations
from 50 principals, no single chain triggers alarm, aggregate
capability dangerous. (Note as sub-variant.)

APS modules: intent-binding, taint tracking, composite-audit
Residual: MEDIUM-HIGH — taint catches data flow, but detecting
whether a specific composition is dangerous requires semantic
understanding (converges with Pattern 1).

---

### Pattern 5: Temporal Context Drift (Governance TOCTOU)

Why it belongs in THIS paper (per reviewer): "The action remains
cryptographically and procedurally valid even after the conditions
that made it safe have disappeared." That is the amplification link.

GPT's deeper insight: requiring the governance layer to reason about
world-state makes the governance layer an agent, with all the
governance problems that implies. Recursive governance problem.

Gemini's mitigation: JIT micro-TTL + world-state oracle polling
before execution. Practical but creates oracle dependency.

APS modules: PolicyContext mandatory sunset, delegation TTL,
governance-drift
Residual: MEDIUM — short TTLs reduce window. Cannot eliminate
because domain volatility is itself dynamic.

---

## EVALUATION (Section 5) — Must be measured, not module labels

Each pattern needs: one scenario, one metric, one result.

| # | Pattern | Scenario | Metric | Expected Result |
|---|---------|----------|--------|-----------------|
| 1 | Semantic Gap | Agent sends authorized report, effect-declaration diverges from actual | Effect divergence score triggers flag | Flag at divergence > 0.3 threshold |
| 2 | Emergence | 100 simulated agents with correlated vendor selections | Shannon entropy drops below monoculture threshold | Flag before concentration > 0.7 HHI |
| 3 | Rep Arbitrage | Agent completes 200 trivial tasks, attempts sovereign-level action | Promotion review complexity check | Block: <20% non-trivial tasks fails review |
| 4 | Auth Laundering | 3-agent read→draft→send pipeline with tainted financial data | Taint propagation blocks send with restricted data | Gateway blocks at taint check |
| 5 | Temporal Drift | Authorize trade at t1, perturb context, execute at t2 | % of stale-authorized actions blocked per TTL window | 24h TTL: X% pass; 5m TTL: Y% pass; execution-time check: Z% pass |

Layer 1 (protocol-agnostic): show each scenario is coherent for ANY
system with identity + delegation + policy checking.

Layer 2 (APS-specific): run against APS, record actual results.

Self-referential caveat: explicitly acknowledged. Three paths to
independent validation identified.

---

## DISCUSSION (Section 6)

6.1 The Compliance-Safety Amplification Effect
- Central finding formalized (see definitions above)
- GPT's stronger formulation: "actively prevents correction"
- Gemini's counter: forensic value of audit trail for post-mortem
- Both are true. Real-time prevention fails. Post-mortem learning works.
  The protocol is better as a black box recorder than a safety net.

6.2 Implications for Framework Design
- Authorization layer (existing): necessary, valuable, insufficient
- Legitimacy layer (missing): outcome monitoring, emergence detection,
  semantic gap management, temporal coherence, population circuit breakers
- These are complementary, not competing layers

6.3 Broader Governance Implications (ONE PARAGRAPH ONLY)
"The five patterns suggest that agent governance may require mechanisms
beyond technical enforcement — including contestation, interpretation,
and revision capabilities. We leave formal exploration to future work."

---

## LANGUAGE RULES (enforced throughout)

Replace "we show" with:
- "we argue"
- "we formalize"
- "we demonstrate through scenario analysis"
- "we provide evidence that"
- "we identify"

Never say:
- "none of the literature addresses this" → say "existing work
  partially addresses adjacent phenomena but does not isolate
  this class in cryptographic agent governance"
- "catastrophic" unless scenario truly warrants it → use "harmful",
  "unsafe", "externally harmful", "systemically destabilizing"
- "first formal taxonomy" → say "a candidate taxonomy"

---

## FUTURE WORK (from elicitation — patterns not in core 5)

- Implicit capability accumulation (knowledge grows, permissions don't)
- Delegation hoarding across independent principals
- Attestation leadership as governance capture mechanism
- Scope boundary probing as ecosystem intelligence gathering
- Context window poisoning through authorized observation
- Regime shopping / governance-context selection
- Interpretive capture (who governs the enforcement layer's interpretation?)
- Principal drift after bootstrapping

---

## TARGET VENUES

Primary: AISec Workshop at ACM CCS (position/open-problem track)
Secondary: AAAI Workshop on AI Safety, SaTML
Tertiary: IEEE S&P Workshop on Language Model Security

Format: 12 pages, acmart class, LaTeX
Deadline: ~July 2026

---

## NEXT STEPS (in order)

1. [x] Multi-model elicitation (Claude, GPT, Gemini) — DONE
2. [x] Three rounds of hostile review — DONE
3. [x] Final outline v3 — THIS DOCUMENT
4. [ ] Run evaluation scenarios against APS code (build session)
5. [ ] Record actual measured results for Section 5 table
6. [ ] Attempt one third-party framework evaluation (DAAP or LangChain)
7. [ ] Write LaTeX draft (acmart, 12 pages)
8. [ ] Final hostile review round on full draft
9. [ ] Submit

## WHAT WE HAVE vs WHAT WE NEED

HAVE:
- Core thesis confirmed by 3 independent models
- 5 patterns with multi-model convergence
- Amplification effect confirmed and strengthened
- Prior-art adjacency table
- Formal definitions (compliance-complete, amplification)
- Running v2 code implementing mitigations (74 modules, 1,183 tests)
- Paper 1 published as foundation (Zenodo DOI)
- Three rounds of hostile review incorporated

NEED:
- Evaluation scenarios run against code with measured results (step 4-5)
- LaTeX draft (step 7)
- Ideally one third-party framework evaluation (step 6, stretch)

TIME ESTIMATE:
- Evaluation build session: 1 session (~3-4 hours)
- LaTeX draft: 2-3 sessions
- Review round: 1 session
- Total to submission-ready: ~5 sessions
