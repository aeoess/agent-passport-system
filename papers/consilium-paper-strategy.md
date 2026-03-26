# CONSILIUM BRIEFING: Paper Strategy Decision
# Date: March 26, 2026
# Send to: GPT, Gemini (separate sessions, no cross-talk)
# Role: F-008 hostile reviewer + strategic advisor

---

## YOUR ROLE

You are advising the architect of a cryptographic governance protocol for AI agents on which academic paper to write next. Be honest, not encouraging. I need the decision that maximizes scientific impact and acceptance probability, not the one that feels most exciting. If none of the options are strong enough, say so.

---

## CONTEXT: WHAT EXISTS

### The Protocol

The Agent Passport System (APS) is an open-source cryptographic governance protocol for AI agents. Ed25519 identity, scoped delegation chains with cascade revocation, a 3-signature policy chain (intent → evaluation → receipt), Bayesian reputation-gated authority, a ProxyGateway enforcement boundary, and a Human Values Floor.

Current state: SDK v1.26.0, 1,507 tests, 392 suites, 80 modules (48 core + 32 v2 constitutional). Published on npm, PyPI, and Zenodo. ~9,000 npm downloads. Apache-2.0.

### Working Group

5 founding members (APS, qntm, AgentID, OATR, ArkForge). 4 ratified specs: QSP-1 transport, DID Resolution v1.0, Entity Verification v1.0, Execution Attestation v0.1. Campaign 7: live cross-protocol composition test — APS governance artifacts verified through Corpo entity API + qntm encrypted relay on production infrastructure. Two independent implementations (TypeScript, Python).

### Published Paper (Paper 1)

"Monotonic Narrowing for Agent Authority" — Zenodo DOI: 10.5281/zenodo.18749779. Presents the protocol design, formal invariants, adversarial testing, 15 known limitations.

### New Work Since Paper 1

1. **Faceted Narrowing formalization** — Generalizes monotonic narrowing from three independent conditions (scope ⊆, spend ≤, depth <) to a single principle: authority is an element of a product lattice A = D₁ × D₂ × ... × D₇, and delegation is a monotone function on that lattice. Seven dimensions: scope, spend, depth, time, reputation, values, reversibility.

   Formal connections established to four frameworks:
   - Capability Attenuation (Miller 2006) — faceted narrowing is Miller with n dimensions
   - Lattice-Based Access Control (Denning 1976, Sandhu 1993) — authority space IS an LBAC lattice
   - Abstract Interpretation (Cousot & Cousot 1977) — gateway constraint checking as Galois connection
   - Domain Theory (Scott 1970) — delegations as dcpo, authority as infimum

   Implemented as ConstraintVector + AuthorizationWitness + structured ConstraintFailure across 7 denial paths. Running code, tested.

2. **Constraint Architecture** — AuthorizationWitness (signed snapshot of agent's position in authority lattice at execution time), ConstraintVector (runtime product lattice evaluation), structured denial paths. 13 tests.

3. **Evidence Diversity & Confidence Scoring** — Shannon entropy over evidence sources. Sybil-resistant: 10 diverse evaluators > 10 from same operator. Bayesian confidence intervals on trust scores. 7 tests.

4. **Near-Miss Alerting** — Proactive constraint boundary warnings with headroom tracking. Gateway warns BEFORE an agent hits its limits. 7 tests.

5. **Compliance-Complete Patterns** — 6 rounds of hostile review across 3 models. 5 named failure modes where all rules are followed perfectly and harm still emerges. Multi-model convergence (Claude, GPT, Gemini all independently identified all 5 patterns). Campaign 7 provides cross-protocol evidence. Core thesis: cryptographic governance amplifies these failures by producing verifiable false evidence of safety.

6. **Data Governance Stack** (Modules 38-42) — Data source registration, enforcement gates, training attribution with fractional weights, derivation chains, settlement with Merkle proofs, compliance report generation. Full data lifecycle governance.

7. **Decision Equivalence** (Module 37 extended) — ContentHash with identityBoundary, boundary profiles, projection-based cross-system comparison. Two systems can determine if they're making "the same decision" across protocol boundaries.

---

## THE THREE PAPER OPTIONS

### Option A: Faceted Narrowing (Formal / Theoretical)

**Title:** "Faceted Narrowing: Product Lattice Authority Attenuation for Autonomous Agent Governance"

**Contribution:** Takes a 50-year principle (capability attenuation, Dennis & Van Horn 1966) and proves it generalizes to an n-dimensional product lattice for LLM agent governance. Formal theorem with proof sketch. Four connections to established theory (Denning, Cousot, Scott, Miller). Running implementation with 1,507 tests and ConstraintVector as runtime representation.

**Strengths:**
- Formal theorem, not a position paper. Reviewers can verify the math.
- Novel: nobody has applied product lattice formalization to LLM agent authorization.
- Clean extension of Paper 1 — same protocol, deeper formalization.
- Implementation evidence: ConstraintVector, AuthorizationWitness, 7 denial paths.
- Connects to 50 years of theory (LBAC, abstract interpretation, domain theory, capabilities).
- Could target strong venues: IEEE S&P, USENIX Security, CCS main track.

**Weaknesses:**
- The formalization may be seen as "obvious" by lattice theory experts — product lattices over ordered sets is standard mathematics.
- The theorem is simple. The novelty is in the APPLICATION (to LLM agents), not the PROOF.
- Needs Belnap four-valued logic treatment (the 'unknown' constraint status) to be truly novel for formal methods reviewers.
- Empirical evaluation limited to "tests pass" — no comparative evaluation against alternative formulations.

**What's needed to complete:** LaTeX conversion. Formal proof tightening. Comparative evaluation showing faceted narrowing catches violations that non-faceted narrowing misses. ~3 sessions.

---

### Option B: Compliance-Complete Patterns (Empirical / Position)

**Title:** "Compliance-Complete Adversarial Patterns in Cryptographic Agent Governance"

**Contribution:** Taxonomy of 5 failure modes where all cryptographic governance checks pass and harmful outcomes still emerge. Core thesis: cryptographic governance amplifies these failures by producing false evidence of safety. Multi-model convergence across 3 frontier AI systems.

**Strengths:**
- The amplification thesis is genuinely novel — nobody has argued that crypto governance makes semantic failures WORSE.
- Multi-model convergence on all 5 patterns provides evidence beyond single-author opinion.
- Campaign 7 provides cross-protocol evidence (not just self-testing).
- Prior-art adjacency table explicitly addresses "isn't this just specification gaming / confused deputy."
- Practical: gives security practitioners vocabulary for a failure class they encounter but can't name.

**Weaknesses:**
- 6 rounds of hostile review produced verdict: "weak reject, fixable." Not yet at accept.
- Methodology (model-assisted threat elicitation) is novel but unproven — reviewers may reject it.
- Amplification thesis is argued, not empirically demonstrated. No HCI study.
- Evaluation is partially circular despite Campaign 7.
- Needs empirical harness: 5 evaluation scenarios with measured results + LangChain third-party test.
- Position paper at AISec workshop, not main track.

**What's needed to complete:** Empirical evaluation harness (5 scenarios run against code), LangChain Pattern 4 test, claim-level consistency fixes, LaTeX. ~5 sessions.

---

### Option C: Both Papers (Positive + Negative)

Paper A says: "Here's the best governance we can build, and the formal proof that authority always narrows."
Paper B says: "Here's what even perfect governance can't do, and why cryptographic proofs make it worse."

**Strengths:**
- Complete story. One positive, one self-critical. Extremely credible combination.
- Paper A (formal) strengthens Paper B (position) — the patterns are tested against a formally specified system, not ad-hoc code.
- Paper B strengthens Paper A — shows the author understands limits, not just strengths.

**Weaknesses:**
- Two papers = double the work.
- If Paper A targets a strong venue (S&P/USENIX) and Paper B targets AISec, they're on different timelines.
- Risk of spreading too thin as a solo author.

---

## QUESTIONS FOR YOUR REVIEW

1. **Which option maximizes scientific impact?** Not which is most interesting to read — which contributes the most to the field and is most likely to be cited.

2. **Which option is most publishable RIGHT NOW?** Given the current evidence base (1,507 tests, faceted narrowing formalization, Campaign 7, multi-model convergence), which paper requires the least additional work to reach acceptance at its target venue?

3. **Is Option A actually novel enough?** Product lattices over ordered sets are standard. Is applying them to LLM agent authorization enough, or will a formal methods reviewer say "this is a textbook construction applied to a new domain"?

4. **Is Option B fixable?** After 6 rounds of review, it's still at weak reject. Is this a paper that gets better with more work, or is the fundamental methodology (model-assisted elicitation) going to keep getting rejected?

5. **Is there an Option D we're not seeing?** Given the full system (80 modules, data governance, decision equivalence, evidence diversity, near-miss alerting, cross-protocol composition), is there a better paper hiding in this material that we haven't considered?

6. **If you had to pick one paper and submit it in 3 weeks, which would you write?**

Be direct. Tell me what to do, not what my options are. I have options. I need a decision.

---

## AFTER BOTH MODELS RESPOND

Feed each model's response to the other and ask: "Where do you agree? Where do you disagree? Which of their arguments changed your mind, if any?"

The convergence = the decision.
The divergence = what needs more thought.
