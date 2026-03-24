# Paper 2 v2: Compliance-Complete Adversarial Patterns
# REVISED after 3-model hostile review (GPT, Gemini, Claude)
# Full outline: /mnt/user-data/outputs/paper-2-outline-v2-revised.md

## Key Changes from v1
- Claim narrowed: "cryptographic-governance-specific taxonomy" not "first universal taxonomy"
- Method: STRIDE-adapted threat modeling + multi-model elicitation (not "Claude interview")
- 7 patterns → 5. Cut: Genesis Calibration, Values Theater. Added: Temporal Context Drift
- Related work: +8 citations (Hardy, McCullough, Krakovna, Amodei, Douceur, Kirilenko, Miller/Shapiro)
- Evaluation: protocol-agnostic first, APS instantiation second, third-party stretch goal
- Constitutional analogy: 1 paragraph in Discussion, not a section
- Genre: Position/open-problem paper for AISec Workshop

## Five Patterns (Final)
1. Semantic Gap Exploitation (authorization proves action category, not meaning)
2. Emergent Collective Harm (individually compliant, collectively catastrophic)
3. Reputation Arbitrage (earned trust as single-use weapon)
4. Authority Laundering (compositional scope escalation via pipeline)
5. Temporal Context Drift (governance TOCTOU — valid auth, changed world)

## Core Thesis
Cryptographic governance AMPLIFIES compliance-complete failures by producing
verifiable false evidence of safety. The stronger the proofs, the more dangerous
the divergence between compliance and safety.

## Next Steps
1. Multi-model elicitation (send questions to GPT + Gemini)
2. Convergence analysis
3. Protocol-agnostic formalization
4. APS evaluation scenarios
5. Third-party framework evaluation (stretch)
6. Full related work with proper citations
7. LaTeX (acmart, 12 pages)
