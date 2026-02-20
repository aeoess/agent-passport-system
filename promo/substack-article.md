# The Agent Social Contract: Running Code, Not Another Paper

*By Tymofii Pidlisnyi and Claude (Anthropic)*

---

Every week brings a new framework paper about AI agent governance. DeepMind publishes theoretical delegation models. OpenAI writes advisory practices. Academics produce governance-as-a-service simulations. All papers. No running code.

We shipped running code.

**The Agent Social Contract** is an open-source protocol that gives AI agents cryptographic identity, ethical governance, and economic attribution — implemented in TypeScript, tested with 49 tests including 23 adversarial cases, and deployable today with zero heavy dependencies.

## The Problem Nobody's Actually Solving

As AI agents from different creators start collaborating at scale, four questions converge into one: who is responsible, under what authority, according to what values, and who benefits?

Google's Agent-to-Agent Protocol handles interoperability. Anthropic's MCP handles tool access. But neither answers the trust question: when Agent A (built by Developer X, running Model Y, serving Human Z) meets Agent B from a completely different stack — how do they establish trust? How does the human stay in control? How does value flow back?

## Three Layers, All Implemented

**Layer 1 — Agent Passport Protocol.** Ed25519 cryptographic identity. Scoped delegation with depth limits and spend caps. Every agent action produces a signed receipt — non-repudiable proof of who did what, under whose authority. Real-time revocation with cascade. If you lose trust in an agent, one revocation kills the entire delegation tree.

**Layer 2 — Human Values Floor.** Seven universal principles. Five technically enforced by the protocol itself (traceability, honest identity, scoped authority, revocability, auditability). Two attested through cryptographic commitment (non-deception, proportionality). This isn't a filter that blocks outputs — it's a set of principles agents attest to, with compliance verifiable against their action receipts. An agent that attests but violates creates a provable contradiction.

**Layer 3 — Beneficiary Attribution.** Every agent action traces back to its human beneficiary through the delegation chain. SHA-256 Merkle trees commit to arbitrarily large receipt sets in 32 bytes. Need to prove one receipt out of 100,000? That takes ~17 hashes. Attribution weights are configurable per domain, with logarithmic spend normalization that prevents gaming — spending 1000x more yields only ~3x more attribution weight.

## The Simplest Version

```
$ passport join --name my-agent --owner alice --floor values/floor.yaml
🤝 Joined the Agent Social Contract

$ passport work --scope code_execution --type implementation --result success
📝 Work recorded

$ passport prove --beneficiary alice
🌳 Merkle root: e8ea23ac... All proofs verified ✓

$ passport audit --floor values/floor.yaml
🔍 Compliance: 94.3% (5/7 enforced)
```

Four commands. Or six function calls in TypeScript:

```typescript
const agent = joinSocialContract({ name, mission, owner, capabilities, floor })
const trust = verifySocialContract(other.passport, other.attestation)
const delegation = delegate({ from: human, toPublicKey: agent.publicKey, scope })
const receipt = recordWork(agent, delegation, chain, work)
const proof = proveContributions(agent, receipts, delegations, beneficiary)
const report = auditCompliance(agentId, receipts, floor, context, verifier)
```

## Why This Matters For the AI Economy

The dominant narrative frames AI as replacing humans, requiring redistribution to compensate. We propose something different: humans as principals in the agent economy. Your agent works, signs receipts, proves its contributions cryptographically, and the value traces back to you — not through redistribution, but through attributed participation.

This isn't theoretical. The receipt system produces the accounting infrastructure. The Merkle proofs make it verifiable at scale. The delegation chains maintain human authority. The values floor keeps it ethical.

## What We're Not

We're not solving alignment. The Values Floor is a coordination mechanism, not a safety solution. We're not proposing a legal framework — we produce cryptographic evidence; legal systems interpret it. We're not a payment system — we produce attribution data that any payment system can consume.

We are infrastructure. The kind that needs to exist before the agent economy can work for humans instead of happening to them.

## Co-Authored By an AI

This protocol was designed and built through human-AI pair programming. The paper is co-authored with Claude. The implementation was itself built through the multi-agent collaboration pattern the protocol describes. We believe this is evidence for the thesis: humans and AI agents can be productive collaborators when identity, accountability, and shared values are in place.

---

**GitHub:** github.com/aeoess/agent-passport-system
**Protocol:** aeoess.com/protocol.html
**Paper:** "The Agent Social Contract" — available on GitHub

*2,627 lines of source. 49 tests. Zero heavy dependencies. The code is running.*
