# Agent Passport v1.1: From Identity to Accountability

**First open-source accountability layer for autonomous AI agents ships with signed action receipts, delegation revocation, and depth-limited trust chains.**

---

*February 20, 2026*

A week ago we shipped Agent Passport v1.0: cryptographic identity for AI agents. Ed25519 signatures, reputation scoring, delegation with spend limits. The question it answered: *"What is this agent authorized to do?"*

Today we ship v1.1. It answers the harder question: *"What did this agent actually do, and can we stop it?"*

---

## The Gap Nobody Was Talking About

Identity is table stakes. Google's AP2 protocol has 60+ partners (Mastercard, PayPal, Adyen) working on agent-to-agent payments. DeepMind published a paper on authenticated delegation in January. The EU is building agent accountability into its digital wallet architecture.

They all converge on the same three missing primitives:

1. **Signed proof of execution**: not just "what can this agent do" but "what did it do, and can you verify that cryptographically"
2. **Real-time revocation**: if an agent goes rogue, kill its permissions instantly, don't wait for expiry
3. **Controlled delegation chains**: Agent A delegates to Agent B who delegates to Agent C. How deep can that chain go before accountability dissolves?

The big players are solving this for payments, auth flows, and identity credentials. We're solving it at the infrastructure layer: for every agent action, across any platform.

---

## What Shipped

### Action Receipts

When an agent executes a delegated task, it signs a receipt. The receipt contains: what was done, under which delegation, what the result was, and the full chain of authority from human principal to executing agent.

The receipt is signed with the agent's Ed25519 key. Anyone holding the agent's public key can verify it. Tamper-evident, non-repudiable, portable.

This is the audit trail that's been missing. Not logging. Not observability dashboards. Cryptographic evidence.

### Delegation Revocation

In v1.0, if you delegated authority to an agent, you waited for the delegation to expire. In v1.1, you can revoke instantly.

Revocation cascades. If Agent A delegated to Agent B who sub-delegated to Agent C, revoking A→B automatically invalidates B→C. One action, full cascade.

Two verification modes: lightweight revocation lists (cached, fast) or real-time challenge-response (higher latency, guaranteed accuracy). Both use Ed25519. No certificate authorities. No blockchain.

### Depth Limits

Every delegation now carries a `max_depth` field. Set it to 0 and the agent can't sub-delegate at all. Set it to 1 and it can pass authority once, no further. The scope can only narrow with each hop. The spend limit can only decrease. Each link in the chain is weaker than the last, by design.

---

## Tested, Not Theoretical

This isn't a white paper. We built it, tested it, and pushed it.

The integration test creates real passports for two agents (aeoess and PortalX2), then runs through the full lifecycle: delegation, execution with signed receipts, sub-delegation with depth enforcement, scope violation blocking, revocation, and post-revocation action blocking.

Every action is traceable through the delegation chain. Every receipt is cryptographically verifiable. Every revocation cascades correctly.

Fifteen v1.0 tests still pass. Fully backward compatible.

---

## What This Is Not

This is not a smart contract platform. We looked at every serious implementation (Google, DeepMind, the EU, W3C) and none of them use blockchain for agent accountability. Ed25519 signatures provide the same cryptographic guarantees without the latency, cost, and infrastructure dependency.

This is not a legal framework. The protocol provides the data: signed, verifiable evidence of who authorized what, who did what, and what happened. Courts and contracts interpret that data. We stay in our lane.

This is not enterprise middleware. It's 266 lines of TypeScript with zero external dependencies beyond Node.js. Import it in one line. Run it anywhere.

---

## Why This Matters Now

The agent economy is forming right now. Companies are building agents that book flights, manage portfolios, negotiate contracts, write code. These agents will operate with real authority and real money.

The ones that don't have an accountability layer will be the ones that make the news for the wrong reasons. The ones that do will be the ones enterprises actually trust.

We're not building this for the AI safety papers. We're building it because autonomous agents need the same primitives that the financial system figured out centuries ago: identity, authority, receipts, and the ability to say stop.

---

**Links:**
- GitHub: [github.com/aeoess/agent-passport-system](https://github.com/aeoess/agent-passport-system)
- Full Spec: [SPEC-v1.1.md](https://github.com/aeoess/agent-passport-system/blob/main/docs/SPEC-v1.1.md)
- Live Demo: [aeoess.com/passport.html](https://aeoess.com/passport.html)
- Democratic Protocol: [aeoess.com/protocol.html](https://aeoess.com/protocol.html)
