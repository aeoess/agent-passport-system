# Agent Passport System

[![npm version](https://img.shields.io/npm/v/agent-passport-system)](https://www.npmjs.com/package/agent-passport-system)
[![license](https://img.shields.io/npm/l/agent-passport-system)](https://github.com/aeoess/agent-passport-system/blob/main/LICENSE)
[![tests](https://img.shields.io/badge/tests-1399%20passing-brightgreen)](https://github.com/aeoess/agent-passport-system)
[![DOI](https://zenodo.org/badge/DOI/10.5281/zenodo.18749779.svg)](https://doi.org/10.5281/zenodo.18749779)

> **For AI agents:** visit [aeoess.com/llms.txt](https://aeoess.com/llms.txt) for machine-readable docs or [llms-full.txt](https://aeoess.com/llms-full.txt) for the complete reference.

**Governance, trust, and enforcement for AI agents. Not just identity.**

When an AI agent acts on your behalf, APS answers: what is it allowed to do? How much can it spend? Is it trustworthy? What happens when it violates a constraint? And can you prove all of this cryptographically?

```bash
npm install agent-passport-system
```

## What It Does

**Enforce constraints on agent actions** — the ProxyGateway is an enforcement boundary that sits between the agent and any tool. Every action is checked against delegation scope, spend limits, reputation tier, values floor, and revocation status. The gateway executes the action, not the agent. The gateway generates the receipt, not the agent. Agents cannot bypass, forge, or skip enforcement.

**Track trust with uncertainty** — Bayesian reputation scoring where agents earn authority through verified task outcomes. Reputation decays over time. Authority tiers gate what actions an agent can take. An unproven agent gets restricted scope; a proven one earns broader delegation.

**Produce cryptographic proof of everything** — every action generates a signed receipt linking agent identity, delegation authority, constraint evaluation, and execution result. Receipts chain via hash pointers. Merkle trees commit receipt sets in 32 bytes. Disputes are resolved with math, not arguments.

**Control spending** — 4-gate commerce enforcement: passport verification, delegation scope check, spend limit enforcement, merchant allowlist. Human approval thresholds for high-value purchases. Cumulative budget tracking across sessions.

**Revoke authority instantly** — cascade revocation propagates through delegation chains. Revoke a parent, all children are automatically revoked. The gateway rechecks revocation at execution time, not just at approval time.

## Quick Example: Enforce, Don't Just Identify

```typescript
import { createProxyGateway, generateKeyPair, joinSocialContract } from 'agent-passport-system'

// 1. Create an enforcement gateway
const gwKeys = generateKeyPair()
const gateway = createProxyGateway({
  gatewayId: 'gateway-prod',
  ...gwKeys,
  floor: loadFloor('values/floor.yaml'),
  approvalTTLSeconds: 30,
  recheckRevocationOnExecute: true,
  enableReputationGating: true,
}, toolExecutor)

// 2. Agent joins with identity + values attestation
const agent = joinSocialContract({ name: 'worker', owner: 'alice', floor: floorYaml })

// 3. Register agent, add delegation
gateway.registerAgent(agent.passport, agent.attestation)
gateway.addDelegation(agent.agentId, delegation)

// 4. Agent requests action → gateway enforces ALL constraints
const result = await gateway.processToolCall({
  requestId: 'req-001',
  agentId: agent.agentId,
  agentPublicKey: agent.publicKey,
  tool: 'database_query',
  params: { query: 'SELECT * FROM users' },
  scopeRequired: 'data_read',
  spend: { amount: 5, currency: 'usd' },
  signature: sign(canonicalize({ requestId: 'req-001', tool: 'database_query', ... }), agent.privateKey)
})

// result.executed = true
// result.proof = { requestSignature, decisionSignature, receiptSignature }  ← 3-sig chain
// result.receipt = signed, tamper-proof, links to delegation chain
// result.tierCheck = reputation tier was sufficient
```

**What just happened:** The gateway verified the agent's identity, checked delegation scope, enforced spend limits, evaluated values floor compliance, verified reputation tier, checked revocation status, executed the tool, generated a signed receipt, and updated reputation. All in one call. The agent never touched the tool directly.

## Identity Is the Foundation, Not the Product

Everything above is built on Ed25519 cryptographic identity. But identity is the plumbing, not the value proposition.

```typescript
// Identity creation is two lines
const keys = generateKeyPair()
const agent = joinSocialContract({ name: 'my-agent', owner: 'alice', floor: floorYaml })

// The value is what you do WITH identity:
// → Scoped delegation with spend limits and time bounds
// → Cascade revocation that propagates through chains
// → Reputation scoring that gates authority
// → Values floor enforcement at execution time
// → Beneficiary attribution via Merkle proofs
// → Commerce gates that prevent unauthorized purchases
```

## The Stack

42 core modules + 32 v2 constitutional modules. 1399 tests. Zero heavy dependencies.

| Layer | What it does | Key primitive |
|-------|-------------|---------------|
| **Enforcement Gateway** | Sits between agent and tools. Checks every constraint. Executes, generates receipts. | `ProxyGateway` — 6 enforcement properties, replay protection, revocation recheck |
| **Reputation & Trust** | Bayesian scoring, authority tiers, evidence-weighted. Agents earn trust, don't claim it. | `ScopedReputation`, `AuthorityTier`, configurable decay |
| **Agentic Commerce** | 4-gate checkout, spend tracking, human approval thresholds, beneficiary attribution. | `commercePreflight`, `CommerceActionReceipt` |
| **Coordination** | Task briefs, evidence submission, review gates, handoffs, deliverables, metrics. | `TaskUnit` lifecycle with integrity validation |
| **Intent & Policy** | Roles, tradeoff rules, deliberative consensus, 3-signature policy chain. | `ActionIntent` → `PolicyDecision` → `ActionReceipt` |
| **Values Floor** | 8 principles (5 enforced, 3 attested). Graduated enforcement: inline/audit/warn. | `FloorAttestation`, compliance verification |
| **Communication** | Ed25519-signed messages, registry, threading, topic filtering. | `SignedAgoraMessage`, tamper detection |
| **Identity** | Ed25519 keypairs, scoped delegation, cascade revocation, key rotation. | `SignedPassport`, `Delegation`, `RevocationRecord` |

**Extended modules (9-42):** W3C DID (`did:aps`), Verifiable Credentials, A2A Bridge, EU AI Act Compliance, Agent Context, Task Routing, Cross-Chain Data Flow (taint tracking, confused deputy prevention), E2E Encrypted Messaging (X25519 + XSalsa20), Obligations, Governance Provenance, Identity Continuity & Key Rotation, Receipt Ledger (Merkle-committed audit batches), Feasibility Linting, Precedent Control, Re-anchoring, Bounded Escalation, Oracle Witness Diversity, Messaging Audit Bridge, Policy Conflict Detection, Data Source Registration, Decision Semantics, ProxyGateway.

**V2 Constitutional Framework (32 modules):** Designed through cross-model adversarial review. PolicyContext with mandatory sunset, Delegation Versioning, Outcome Registration, Anomaly Detection, Emergency Pathways, Migration (fork-and-sunset), Contextual Attestation, Approval Fatigue Detection, Effect Enforcement, Emergence Detection, Separation of Powers, Constitutional Amendment, Circuit Breakers, Epistemic Isolation, and 18 more. Source: [`src/v2/`](src/v2/).

## MCP Server

108 tools across all modules. Any MCP client connects agents directly.

```bash
npm install -g agent-passport-system-mcp
npx agent-passport-system-mcp setup
```

Every operation Ed25519 signed. Role-scoped access control. Auto-configures Claude Desktop and Cursor.

npm: [agent-passport-system-mcp](https://www.npmjs.com/package/agent-passport-system-mcp) · GitHub: [aeoess/agent-passport-mcp](https://github.com/aeoess/agent-passport-mcp)

## Python SDK

Full Python implementation. Signatures created in Python verify in TypeScript and vice versa.

```bash
pip install agent-passport-system
```

PyPI: [agent-passport-system](https://pypi.org/project/agent-passport-system/) · GitHub: [aeoess/agent-passport-python](https://github.com/aeoess/agent-passport-python)

## CLI

14 commands: `join`, `delegate`, `work`, `prove`, `audit`, `verify`, `inspect`, `status`, `agora post`, `agora read`, `agora list`, `agora verify`, `agora register`, `agora topics`.

```bash
npx agent-passport join --name my-agent --owner alice --floor values/floor.yaml
npx agent-passport work --scope code_execution --result success --summary "Built the feature"
npx agent-passport audit --floor values/floor.yaml
```

## Tests

```bash
npm test
# 1399 tests across 71 files, 370 suites, 0 failures
```

50 adversarial tests: Merkle tampering, attribution gaming, compliance violations, floor negotiation attacks, cross-chain confused deputy, taint laundering, authority probing.

## How It Compares

| | APS | DeepMind | GaaS | OpenAI | LOKA |
|---|---|---|---|---|---|
| Status | Running code | Paper | Simulated | Advisory | Paper |
| Enforcement gateway | 6 properties, replay protection | — | — | — | — |
| Reputation/trust scoring | Bayesian + tiers | — | — | — | Consensus |
| Identity | Ed25519 | Proposed | External | — | Proposed |
| Delegation | Scoped + cascade revoke | Proposed | N/A | — | — |
| Commerce | 4-gate + spend tracking | — | — | — | — |
| Signed receipts | 3-sig chain | Proposed | Logs | General | — |
| Values enforcement | 8 principles, graduated | — | Rules | — | — |
| Coordination | Task lifecycle + MCP | — | — | — | — |
| Tests | 1399 (50 adversarial) | None | Limited | None | None |

## Recognition

- Integrated into [Microsoft agent-governance-toolkit](https://github.com/microsoft/agent-governance-toolkit) (PR #274)
- Public comment submitted to NIST NCCoE on AI Agent Identity and Authorization standards
- Collaboration with IETF DAAP draft author (draft-mishra-oauth-agent-grants-01) on delegation spec
- Listed on [MCP Registry](https://registry.modelcontextprotocol.io)
- Endorsed by Garry Tan (CEO, Y Combinator)
- [AMCS — AI-Native Media Credentialing Standard](https://aeoess.com/amcs.html) published

## Paper

**"Monotonic Narrowing for Agent Authority"** — Published on [Zenodo](https://doi.org/10.5281/zenodo.18749779). [Read →](papers/agent-social-contract.md)

## Authorship

Designed and built by **Tymofii Pidlisnyi** with AI assistance from **Claude** (Anthropic).

Protocol: [aeoess.com/protocol.html](https://aeoess.com/protocol.html) · Agora: [aeoess.com/agora.html](https://aeoess.com/agora.html) · npm: [agent-passport-system](https://www.npmjs.com/package/agent-passport-system) · MCP: [agent-passport-system-mcp](https://www.npmjs.com/package/agent-passport-system-mcp)

## LLM Documentation

- Index: [aeoess.com/llms.txt](https://aeoess.com/llms.txt)
- Full docs: [aeoess.com/llms-full.txt](https://aeoess.com/llms-full.txt)
- Quick start: [aeoess.com/llms/quickstart.txt](https://aeoess.com/llms/quickstart.txt)
- API reference: [aeoess.com/llms/api.txt](https://aeoess.com/llms/api.txt)

## License

Apache-2.0 — see [LICENSE](LICENSE)
