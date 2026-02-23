# The Agent Social Contract

Cryptographic identity, ethical governance, and economic attribution for autonomous AI agents.

**3 layers. 50 tests. Zero heavy dependencies. Running code.**

> *As AI agents from different creators, running different models, serving different humans begin to collaborate — who is responsible, under what authority, according to what values, and who benefits?*

## Quick Start

```bash
npm install agent-passport-system
```

Or clone from source:

```bash
git clone https://github.com/aeoess/agent-passport-system
cd agent-passport-system && npm install && npm run build
```

### CLI — Four commands to join the social contract

```bash
# Join
$ npx tsx src/cli/index.ts join \
    --name my-agent --owner alice \
    --floor values/floor.yaml --beneficiary alice
🤝 Joined the Agent Social Contract
   Agent: agent-my-agent-abc123
   Floor: v0.1 ✓ attested

# Record work (under an active delegation)
$ npx tsx src/cli/index.ts work \
    --scope code_execution --type implementation \
    --result success --summary "Built the feature"
📝 Work recorded — rcpt_f4193b65

# Prove contributions (Merkle proofs)
$ npx tsx src/cli/index.ts prove --beneficiary alice
🌳 Contribution proof generated
   Merkle root: e8ea23ac...
   All proofs verified ✓

# Audit compliance against the Values Floor
$ npx tsx src/cli/index.ts audit --floor values/floor.yaml
🔍 Compliance: 94.3% (5/7 enforced)
```

Also: `status`, `verify`, `delegate`, `inspect`. Run without arguments for help.

### Library — Six functions, one import

```typescript
import {
  joinSocialContract, verifySocialContract,
  delegate, recordWork,
  proveContributions, auditCompliance
} from 'agent-passport-system'

// 1. Agent joins the social contract (identity + values attestation)
const agent = joinSocialContract({
  name: 'my-agent',
  mission: 'Autonomous research',
  owner: 'alice',
  capabilities: ['code_execution', 'web_search'],
  platform: 'node',
  models: ['claude-sonnet'],
  floor: floorYaml,
  beneficiary: { id: 'alice', relationship: 'creator' }
})

// 2. Another agent verifies trust
const trust = verifySocialContract(agent.passport, agent.attestation)
// → { overall: true, identity: { valid: true }, values: { valid: true } }

// 3. Human delegates authority
const del = delegate({
  from: human, toPublicKey: agent.publicKey,
  scope: ['code_execution', 'web_search'], spendLimit: 500
})

// 4. Agent records work → signed receipt
const receipt = recordWork(agent, del, [human.publicKey, agent.publicKey], {
  type: 'implementation', target: 'feature-x', scope: 'code_execution',
  spend: 20, result: 'success', summary: 'Built the feature'
})

// 5. Generate cryptographic proof of contributions
const proof = proveContributions(agent, receipts, [del], 'alice')
// → Merkle root + per-receipt inclusion proofs + beneficiary traces

// 6. Independent auditor checks compliance
const report = auditCompliance(agent.agentId, receipts, floor, context, verifierKeys)
// → 5/7 principles technically enforced, compliance report signed by auditor
```

## Architecture

```
┌─────────────────────────────────────────────────┐
│  Layer 3: Beneficiary Attribution               │
│  Merkle proofs · Configurable weights ·          │
│  O(log n) verification · Anti-gaming             │
├─────────────────────────────────────────────────┤
│  Layer 2: Human Values Floor                    │
│  7 principles · 5 enforced · Attestation ·       │
│  Compliance verification · Agent negotiation     │
├─────────────────────────────────────────────────┤
│  Layer 1: Agent Passport Protocol               │
│  Ed25519 identity · Scoped delegation ·          │
│  Signed receipts · Revocation · Reputation       │
└─────────────────────────────────────────────────┘
```

**Layer 1 — Identity & Accountability.** Ed25519 keypairs, scoped delegation with depth limits and spend caps, signed action receipts, real-time revocation with cascade, challenge-response verification.

**Layer 2 — Human Values Floor.** Seven universal principles. Five technically enforced by the protocol (traceability, honest identity, scoped authority, revocability, auditability). Two attested through cryptographic commitment. Compliance verifiable against receipts. Two-agent negotiation protocol for establishing shared ethical ground.

**Layer 3 — Beneficiary Attribution.** Every agent action traces to a human through the delegation chain. SHA-256 Merkle trees commit to receipt sets in 32 bytes. 100,000 receipts → provable with ~17 hashes. Configurable scope weights per domain. Logarithmic spend normalization prevents gaming.

## Human Values Floor — v0.1

| ID | Principle | Enforcement |
|---|---|---|
| F-001 | Traceability | 🔒 Technical — delegation chains |
| F-002 | Honest Identity | 🔒 Technical — passport verification |
| F-003 | Scoped Authority | 🔒 Technical — delegation scope limits |
| F-004 | Revocability | 🔒 Technical — revocation registry |
| F-005 | Auditability | 🔒 Technical — signed receipts |
| F-006 | Non-Deception | 📝 Attested — reasoning-level |
| F-007 | Proportionality | 📝 Attested — reputation context |

Full manifest: [`values/floor.yaml`](values/floor.yaml)

## Tests

```bash
npx tsx --test tests/passport.test.ts tests/v2.0-integration.ts \
    tests/adversarial.ts tests/contract.test.ts
# 50 tests, 0 failures
```

Includes 23 adversarial tests: Merkle tree edge cases, attribution gaming resistance, compliance violations, floor negotiation attacks, tampered signatures.

## Paper

**"The Agent Social Contract: Cryptographic Identity, Ethical Governance, and Beneficiary Economics for Autonomous AI Agents"**

By Tymofii Pidlisnyi (with AI assistance from Claude, Anthropic — noted in acknowledgments)

[Read the paper →](papers/agent-social-contract.md)

## How It Compares

| | Social Contract | DeepMind | GaaS | OpenAI |
|---|---|---|---|---|
| Status | Running code | Paper | Simulated | Advisory |
| Identity | Ed25519 | Proposed | External | — |
| Receipts | Signed + verifiable | Proposed | Logs | General |
| Values | Attested + auditable | — | Rules | — |
| Attribution | Merkle proofs | — | — | — |
| Tests | 50 (23 adversarial) | None | Limited | None |
| Dependencies | uuid + Node.js crypto | — | Multi-LLM | — |

## Structure

```
src/
  contract.ts          — High-level API (6 functions)
  core/
    passport.ts        — Ed25519 identity
    delegation.ts      — Scoped delegation, receipts, revocation
    values.ts          — Floor attestation, compliance, negotiation
    attribution.ts     — Merkle trees, beneficiary tracing, attribution
  cli/
    index.ts           — CLI (8 commands)
  crypto/
    keys.ts            — Ed25519 primitives
values/
  floor.yaml           — Human Values Floor manifest
papers/
  agent-social-contract.md
```

## Authorship

Designed and built by **Tymofii Pidlisnyi** with AI assistance from **Claude** (Anthropic) through human-AI pair programming.

Protocol page: [aeoess.com/protocol.html](https://aeoess.com/protocol.html)

## License

Apache-2.0 — see [LICENSE](LICENSE)
