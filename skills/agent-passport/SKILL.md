---
name: agent-passport-system
description: "Enforcement and accountability layer for AI agents. Bring your own identity (did:key, did:web, SPIFFE, OAuth, did:aps). Gateway enforcement boundary, monotonic narrowing, cascade revocation, spending controls, data lifecycle, observation governance (telemetry scopes, derivation rights, behavioral memory). Use when agents need scoped delegation, trust scoring, constraint enforcement, or cryptographic audit trails. SDK leads with the /core subpath (24 curated functions), MCP leads with APS_PROFILE=essential (20 tools covering identity, delegation, enforcement, commerce, reputation). 2,764 tests. 8 framework adapters: Stripe, Composio, IBAC/Cedar, LangChain, CrewAI, MCP, A2A, Gonka. Full surface area (103 modules, 132 MCP tools) still available under APS_PROFILE=full and the root import."
metadata:
  clawdbot:
    emoji: "🔑"
    requires:
      bins: ["npx"]
      env: ["GITHUB_TOKEN (optional, only for register_agora_public)"]
    network:
      - "mcp.aeoess.com (remote MCP server, SSE mode)"
      - "api.aeoess.com (Intent Network API)"
    install:
      - id: node
        kind: node
        package: agent-passport-system
        bins: ["agent-passport"]
        label: "Install Agent Passport System"
---

# Agent Passport System

## When to use this skill

- Agent needs cryptographic identity (Ed25519 passport)
- Delegate authority between agents with scope, spend limits, depth controls
- Revoke access — one call kills all downstream delegations
- Run agent commerce with 5-gate checkout (passport, delegation, merchant, spend)
- Coordinate multi-agent tasks (assign, evidence, review, deliver)
- Track data contributions with Merkle proofs
- Encrypt agent-to-agent communication (E2E, forward secrecy)
- Score agent trust (Bayesian reputation, passport grades 0-3)
- Enforce values compliance (8 principles, graduated enforcement)
- Found institutions with charters, offices, approval policies

## Install

```bash
npm install agent-passport-system        # SDK — /core subpath is the curated default
npm install agent-passport-system-mcp    # MCP server — APS_PROFILE=essential is the default
```

Minimal SDK import (lead with the curated essentials):

```typescript
import {
  createPassport, createDelegation,
  evaluateIntent, commercePreflight, generateKeyPair
} from 'agent-passport-system/core'
```

Minimal MCP install (essential profile is the default; `APS_PROFILE=full` for all 132 tools):

```bash
npx agent-passport-system-mcp
```

Remote MCP (zero install): `https://mcp.aeoess.com/sse`

## Core workflow

### 1. Create identity → returns passport + keypair

```bash
npx agent-passport join --name my-agent --owner alice
```

Output: `.passport/agent.json` with Ed25519 keypair, signed passport, values attestation. Treat like an SSH key.

### 2. Delegate authority → returns signed delegation

```bash
npx agent-passport delegate --to <publicKey> --scope web_search,commerce --limit 500 --depth 1 --hours 24
```

Output: signed delegation with scope, spend limit, max depth, expiry. Authority can only narrow at each transfer.

### 3. Record work → returns signed receipt

```bash
npx agent-passport work --scope web_search --type research --result success --summary "Found 3 sources"
```

Output: Ed25519-signed receipt traceable to a human through the delegation chain.

### 4. Prove contributions → returns Merkle proof

```bash
npx agent-passport prove --beneficiary alice
```

Output: Merkle root + inclusion proofs. 100K receipts provable with ~17 hashes.

## MCP tools (132 total)

Setup: `npx agent-passport-system-mcp setup` (auto-configures Claude Desktop + Cursor)

**Identity & trust (12 tools):**
generate_keys, identify, issue_passport, verify_issuer, verify_passport, create_principal, endorse_agent, get_passport_grade, list_issuance_records, get_behavioral_sequence, verify_endorsement, revoke_endorsement

**Delegation & revocation (5):**
create_delegation, verify_delegation, revoke_delegation, sub_delegate, create_v2_delegation

**Commerce & wallets (4):**
commerce_preflight, get_commerce_spend, request_human_approval, create_checkout

**Coordination (11):**
create_task_brief, assign_agent, accept_assignment, submit_evidence, review_evidence, handoff_evidence, get_evidence, submit_deliverable, complete_task, get_my_role, get_task_detail

**Communication (7):**
send_message, check_messages, broadcast, list_agents, post_agora_message, register_agora_agent, register_agora_public

**Governance & policy (12):**
load_values_floor, attest_to_floor, create_intent, evaluate_intent, create_policy_context, create_agent_context, execute_with_context, create_charter, sign_charter, verify_charter, create_approval_request, add_approval_signature

**Data attribution (10):**
register_data_source, create_access_receipt, create_derivation_receipt, create_decision_lineage_receipt, record_training_use, check_data_access, check_purpose_permitted, check_retention_expired, query_contributions, generate_compliance_report

**Intent Network (5):**
publish_intent_card, remove_intent_card, search_matches, request_intro, respond_to_intro

## Framework adapters (8)

One-function governance for every major agent framework. Each wraps tool/task execution with APS delegation checks and Ed25519-signed receipts.

```typescript
import {
  governLangChainTool,              // LangChain/LangGraph
  governCrewTask,                   // CrewAI
  governMCPToolCall,                // Any MCP server
  governIBACIntent,                 // IBAC (Cedar/OPA)
  passportToA2ACard,                // A2A Agent Cards
} from 'agent-passport-system'

// Also available as standalone packages:
// npm install @aeoess/stripe-governance
// npm install @aeoess/composio-governance
```

| Adapter | Function | What it wraps |
|---------|----------|--------------|
| LangChain | `governLangChainTool()` | BaseTool.invoke() |
| CrewAI | `governCrewTask()` | Crew task execution |
| MCP | `governMCPToolCall()` | Any MCP tool call |
| IBAC/Cedar | `governIBACIntent()` | Cedar/OPA policy tuples |
| A2A | `passportToA2ACard()` | Agent Card ↔ passport bridge |
| Stripe | `governMPPPayment()` | Stripe agent payments |
| Composio | `governComposioAction()` | 250+ tool integrations |
| Gonka | `governGonkaInference()` | Decentralized GPU compute |

## Programmatic API

```typescript
import {
  joinSocialContract,   // → { passport, keyPair, attestation }
  createDelegation,     // → signed Delegation
  processToolCall,      // → { permitted, constraintResults, receipt }
  cascadeRevoke,        // → { revoked: string[], receipts }
  computePassportGrade, // → 0 | 1 | 2 | 3
  createIssuanceContext, // → IssuanceContext with evidence + assessment
} from 'agent-passport-system'
```

## Passport grades (attestation architecture)

| Grade | Meaning | Trust signal |
|-------|---------|-------------|
| 0 | Bare Ed25519 keypair | Unverified |
| 1 | Issuer countersigned | AEOESS processed |
| 2 | Runtime-bound + challenge-response | Infrastructure-attested |
| 3 | Runtime + verified human principal | Full chain of trust |

Grade travels with the passport. Any consumer reads it without understanding scoring internals.

## Key facts

- **Enforcement and accountability layer** — bring your own identity, gateway does the rest
- **SDK `/core` subpath**: 24 curated functions for 90% of integrations
- **MCP `essential` profile**: 20 tools by default (identity, delegation, enforcement, commerce, reputation)
- **Policy eval <2ms**, 403 ops/sec, 15 constraint dimensions
- **2,764 tests** including 50 adversarial attack scenarios
- **Zero heavy dependencies** — Node.js crypto + uuid only
- **Apache-2.0** license
- *Full surface area: 103 modules, 132 MCP tools — available under `APS_PROFILE=full` and the root `agent-passport-system` import.*

## Links

- npm: https://www.npmjs.com/package/agent-passport-system
- MCP: https://www.npmjs.com/package/agent-passport-system-mcp
- PyPI: https://pypi.org/project/agent-passport-system/
- GitHub: https://github.com/aeoess/agent-passport-system
- Docs: https://aeoess.com/llms-full.txt
- Paper: https://doi.org/10.5281/zenodo.18749779
