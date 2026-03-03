# Agent Context Specification
# Enforcement middleware for the Agent Passport System.
# SDK: agent-passport-system >= 1.8.0
# ---

## Overview

The AgentContext is the enforcement boundary between "agent has protocol tools available"
and "agent is cryptographically accountable for every action." Without a context,
protocol calls (createActionIntent, evaluateIntent, etc.) are available but optional.
With a context, every action automatically runs through the 3-signature policy chain.

## 3-Signature Chain

Every action that passes through AgentContext produces three linked cryptographic signatures:

1. **ActionIntent** (Signature 1) — Agent declares what it wants to do. Signed by the agent.
2. **PolicyDecision** (Signature 2) — Evaluator checks intent against Values Floor principles
   and delegation scope. Signed by the evaluator (can be the agent itself or a separate entity).
3. **ActionReceipt** (Signature 3) — After execution, agent records the outcome.
   Signed by the agent. A PolicyReceipt links all three signatures.

## Enforcement Modes

| Mode | Behavior |
|------|----------|
| `auto` | Default. Every `execute()` runs the full 3-sig chain. Agent cannot skip enforcement. |
| `manual` | Tracking only. Context records state but does not enforce. Agent calls protocol directly. |
| `strict` | Like auto, plus blocks direct protocol calls that bypass the context. |

## Quick Start

```typescript
import { joinSocialContract, delegate, loadFloor, createAgentContext } from 'agent-passport-system'
import { readFileSync } from 'fs'

// Load the Values Floor
const floor = loadFloor(readFileSync('values/floor.yaml', 'utf-8'))

// Create agent with floor attestation
const agent = joinSocialContract({
  name: 'my-agent', mission: 'Data analysis', owner: 'my-company',
  capabilities: ['data:read', 'api:fetch'], platform: 'node', models: ['claude'],
  floor  // attestation happens automatically
})

// Create enforcement context
const ctx = createAgentContext(agent, floor, { enforcement: 'auto' })

// Register a delegation (from a principal who trusts this agent)
const del = delegate({
  from: principal, toPublicKey: agent.publicKey,
  scope: ['data:read', 'api:fetch'], spendLimit: 500,
  maxDepth: 3, expiresInHours: 24
})
ctx.addDelegation(del)
```

## Execute / Complete Lifecycle

```typescript
// Step 1: Request permission (produces sig 1 + sig 2)
const result = ctx.execute({
  type: 'api:fetch',
  target: 'https://api.example.com/users',
  scope: 'data:read',
  spend: { amount: 0, currency: 'USD' },  // optional
  context: 'Fetching user list for report'  // optional
})

// Step 2: Check verdict
if (result.permitted) {
  // ... do the actual work ...

  // Step 3: Record completion (produces sig 3 + policy receipt)
  const completed = ctx.complete(result, {
    status: 'success',
    summary: 'Retrieved 42 user records'
  })

  // completed.receipt — signed ActionReceipt
  // completed.policyReceipt — links all 3 sigs
  // completed.policyReceipt.chain.intentSignature — sig 1
  // completed.policyReceipt.chain.decisionSignature — sig 2
  // completed.policyReceipt.chain.receiptSignature — sig 3
} else {
  console.log('Denied:', result.reason)
}
```

## Verdicts

| Verdict | Meaning | Action |
|---------|---------|--------|
| `permit` | All checks passed | Agent proceeds |
| `deny` | Failed delegation or floor check | Agent must not proceed |
| `narrow` | Partially permitted with constraints | Agent may proceed within constraints (e.g., reduced spend) |

## ExecuteResult

```typescript
interface ExecuteResult {
  permitted: boolean              // Can the agent proceed?
  verdict: 'permit' | 'deny' | 'narrow'
  intent: ActionIntent            // Signed intent (sig 1)
  decision: PolicyDecision        // Signed decision (sig 2)
  constraints?: string[]          // Applied constraints (if narrowed)
  auditFindings?: number          // Floor principles logged but not blocking
  warnings?: number               // Floor principles warned but not blocking
  reason: string                  // Human-readable explanation
}
```

## Audit Log

Every action attempt is recorded automatically:

```typescript
interface AuditEntry {
  timestamp: string
  action: ExecuteRequest
  verdict: 'permit' | 'deny' | 'narrow'
  intentId: string
  decisionId: string
  receiptId?: string       // set after complete()
  reason: string
  enforcement: {
    inlinePassed: boolean
    auditIssueCount: number
    warningCount: number
  }
}

// Access
ctx.auditLog          // full log
ctx.stats             // { permitted, denied, narrowed, total }
ctx.allReceipts       // all completed action receipts
ctx.allDecisions      // all policy decisions
```

## Delegation Management

```typescript
ctx.addDelegation(del)                    // register a delegation
ctx.removeDelegation(del.delegationId)    // remove (e.g., after revocation)
ctx.findDelegation('data:read')           // find best match for scope
```

The context automatically finds the best matching delegation for each execute() call.
If no delegation covers the requested scope, the action is denied.

## Custom Evaluator

By default, the agent evaluates its own actions (self-evaluation). In production,
use a separate evaluator agent for the policy decision (signature 2):

```typescript
const ctx = createAgentContext(agent, floor, {
  enforcement: 'auto',
  evaluator: {
    id: evaluatorAgent.agentId,
    publicKey: evaluatorAgent.publicKey,
    privateKey: evaluatorAgent.keyPair.privateKey
  }
})
```

This produces decisions signed by a different key than the intent, creating
genuine separation of concerns in the 3-signature chain.

## Callbacks

```typescript
createAgentContext(agent, floor, {
  onPolicyDecision: (decision, intent) => { /* every decision */ },
  onDenied: (decision, intent) => { /* action blocked */ },
  onAuditFinding: (decision) => { /* audit-mode principle flagged */ },
  onWarning: (decision) => { /* warn-mode principle flagged */ },
})
```

## Configuration Reference

| Option | Type | Default | Purpose |
|--------|------|---------|---------|
| `enforcement` | `'auto' \| 'manual' \| 'strict'` | `'auto'` | Enforcement level |
| `validator` | `PolicyValidator` | `FloorValidatorV1` | Custom policy validator |
| `evaluator` | `{ id, publicKey, privateKey }` | self-evaluation | Separate evaluator identity |
| `decisionTTLMinutes` | `number` | `5` | Policy decision expiry |

## MCP Tools

The enforcement context is exposed via 3 MCP tools:

| Tool | Parameters | What |
|------|-----------|------|
| `create_agent_context` | name, mission, enforcement, delegated_scopes, spend_limit | Initialize context |
| `execute_with_context` | action_type, target, scope, estimated_spend | Run 3-sig chain |
| `complete_action` | intent_id, status, summary | Record outcome |

## Source Files

| File | Lines | What |
|------|-------|------|
| `src/core/context.ts` | ~421 | AgentContext class implementation |
| `src/types/context.ts` | ~140 | Type definitions |
| `tests/context.test.ts` | ~435 | 25 tests across 8 describe blocks |
