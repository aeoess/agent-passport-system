# APS Governance Adapter for Composio Tool Execution

**The authorization layer between your agent and 250+ tools.**

Composio handles authentication and connectivity. APS handles who authorized which tool, within what scope, and produces the audit trail. Neither replaces the other.

## The Problem

Composio gives agents access to 250+ tool integrations with managed OAuth. But OAuth answers "can this app access this account?" not:

- **Which specific agent** is authorized to use this tool?
- **What actions** can this agent perform (read but not delete)?
- **Are destructive actions** (delete, drop, destroy) explicitly authorized?
- **Can we trace** this tool call back to the human principal who delegated authority?
- **What happens** when a tool call fails?

APS delegation answers all five.

## How It Works

```
Agent wants to read a Salesforce account
       |
       v
+---------------------------+
|  APS Governance Gates     |
|                           |
|  1. Passport valid?       |  <- Agent identity (Ed25519)
|  2. Delegation scope?     |  <- Scope covers this tool + action
|  3. Destructive check?    |  <- delete/destroy needs explicit scope
|  4. Values floor?         |  <- Optional compliance check
|                           |
|  All gates pass? -------->|---- Composio executes tool
|  Any gate fails? -------->|---- Tool blocked, denial receipt emitted
+---------------------------+
       |
       v
  Signed ActionReceipt
  (links tool call -> delegation -> human principal)
```

## Works With

Any tool object that has `name`, `description`, and `execute()`. No Composio dependency required. Compatible with:

- **Composio** (`composio.getTools()`)
- **LangChain tools** (same interface)
- **Any custom tool registry**

## Quick Start

```bash
npm install agent-passport-system
```

```typescript
import { governComposioAction } from './composio-governance-adapter'
import { createPassport, createDelegation, generateKeyPair } from 'agent-passport-system'

const governed = governComposioAction({
  passport: agentPassport,
  delegation: createDelegation(
    principalKeys.publicKey,
    agentKeys.publicKey,
    ['salesforce:read', 'salesforce:update', 'slack:post'],
    principalKeys.privateKey,
  ),
  privateKey: agentKeys.privateKey,
  action: composioTool,  // any { name, description, execute() }
})

const result = await governed.execute({ accountId: 'acc_001' })
// result.receipt links this tool call to the delegation chain
```

## Batch Governance

```typescript
import { governComposioToolkit } from './composio-governance-adapter'

// Wrap all tools at once
const governed = governComposioToolkit({
  passport: agentPassport,
  delegation,
  privateKey: agentKeys.privateKey,
  tools: composio.getTools(),  // or any array of { name, description, execute() }
})

// Every tool call now goes through APS governance
for (const tool of governed) {
  console.log(`${tool.name}: ${tool.description}`)
}
```

## Destructive Action Protection

Tools with names containing `delete`, `destroy`, `drop`, `remove`, `purge`, `wipe`, or `truncate` are flagged as destructive. Even if the delegation scope technically covers the tool's category, destructive actions require explicit `delete`, `destroy`, or `admin` scope.

```typescript
// Delegation with read/update scope
const delegation = createDelegation(principal, agent,
  ['salesforce:read', 'salesforce:update'], privateKey)

// SALESFORCE_READ_ACCOUNT -> permitted (salesforce:read)
// SALESFORCE_DELETE_RECORD -> BLOCKED (destructive, no delete scope)
```

## Recovery Policy Integration

When a tool call fails, APS consults the agent's `RecoveryPolicy` for the appropriate strategy:

```typescript
import { createDefaultRecoveryPolicy } from 'agent-passport-system'

const governed = governComposioAction({
  passport, delegation, privateKey,
  action: composioTool,
  recoveryPolicy: createDefaultRecoveryPolicy(),
  onDenied: (event) => {
    // event.reason includes the recovery strategy suggestion
    console.log(`Recovery: ${event.reason}`)
  },
})
```

## Run the Demo

```bash
npx tsx examples/composio-governance/demo.ts
```

Shows five scenarios: Salesforce read (permitted), Salesforce delete (blocked), Slack post (permitted), GitHub create PR (permitted), GitHub delete repo (blocked).

## Architecture

Composio owns **authentication and connectivity**. APS owns **authorization and audit**.

| Concern | Who Handles It |
|---------|---------------|
| Agent identity | APS (Ed25519 passport) |
| Tool authorization | APS (delegation scope) |
| Destructive action gating | APS (verb analysis) |
| Values compliance | APS (values floor) |
| Audit trail | APS (signed receipts) |
| Tool connectivity | Composio (250+ integrations) |
| OAuth management | Composio (managed auth) |
| API rate limiting | Composio (built-in) |

See also: [Stripe Governance Adapter](../stripe-governance/) for the payment-side equivalent.

## License

Apache-2.0. Part of the [Agent Passport System](https://github.com/aeoess/agent-passport-system).
