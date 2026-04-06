# @aeoess/composio-governance

**Delegation-scoped authorization for 250+ tool integrations.**

Composio handles authentication and connectivity. APS handles who authorized which tool, within what scope, and produces the audit trail. Neither replaces the other.

Works with **Composio**, **MCP**, **LangChain**, or any tool with `{ name, description, execute() }`.

## Install

```bash
npm install @aeoess/composio-governance agent-passport-system
```

## Quick Start

```typescript
import { governComposioAction } from '@aeoess/composio-governance'
import { createPassport, createDelegation, generateKeyPair } from 'agent-passport-system'

const governed = governComposioAction({
  passport: agentPassport,
  delegation: createDelegation({
    delegatedTo: agentKeys.publicKey,
    delegatedBy: principalKeys.publicKey,
    scope: ['salesforce:read', 'salesforce:update', 'slack:post'],
    privateKey: principalKeys.privateKey,
  }),
  privateKey: agentKeys.privateKey,
  action: composioTool,  // any { name, description, execute() }
})

const result = await governed.execute({ accountId: 'acc_001' })
// result.receipt links this tool call to the delegation chain
```

## Batch Governance

```typescript
import { governComposioToolkit } from '@aeoess/composio-governance'

const governed = governComposioToolkit({
  passport, delegation, privateKey,
  tools: composio.getTools(),  // or any tool array
})
```

## Destructive Action Protection

Tools with names containing `delete`, `destroy`, `drop`, `remove`, `purge`, `wipe`, or `truncate` require explicit `delete`, `destroy`, or `admin` scope in the delegation.

## Recovery Policy

```typescript
import { createDefaultRecoveryPolicy } from 'agent-passport-system'

const governed = governComposioAction({
  passport, delegation, privateKey,
  action: composioTool,
  recoveryPolicy: createDefaultRecoveryPolicy(),
  onDenied: (event) => console.log(event.reason),
})
```

## Architecture

| Concern | Who Handles It |
|---------|---------------|
| Agent identity | APS (Ed25519 passport) |
| Tool authorization | APS (delegation scope) |
| Destructive action gating | APS (verb analysis) |
| Audit trail | APS (signed receipts) |
| Tool connectivity | Composio (250+ integrations) |
| OAuth management | Composio (managed auth) |

See also: [@aeoess/stripe-governance](../stripe-governance/) for payment governance.

## License

Apache-2.0. Part of [Agent Passport System](https://github.com/aeoess/agent-passport-system).
