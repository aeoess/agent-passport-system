# Build Spec: Composio Governance Adapter

## Context
Composio (ComposioHQ/composio) is the leading tool integration layer for agents. 250+ tools, managed auth, SOC 2. They handle authentication. We handle authorization. Issue opened: ComposioHQ/composio#3123.

## What
An example adapter showing APS governance wrapping Composio tool execution. Same pattern as the Stripe adapter but for tool calls instead of payments.

## Where
- `examples/composio-governance/composio-governance-adapter.ts`
- `examples/composio-governance/demo.ts`
- `examples/composio-governance/README.md`

## How it works

Composio authenticates the tool connection (OAuth, tokens). Before the tool executes, APS evaluates:
1. Passport valid (agent identity)
2. Delegation scope covers this tool and action type
3. Action count / rate within limits
4. Tool on allowed list for this delegation

## Core function

```typescript
/**
 * Wrap a Composio tool action with APS governance.
 * Returns governed version that checks delegation before execution.
 */
function governComposioAction(opts: {
  passport: SignedPassport
  delegation: Delegation          // standard APS delegation, not commerce-specific
  action: ComposioAction          // the Composio tool action
  valuesFloor?: ValuesFloor
  onDenied?: (event: DenialEvent) => void
  onReceipt?: (receipt: ActionReceipt) => void
}): GovernedAction

interface GovernedAction {
  execute: (params: Record<string, unknown>) => Promise<{
    result: unknown
    receipt: ActionReceipt
  } | {
    denied: true
    reason: string
    denialReceipt: ActionReceipt
  }>
}
```

## Batch governance for multiple tools

```typescript
/**
 * Wrap all Composio tools for an agent with APS governance.
 */
function governComposioToolkit(opts: {
  passport: SignedPassport
  delegation: Delegation
  tools: ComposioAction[]         // from composio.getTools()
  valuesFloor?: ValuesFloor
}): GovernedAction[]
```

## Demo scenarios (demo.ts)

1. **Salesforce read** — agent reads account (scope: `crm:read`) → permitted
2. **Salesforce delete** — agent tries to delete record (scope: `crm:delete`) → blocked, scope not in delegation
3. **Slack post to private channel** — permitted
4. **Slack post to public channel** — requires human approval (configured threshold)
5. **GitHub create PR** — permitted
6. **GitHub delete repo** — blocked, destructive action outside delegation

## README positioning

Same framing as Stripe adapter:
- Composio owns authentication. APS owns authorization.
- Table showing concern split (connectivity, OAuth = Composio; identity, delegation, audit = APS)
- Link to Stripe adapter as the payment-side equivalent
- "Your agent uses Composio for Salesforce access. APS ensures it only reads the accounts it's delegated to."

## Notes
- Don't import Composio as a dependency. The adapter should work with any tool object that has `name`, `description`, and `execute()`. Composio-agnostic interface.
- Use standard APS `Delegation` type, not `CommerceDelegation`. This is tool governance, not payment governance.
- Every governed action produces a signed `ActionReceipt` regardless of permit/deny.
- Recovery policy integration: if a tool call fails, check the agent's `RecoveryPolicy` for the appropriate strategy.

## Tests
- Permitted action produces receipt with correct scope
- Denied action produces denial receipt with reason
- Batch governance wraps all tools
- Destructive actions (delete, drop, destroy) flagged even if scope technically allows
- Recovery policy consulted on tool_error failure type
