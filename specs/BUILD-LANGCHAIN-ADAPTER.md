# BUILD-LANGCHAIN-ADAPTER — Governance wrapper for LangChain/LangGraph tools

## Context

LangChain is the largest agent framework. Wrapping BaseTool.invoke() with APS
delegation checks gives every LangChain developer instant governance.

## Deliverables

### 1. `src/adapters/langchain.ts` (~120 lines)

```typescript
interface LangChainToolCall {
  name: string
  args: Record<string, unknown>
  id?: string
}

interface GovernedToolResult {
  output: unknown
  receipt: ActionReceipt
}

interface DeniedToolResult {
  denied: true
  reason: string
  receipt: ActionReceipt
}

interface LangChainGovernanceConfig {
  passport: SignedPassport
  delegation: Delegation
  privateKey: string
  scopeMapping?: Record<string, string>  // tool name → APS scope override
  onReceipt?: (r: ActionReceipt) => void
  onDenied?: (info: { tool: string; reason: string }) => void
}

// Wrap a single LangChain tool call
export function governLangChainTool(
  call: LangChainToolCall,
  execute: (args: Record<string, unknown>) => Promise<unknown>,
  config: LangChainGovernanceConfig
): Promise<GovernedToolResult | DeniedToolResult>

// Create a governance middleware for LangGraph
export function createLangGraphGovernance(
  config: LangChainGovernanceConfig
): (call: LangChainToolCall, execute: (...) => Promise<unknown>) => Promise<...>

// Map LangChain tool name to APS scope
export function langchainToolToScope(
  toolName: string,
  scopeMapping?: Record<string, string>
): string
```

Key logic:
- Default scope mapping: tool name → `tools:{toolName}` 
- scopeMapping override lets users map `"search_google"` → `"web:search"` etc.
- Uses `scopeAuthorizes()` for checks
- Builds receipts with `sign()` + `canonicalize()` (same pattern as composio)
- `createLangGraphGovernance` returns a curried function for LangGraph node wrapping

### 2. Export from `src/index.ts`

### 3. Tests: `tests/langchain-adapter.test.ts` (~15 tests)

- tool call authorized → receipt
- tool call denied (scope) → denial receipt
- tool call denied (expired delegation)
- custom scope mapping
- default scope derivation
- batch tool calls (multiple sequential)
- LangGraph middleware creation
- receipt signature verification
- onDenied callback fires
- onReceipt callback fires
- empty args handling
- tool name with special chars

## Build Rules
- Same receipt pattern as composio adapter
- No LangChain dependency (framework-agnostic types)
- `npm run build && npm test` must pass
- Report test count delta
