# BUILD-MCP-ADAPTER — Generic governance wrapper for any MCP tool call

## Context

MCP (Model Context Protocol) is the standard for tool integration. This adapter
wraps any MCP tool call with APS enforcement. Works with any MCP server, any client.

## Deliverables

### 1. `src/adapters/mcp.ts` (~110 lines)

```typescript
interface MCPToolCall {
  name: string
  arguments: Record<string, unknown>
  server?: string       // MCP server name for scope namespacing
}

interface MCPGovernanceConfig {
  passport: SignedPassport
  delegation: Delegation
  privateKey: string
  scopePrefix?: string  // e.g. "mcp:" → "mcp:toolName"
  destructiveTools?: string[]  // tools requiring admin scope
  onReceipt?: (r: ActionReceipt) => void
  onDenied?: (info: { tool: string; reason: string }) => void
}

// Govern a single MCP tool call
export function governMCPToolCall(
  call: MCPToolCall,
  execute: (args: Record<string, unknown>) => Promise<unknown>,
  config: MCPGovernanceConfig
): Promise<{ result: unknown; receipt: ActionReceipt } | { denied: true; reason: string; receipt: ActionReceipt }>

// Create a governance interceptor for an MCP client
export function createMCPGovernanceInterceptor(
  config: MCPGovernanceConfig
): (call: MCPToolCall, execute: (...) => Promise<unknown>) => Promise<...>

// Derive APS scope from MCP tool call
export function mcpToolToScope(
  call: MCPToolCall,
  config: Pick<MCPGovernanceConfig, 'scopePrefix' | 'destructiveTools'>
): string
```

Key logic:
- Default scope: `mcp:{server}:{toolName}` or `tools:{toolName}` if no server
- Destructive tools (delete, drop, remove patterns) require `admin:` prefix
- Custom destructiveTools list for explicit marking
- scopePrefix for namespacing
- Interceptor pattern: drop-in for MCP client middleware

### 2. Export from `src/index.ts`

### 3. Tests: `tests/mcp-adapter.test.ts` (~14 tests)

- tool call authorized → receipt
- tool call denied → denial receipt
- server-namespaced scope derivation
- no-server scope derivation
- destructive tool detection (delete, drop, remove)
- custom destructive tools list
- custom scope prefix
- interceptor creation and use
- receipt signature verification
- expired delegation denial
- batch tool calls via interceptor
- special characters in tool names
- empty arguments handling

## Build Rules
- No MCP SDK dependency (generic types only)
- Same receipt builder pattern
- `npm run build && npm test` must pass
- Report test count delta
