# Build Spec: Promote Composio Adapter to Standalone npm Package

## Context
Same pattern as Stripe. The Composio governance adapter lives at `examples/composio-governance/`. Enterprise users and Composio's team need `npm install @aeoess/composio-governance`.

## What
Create a standalone npm package at `packages/composio-governance/`. Publishable as `@aeoess/composio-governance`.

## Where
- `packages/composio-governance/` (new directory)
- Keep `examples/composio-governance/` as demo

## Structure

```
packages/composio-governance/
  package.json
  tsconfig.json
  src/
    index.ts           — re-exports everything
    adapter.ts         — governComposioAction, governComposioToolkit
    types.ts           — ComposioAction, GovernedAction, ToolGovernanceConfig, DenialEvent
  tests/
    adapter.test.ts
  README.md
```

## package.json

```json
{
  "name": "@aeoess/composio-governance",
  "version": "0.1.0",
  "description": "APS governance layer for Composio tool execution — delegation-scoped authorization for 250+ integrations",
  "main": "dist/index.js",
  "types": "dist/index.d.ts",
  "license": "Apache-2.0",
  "peerDependencies": {
    "agent-passport-system": ">=1.34.0"
  },
  "keywords": ["composio", "agent", "governance", "tools", "authorization", "ai-agent", "mcp"],
  "repository": {
    "type": "git",
    "url": "https://github.com/aeoess/agent-passport-system",
    "directory": "packages/composio-governance"
  }
}
```

## Key design: framework-agnostic tool interface

The adapter does NOT depend on Composio. It works with any tool that has:

```typescript
interface ComposioAction {
  name: string
  description: string
  execute: (params: Record<string, unknown>) => Promise<unknown>
}
```

This means it works with Composio, raw MCP tools, LangChain tools, or any custom tool wrapper. The README should emphasize this: "Works with Composio, MCP, LangChain, or any tool with name + description + execute."

## Exports

```typescript
export { governComposioAction, governComposioToolkit } from './adapter'
export type { ComposioAction, GovernedAction, ToolGovernanceConfig, DenialEvent } from './types'
```

## Changes from example to package
1. All imports use `agent-passport-system` as peer dependency
2. Proper TypeScript compilation
3. The `emitDenial` function builds denial receipts directly (bypassing createReceipt scope validation) — keep this pattern from the example
4. Recovery policy integration: on `tool_error`, consult `evaluateRecovery()` if policy configured
5. Clean up `any` types

## Tests
- Copy and adapt from `tests/composio-adapter.test.ts`
- 7 scenarios: permit, deny scope, batch, destructive block, admin permit, recovery
- `npm run build && npm test` in package directory

## After building
- Build and test in package directory
- DON'T publish — Tima does Touch ID
- Update examples/composio-governance/README.md to reference the package
- Commit
