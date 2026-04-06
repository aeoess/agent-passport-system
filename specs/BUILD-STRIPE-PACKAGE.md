# Build Spec: Promote Stripe Adapter to Standalone npm Package

## Context
The Stripe governance adapter lives at `examples/stripe-governance/`. Enterprise users and Stripe's team need `npm install @aeoess/stripe-governance` — not "clone repo and import from examples."

## What
Create a standalone npm package at `packages/stripe-governance/` within the monorepo. Publishable as `@aeoess/stripe-governance`.

## Where
- `packages/stripe-governance/` (new directory)
- Keep `examples/stripe-governance/` as-is (demo stays, package is the real thing)

## Structure

```
packages/stripe-governance/
  package.json
  tsconfig.json
  src/
    index.ts           — re-exports everything
    adapter.ts         — governStripeTools, governMPPPayment (from examples, cleaned up)
    budget.ts          — getAgentBudgetStatus
    types.ts           — GovernedStripeConfig, PreflightDecision
  tests/
    adapter.test.ts
  README.md            — copy from examples/stripe-governance/README.md, update install instructions
```

## package.json

```json
{
  "name": "@aeoess/stripe-governance",
  "version": "0.1.0",
  "description": "APS governance layer for Stripe agent payments — commerce delegation, spend limits, merchant allowlists, audit trail",
  "main": "dist/index.js",
  "types": "dist/index.d.ts",
  "license": "Apache-2.0",
  "peerDependencies": {
    "agent-passport-system": ">=1.34.0"
  },
  "keywords": ["stripe", "agent", "governance", "payments", "x402", "mpp", "spt", "ai-agent"],
  "repository": {
    "type": "git",
    "url": "https://github.com/aeoess/agent-passport-system",
    "directory": "packages/stripe-governance"
  }
}
```

## Key changes from example to package
1. All imports use `agent-passport-system` as a peer dependency (not relative paths)
2. Proper TypeScript compilation with own `tsconfig.json`
3. Exported types for consumers
4. The `requestHumanApproval` call uses correct SDK API (merchantName, items, totalAmount)
5. Clean up the `any` types — use proper Stripe Agent Toolkit types where possible, or generic tool interface

## Exports

```typescript
// Main adapter
export { governStripeTools, governMPPPayment } from './adapter'
export { getAgentBudgetStatus } from './budget'

// Types
export type { GovernedStripeConfig, PreflightDecision } from './types'
```

## Tests
- Copy and adapt from `examples/stripe-governance/` patterns
- All 4 scenarios: auto-approve, human approval, merchant block, budget block
- Verify peer dependency resolution works
- `npm run build && npm test` in package directory

## After building
- `npm run build` in package directory
- Run tests
- DON'T publish yet — Tima does Touch ID
- Update examples/stripe-governance/README.md to say "For production use: `npm install @aeoess/stripe-governance`"
- Commit with descriptive message
