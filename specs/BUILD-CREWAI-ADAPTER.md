# BUILD-CREWAI-ADAPTER — Governance wrapper for CrewAI task execution

## Context

CrewAI orchestrates multi-agent crews. Each crew member should have a passport
and scoped delegation. This adapter wraps crew task execution with APS verification.

## Deliverables

### 1. `src/adapters/crewai.ts` (~130 lines)

```typescript
interface CrewTask {
  description: string
  agent: string         // crew member name/id
  tools?: string[]      // tool names this task may use
  expected_output?: string
}

interface CrewGovernanceConfig {
  passport: SignedPassport
  delegation: Delegation
  privateKey: string
  onReceipt?: (r: ActionReceipt) => void
  onDenied?: (info: { task: string; agent: string; reason: string }) => void
}

interface GovernedTaskResult {
  output: unknown
  receipt: ActionReceipt
  toolReceipts: ActionReceipt[]  // one per tool used during task
}

// Verify crew member has authority for task
export function verifyCrewMember(
  agentName: string,
  task: CrewTask,
  config: CrewGovernanceConfig
): { authorized: boolean; reason: string; scope: string }

// Wrap task execution with governance
export function governCrewTask(
  task: CrewTask,
  execute: (task: CrewTask) => Promise<unknown>,
  config: CrewGovernanceConfig
): Promise<GovernedTaskResult | { denied: true; reason: string; receipt: ActionReceipt }>

// Generate scopes needed for a CrewTask
export function crewTaskToScopes(task: CrewTask): string[]
```

Key logic:
- Task description → scope: `crew:execute:{agentName}`
- Task tools → additional scopes: `tools:{toolName}` per tool
- `verifyCrewMember` checks passport + delegation covers all required scopes
- `governCrewTask` runs verification, executes if authorized, produces receipt
- Tool-level receipts collected during execution

### 2. Export from `src/index.ts`

### 3. Tests: `tests/crewai-adapter.test.ts` (~14 tests)

- crew member authorized for task
- crew member denied (scope mismatch)
- crew member denied (expired delegation)
- task with tools → scope includes tool scopes
- task without tools → scope is crew:execute only
- governed task execution with receipt
- governed task denial with receipt
- tool receipts collected
- receipt chain integrity
- multiple crew members different scopes
- empty task description handling
- onDenied callback fires
- signature verification on receipts

## Build Rules
- No CrewAI dependency
- Same receipt pattern as composio/langchain adapters
- `npm run build && npm test` must pass
- Report test count delta
