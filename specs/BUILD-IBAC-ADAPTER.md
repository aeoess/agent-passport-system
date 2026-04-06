# BUILD-IBAC-ADAPTER — Intent-Based Access Control Bridge

## Context

Ken Huang (CSA MAESTRO, OWASP AIVSS, ITU ANS) published an IBAC architecture:
Intent parser → Policy mapper → Authorization engine (Cedar/OPA) → Tool gateway.

APS already implements this with cryptographic proof. This adapter bridges
Ken's IBAC tuple format into APS delegations, making APS the enforcement
layer IBAC is missing.

## Deliverables

### 1. `src/adapters/ibac.ts` — Core adapter (~150 lines)

Types:
```typescript
interface IBACIntent {
  task: string                    // e.g. "incident_report", "clinical_note_review"
  subject: { id: string; role?: string }
  actions: IBACAction[]
  constraints?: Record<string, unknown>
  timestamp: string
}

interface IBACAction {
  verb: string                    // "read" | "write" | "query" | "send" | "delete"
  resource: string                // "table:patients" | "channel:slack" | "file:report.pdf"
  constraints?: Record<string, unknown>  // { max_rows: 100, sensitivity: "phi" }
}

interface IBACTuple {
  principal: string               // "agent:agent-123"
  action: string                  // "tool:query_db"
  resource: string                // "table:patients"
  constraints?: Record<string, unknown>
}

interface IBACEvaluationResult {
  intent: IBACIntent
  delegation: Delegation
  tupleResults: Array<{
    tuple: IBACTuple
    authorized: boolean
    scope: string
    reason: string
  }>
  receipt: ActionReceipt
}
```

Functions:
```typescript
// Convert IBAC intent to APS delegation scope
export function ibacIntentToScope(intent: IBACIntent): string[]
// e.g. { task: "incident_report", actions: [{ verb: "read", resource: "table:logs" }] }
// → ["data:read:table:logs", "data:read:table:events"]

// Convert IBAC tuples to APS delegation
export function ibacTuplesToDelegation(
  tuples: IBACTuple[],
  principalKey: string,
  agentKey: string,
  privateKey: string,
  opts?: { expiresInHours?: number; spendLimit?: number }
): Delegation

// Evaluate IBAC tuples against existing APS delegation
export function evaluateIBACTuples(
  tuples: IBACTuple[],
  delegation: Delegation
): IBACEvaluationResult

// Full pipeline: intent → delegation → evaluate → receipt
export function governIBACIntent(
  intent: IBACIntent,
  config: {
    passport: SignedPassport
    delegation: Delegation
    privateKey: string
    onReceipt?: (r: ActionReceipt) => void
  }
): IBACEvaluationResult
```

Key logic:
- `ibacIntentToScope` maps IBAC verb+resource to APS scope strings
  - `read` + `table:patients` → `data:read:table:patients`
  - `write` + `file:report.pdf` → `data:write:file:report.pdf`
  - `send` + `channel:slack` → `comms:send:channel:slack`
  - `delete` + anything → `admin:delete:*` (requires explicit scope)
- `ibacTuplesToDelegation` creates a scoped delegation from tuples
  - Constraints map to delegation metadata (max_rows → spendLimit analog)
  - Time-bound constraints map to expiresAt
- `evaluateIBACTuples` checks each tuple against delegation via scopeAuthorizes()
  - Returns per-tuple authorized/denied with reason
- `governIBACIntent` is the full pipeline with receipt generation

### 2. `src/adapters/ibac-cedar.ts` — Cedar policy format bridge (~80 lines)

```typescript
// Parse Cedar-style policy string into IBACTuples
export function cedarPolicyToTuples(cedarPolicy: string): IBACTuple[]

// Generate Cedar-style policy from APS delegation
export function delegationToCedarPolicy(delegation: Delegation): string
```

This lets Cedar/OPA users see APS delegations as native policies and vice versa.

### 3. Export from `src/index.ts`

Add all IBAC adapter exports.

### 4. Tests: `tests/ibac-adapter.test.ts` (~20 tests)

- intent → scope mapping (read, write, send, delete, query)
- tuples → delegation round-trip
- evaluate authorized tuple
- evaluate denied tuple (scope violation)
- evaluate denied tuple (expired delegation)
- constraint mapping (max_rows, sensitivity, time_bound)
- delete requires explicit admin scope
- full pipeline with receipt
- Cedar policy → tuples → delegation round-trip
- delegation → Cedar policy generation
- mixed authorized/denied in single intent
- empty intent produces empty scope
- malformed tuple handling

### 5. Update SDK README

Add IBAC section under adapters:
```markdown
### IBAC (Intent-Based Access Control)

Bridge Ken Huang's IBAC framework into APS enforcement:

\`\`\`typescript
import { governIBACIntent } from 'agent-passport-system'

const result = governIBACIntent({
  task: 'clinical_note_review',
  subject: { id: 'agent-nurse-001' },
  actions: [
    { verb: 'read', resource: 'table:patients', constraints: { sensitivity: 'phi' } },
    { verb: 'write', resource: 'file:clinical_notes' }
  ],
  timestamp: new Date().toISOString()
}, { passport, delegation, privateKey })

// result.tupleResults[0].authorized === true (if delegation covers data:read:table:patients)
// result.receipt — signed Ed25519 proof of the evaluation
\`\`\`

IBAC defines the intent. APS proves it was enforced.
```

## Build Rules

- All types in `src/adapters/ibac.ts`, no separate types file
- Use `scopeAuthorizes()` from existing SDK for authorization checks
- Use `sign()` + `canonicalize()` for receipts (same pattern as composio adapter)
- Cedar bridge is string parsing, no external deps
- Copyright header on all files
- Run `npm run build && npm test` after completion
- Report test count delta

## References

- Ken Huang IBAC article: Intent-Based Access Control technical primer
- Ken Huang OWASP AIVSS: aivss.owasp.org
- Ken Huang CSA MAESTRO: our thread at CloudSecurityAlliance/taise-agent-v01 #2
- OWASP Agentic Top 10: our thread at OWASP #802
- APS composio adapter: `packages/composio-governance/` (pattern reference)
