# CC Build Spec: Commerce Idempotency Key

## Context

Two independent threads (A2A Discussion #1404 — msaleme on retry storms, and a2a-x402 #60 — mkmkkkkk on duplicate payments) surfaced the same gap: when an agent retries a failed commerce operation, there's no dedup mechanism. The existing `computeActionRef()` includes `createdAt` in the hash, so identical requests at different times produce different refs — useless for retry dedup.

## What to Build

### 1. SDK: `computeIdempotencyKey()` in `src/core/idempotency.ts`

A content-addressed hash for commerce dedup that deliberately EXCLUDES timestamp.

```typescript
export function computeIdempotencyKey(params: {
  agentId: string
  scope: string
  target: string
  amount?: { amount: number, currency: string }
}): string
```

Hash: `SHA-256(canonicalJson({ agentId, scope, target, amount }))` — same computation as `computeActionRef()` but without `createdAt`.

Two identical purchase attempts (same agent, same scope, same target, same amount) produce the same idempotency key regardless of when they happen.

### 2. SDK: `IdempotencyCheck` type in `src/types/commerce.ts`

```typescript
export interface IdempotencyCheck {
  idempotencyKey: string        // from computeIdempotencyKey()
  windowSeconds: number         // configurable dedup window (default: 300)
  action: 'reject' | 'return_existing'  // reject duplicate or return previous receipt
}
```

### 3. SDK: Add `idempotencyKey` field to `CommerceActionReceipt`

The receipt should carry the idempotency key so the gateway can look it up.

### 4. SDK: Integrate into `commercePreflight()`

Add optional 5th gate to the existing 4-gate pipeline:

```
Gate 1: passport valid
Gate 2: scope includes commerce:checkout
Gate 3: cumulative spend within limit
Gate 4: merchant on allowlist
Gate 5 (new): idempotency check — has this exact operation been completed within the window?
```

`commercePreflight()` should accept an optional `idempotencyKey` parameter. If provided, it returns `{ approved: false, reason: 'duplicate_within_window', existingReceiptId: '...' }` when a match is found.

Note: Gate 5 requires a receipt store to check against. In the SDK (stateless), this is a passed-in lookup function. In the gateway (stateful), this hits the SQLite receipt table.

### 5. SDK: `IdempotencyStore` interface

```typescript
export interface IdempotencyStore {
  check(key: string, windowSeconds: number): Promise<{ duplicate: boolean, existingReceiptId?: string }>
  record(key: string, receiptId: string): Promise<void>
}
```

The SDK defines the interface. The gateway implements it. This keeps the SDK stateless.

## What NOT to Build

- Do NOT add idempotency to non-commerce operations. Evaluating the same delegation twice is harmless. This is commerce-only.
- Do NOT modify `computeActionRef()`. It correctly includes timestamp for receipt identity. Idempotency key is a separate computation for a separate purpose.
- Do NOT add any gateway code. This spec is SDK-only. Gateway integration is a separate task.
- Do NOT bump version or publish. Tima reviews the diff first.

## Pre-Build Checks

Before writing any code:
1. Read `src/core/action-ref.ts` — understand existing `computeActionRef()` to avoid duplication
2. Read `src/types/commerce.ts` — understand existing commerce types
3. Read `src/core/commerce.ts` — understand existing `commercePreflight()` pipeline
4. Read `src/core/canonical.ts` — use existing `canonicalJson()` for deterministic hashing
5. Run `npm test` — record baseline test count

## Tests Required

In `tests/idempotency.test.ts`:

1. Same inputs produce same idempotency key
2. Different amounts produce different keys
3. Different agents produce different keys
4. Same inputs at different times produce SAME key (this is the whole point — contrast with action_ref)
5. `commercePreflight()` with idempotency store returns duplicate when match found
6. `commercePreflight()` without idempotency key works exactly as before (backward compat)
7. Window expiry: key recorded, window passes, same key is allowed again

In existing commerce tests: verify no regressions. All existing 17 commerce tests must pass unchanged.

## Verification

After building:
1. `npm test` — all tests pass, new test count = baseline + new tests
2. `npm run build` — clean TypeScript compilation
3. `git diff --stat` — review files changed
4. DO NOT commit, push, or publish
