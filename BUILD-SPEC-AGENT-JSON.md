# Build Spec: agent.json Commerce Integration + DID Conformance + Finding Layer Tags

## Context
This spec comes from a massive outreach session (March 23-24, 2026). Three builds emerged from WG discussions on corpollc/qntm#5 and aeoess/agent-passport-system#3.

Current state: SDK v1.21.4, 1183 tests, 321 suites, 63 files.

---

## Build 1: agent.json + APS Commerce Bridge (HIGHEST PRIORITY)

**Why:** FransDevelopment posted agent.json as the capability discovery + economics layer on qntm#5 and directly tagged @aeoess. We described the composition in words. A working reference integration proves it. This is the economics layer the WG needs.

**agent.json spec:** https://github.com/FransDevelopment/agent-json/blob/main/SPECIFICATION.md
**Schema:** https://github.com/FransDevelopment/agent-json/blob/main/schema.json
**Examples:** https://github.com/FransDevelopment/agent-json/tree/main/examples

**What to build:**

File: `src/interop/agent-json-bridge.ts`
Tests: `tests/agent-json-bridge.test.ts`

### Interface

```typescript
interface AgentJsonManifest {
  name: string
  description: string
  intents: AgentJsonIntent[]
  pricing?: AgentJsonPricing
  payment?: AgentJsonPayment
  identity?: { did: string; publicKey: string }
}

interface AgentJsonIntent {
  name: string
  description: string
  endpoint: string
  parameters: Record<string, any>
  returns: Record<string, any>
}

interface AgentJsonPricing {
  model: 'per_call' | 'per_unit' | 'free'
  amount?: number
  currency?: string
  unit?: string
}

interface AgentJsonPayment {
  methods: ('x402' | 'lightning' | 'stripe')[]
  address?: string
}
```

### Functions

1. `parseAgentJson(manifest: string | object): AgentJsonManifest`
   - Parse and validate an agent.json manifest
   - Handle both string (fetched from URL) and object input

2. `commercePreflightFromManifest(manifest: AgentJsonManifest, intent: string, delegation: DelegationChain): CommercePreflightResult`
   - Extract intent + price from manifest
   - Run APS 4-gate commerce preflight against delegation:
     - Scope check: is the intent's scope in delegation?
     - Spend limit: is price within remaining budget?
     - Merchant whitelist: is the service in allowed merchants?
     - Human approval threshold: does price exceed threshold?
   - Return preflight result (pass/fail with reasons)

3. `generateCommerceReceiptFromIntent(manifest: AgentJsonManifest, intent: string, delegation: DelegationChain, keys: KeyPair): SignedCommerceReceipt`
   - After successful preflight + execution
   - Generate signed commerce receipt linking:
     - Intent called (from manifest)
     - Amount paid (from manifest pricing)
     - Delegation chain (who authorized)
     - Beneficiary (principal from delegation)
     - Service DID (from manifest identity)

### Test cases (minimum)

1. Parse valid agent.json manifest (Tier 1, 2, 3)
2. Commerce preflight — passes when delegation covers scope + budget
3. Commerce preflight — fails when scope not in delegation
4. Commerce preflight — fails when price exceeds remaining spend limit
5. Commerce preflight — fails when merchant not in whitelist
6. Commerce preflight — requires human approval when price > threshold
7. Generate commerce receipt with full attribution chain
8. Receipt traces back to principal (beneficiary)
9. Receipt includes service DID from manifest
10. End-to-end: parse manifest → preflight → receipt generation

---

## Build 2: DID Resolution v1.0 Conformance Vectors

**Why:** vessenes circulated DID Resolution v1.0 spec on qntm#5 with 8 test vectors. We need to verify our resolver passes before ratifying.

**Spec:** corpollc/qntm/specs/working-group/did-resolution.md
**Vectors:** corpollc/qntm/test-vectors/did-resolution.json (if published) or derive from spec §6

File: `tests/did-resolution-conformance.test.ts`

### What to test

1. `did:aps` creation — hex input → multibase output with 0xed01 prefix
2. `did:aps` resolution — resolve to DID Document with correct verificationMethod
3. `did:key` resolution — resolve Ed25519 did:key to public key
4. `did:web` resolution — mock HTTP resolution
5. Sender ID derivation — SHA-256(pubkey)[0:16] matches spec §4
6. Round-trip: createDID → publicKeyFromDID → verify key matches
7. Legacy hex format backward compatibility
8. Cross-method verification: same key produces valid DID in both did:aps and did:key

### Important detail from our qntm#5 reply
Our `did:aps` uses multicodec-prefixed multibase (0xed01 + base58btc + z-prefix). Verify this matches the spec vectors. If spec intends raw multibase, flag the discrepancy.

---

## Build 3: PolicyDecision Finding Layer Tags

**Why:** xsa520's March 19 discussion on issue #3 resulted in agreement: findings should declare whether they're structural (must converge across engines) or trust-informed (may diverge).

File: Modify `src/core/intent.ts` or `src/core/policy.ts`
Tests: Add to existing policy tests

### Changes

1. Add to finding type:
```typescript
interface PolicyFinding {
  check: string
  result: 'pass' | 'fail' | 'warn'
  reason?: string
  layer?: 'structural' | 'trust'  // NEW
}
```

2. Tag existing findings:
   - `scope_membership` → structural
   - `chain_validity` → structural  
   - `spend_limit` → structural
   - `floor_compliance` → structural
   - `reputation_threshold` → trust
   - `behavioral_signal` → trust
   - Any engine-specific check → trust

3. Tests:
   - Verify structural findings always present on permit/deny
   - Verify structural findings are deterministic (same input → same tags)
   - Verify trust findings carry engine identifier

---

## Build Order

1. **agent.json bridge** — highest impact, proves economics layer to WG
2. **DID conformance** — needed for ratification sign-off
3. **Finding layer tags** — small change, high protocol value

## After Build

- Post on qntm#5: "Reference integration is live. Here's how agent.json + APS commerce compose with running code."
- Post on issue #3: "Finding layer tags shipped per the March 19 discussion."
- Run propagation: test count will increase

## Current file locations for reference
- Commerce module: `src/core/commerce.ts`
- DID module: `src/core/did.ts`
- Policy/Intent: `src/core/intent.ts`, `src/core/policy.ts`
- Types: `src/types/`
- Existing bridge examples: `src/interop/qntm-bridge.ts`, `src/interop/a2a-bridge.ts`
