# `governance_attestation` Signal Schema

**Status:** Draft v0.1
**Context:** 5th signal type in A2A#1628 (douglasborthwick-crypto). Extends the 2-signature minimum to a 3-signature audit chain. Wraps `active_constraints` as a signed, JWKS-verifiable claim.

**Cross-references:**
- aeoess/agent-passport-system#11 (commit)
- a2aproject/A2A#1628 (extension review)
- douglasborthwick-crypto/insumer-examples#1 (reference implementation)

---

## 1. Schema Contract

A `governance_attestation` is a signed claim, emitted by a gateway, asserting the governance constraints and delegation state in effect for an agent at a point in time. It is content-addressable via the agent's delegation chain hash and independently verifiable via the gateway's published JWKS.

### 1.1 Signal type identifier

```
signal_type: "governance_attestation"
```

### 1.2 Required fields

| Field | Type | Description |
|---|---|---|
| `signal_type` | `string` | Must be `"governance_attestation"`. Required per §1.6 JSON Schema. |
| `active_constraints` | `object` | The enforceable constraint set at attestation time. See §1.4. |
| `delegation_chain_hash` | `string` | SHA-256 hex digest of the canonicalized delegation chain (root → current). Stable request identity. |
| `evaluation_timestamp` | `string` | RFC 3339 / ISO 8601 UTC timestamp, second-precision, at which constraints were evaluated. |
| `iss` | `string` | Issuer identifier (gateway URL). Required by JWS verification (`issuer` option). |

### 1.3 Optional fields

| Field | Type | Description |
|---|---|---|
| `policy_version` | `string` | Floor/policy version the evaluator used (e.g. `"floor-v1.2.0"`). |
| `gateway_id` | `string` | Stable identifier of the issuing gateway (e.g. `"gateway.aeoess.com"`). |
| `attestation_grade` | `integer` | Passport grade 0–3. See §1.5. |
| `expires_at` | `string` | RFC 3339 UTC; after which the attestation MUST NOT be treated as fresh. |

### 1.4 `active_constraints` object

Shape derived from the public trust profile endpoint (`GET /api/v1/public/trust/:agentId`).

```ts
interface ActiveConstraints {
  scopes: string[]                    // granted delegation scopes, e.g. ["read:docs", "write:issues"]
  spend_limit: number | null          // cumulative cap; null = unlimited (not recommended)
  spend_used: number                  // cumulative spent so far
  spend_currency?: string             // ISO 4217 (e.g. "USD") or cryptocurrency ticker (e.g. "XNO")
  tool_restrictions?: string[]        // optional denylist of tool IDs
  max_depth?: number                  // sub-delegation depth ceiling
  current_depth?: number              // depth at evaluation time
  expires_at?: string                 // delegation expiry, independent of attestation expiry
}
```

All numeric fields are inclusive. A verifier rejects an action when any monotonic budget would be exceeded, or the requested scope is not authorized by any element in `scopes`.

### 1.5 `attestation_grade` (0–3)

| Grade | Meaning |
|---|---|
| 0 | Self-signed (bare keypair) |
| 1 | Issuer countersigned |
| 2 | Runtime-bound (issuer + challenge-response + trusted attestation) |
| 3 | Runtime + principal bound |

Source: `src/core/attestation.ts#computePassportGrade`.

### 1.6 JSON Schema

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "https://aeoess.com/schemas/governance-attestation-v0.1.json",
  "title": "governance_attestation",
  "type": "object",
  "required": ["signal_type", "active_constraints", "delegation_chain_hash", "evaluation_timestamp"],
  "properties": {
    "signal_type": { "const": "governance_attestation" },
    "active_constraints": {
      "type": "object",
      "required": ["scopes", "spend_used"],
      "properties": {
        "scopes": { "type": "array", "items": { "type": "string" } },
        "spend_limit": { "type": ["number", "null"], "minimum": 0 },
        "spend_used": { "type": "number", "minimum": 0 },
        "spend_currency": { "type": "string" },
        "tool_restrictions": { "type": "array", "items": { "type": "string" } },
        "max_depth": { "type": "integer", "minimum": 0 },
        "current_depth": { "type": "integer", "minimum": 0 },
        "expires_at": { "type": "string", "format": "date-time" }
      },
      "additionalProperties": false
    },
    "delegation_chain_hash": {
      "type": "string",
      "pattern": "^[0-9a-f]{64}$"
    },
    "evaluation_timestamp": { "type": "string", "format": "date-time" },
    "policy_version": { "type": "string" },
    "gateway_id": { "type": "string" },
    "attestation_grade": { "type": "integer", "minimum": 0, "maximum": 3 },
    "expires_at": { "type": "string", "format": "date-time" }
  },
  "additionalProperties": false
}
```

---

## 2. 3-Signature Chain Structure

douglasborthwick's spec (A2A#1628) requires a 2-signature minimum: agent intent + evaluator decision. `governance_attestation` wraps this into the APS **three-signature chain** (`src/core/policy.ts`, `src/types/policy.ts`), appending a third signature that binds the executed action to the evaluated decision.

```
┌────────────────────────────────────────────────────────────┐
│  Sig 1: ActionIntent — signed by agent                     │
│  "I want to do X with scope S at time T"                   │
│  agent_private_key → sign(canonicalize(intent))            │
├────────────────────────────────────────────────────────────┤
│  Sig 2: PolicyDecision — signed by evaluator (gateway)     │
│  "Intent I checked against floor F → verdict V"            │
│  gateway_private_key → sign(canonicalize(decision))        │
├────────────────────────────────────────────────────────────┤
│  Sig 3: ActionReceipt — signed by executor                 │
│  "Decision D was honored; here's proof of execution"       │
│  executor_private_key → sign(canonicalize(receipt))        │
└────────────────────────────────────────────────────────────┘
                            │
                            ▼
              PolicyReceipt (binds all three)
              chain = { intentSignature, decisionSignature, receiptSignature }
```

### 2.1 Relation to douglasborthwick's 2-sig minimum

| douglasborthwick (A2A#1628) | APS 3-sig chain |
|---|---|
| Sig A — agent intent | **Sig 1** `ActionIntent.signature` |
| Sig B — evaluator decision | **Sig 2** `PolicyDecision.signature` |
| *(implicit: execution happened)* | **Sig 3** `ActionReceipt.signature` |

The third signature is not redundant. Without it, a verifier can prove that *an evaluation occurred* but not that *the evaluated action ran*. Sig 3 closes the gap between "permitted" and "executed" — the difference between a policy simulator and an enforcement gateway.

### 2.2 Independent verifiability

Each signature is independently verifiable:

1. Resolve the signer's public key via DID or JWKS (`/.well-known/jwks.json`).
2. Canonicalize the unsigned object (deterministic JSON).
3. Verify the Ed25519 signature.

No shared trust root is required. A third party holding only the `PolicyReceipt.chain` block can verify all three without contacting the gateway, *provided* it can resolve the three public keys.

The `governance_attestation` signal is emitted alongside Sig 2 — it is the machine-readable projection of what the gateway *claimed was true* when it signed the decision. It does not replace any signature in the chain; it annotates Sig 2 with the constraint set that made the verdict possible.

### 2.3 Canonicalization

Canonicalization follows RFC 8785 (JCS) with `src/core/canonical.ts`:
- UTF-8
- Sorted object keys
- No insignificant whitespace
- Numbers in shortest round-trippable form
- Timestamps normalized to second-precision ISO 8601 UTC

---

## 3. Live Payload Example

> **Note:** This section describes the **target envelope shape** for the `governance_attestation` signal type. The current gateway endpoint (`/api/v1/public/trust/:agentId`) returns a `passport_grade` envelope with embedded `active_constraints`. The standalone `governance_attestation` envelope described below is the next gateway build. The schema contract (§1) and verification snippet (§4) are written against this target shape.

The following is a realistic attestation envelope. Keys, agent IDs, and signatures are illustrative — they are not drawn from a production tenant.

### 3.1 Unsigned claim

```json
{
  "signal_type": "governance_attestation",
  "iss": "https://gateway.aeoess.com",
  "gateway_id": "gateway.aeoess.com",
  "policy_version": "floor-v1.2.0",
  "attestation_grade": 2,
  "evaluation_timestamp": "2026-04-05T17:42:00Z",
  "expires_at": "2026-04-05T17:47:00Z",
  "delegation_chain_hash": "9c7a3f8d2b1e4a6c5f8d2b1e4a6c9c7a3f8d2b1e4a6c5f8d2b1e4a6c9c7a3f8d",
  "active_constraints": {
    "scopes": ["read:repo", "write:issue-comments", "spend:xno"],
    "spend_limit": 5.0,
    "spend_used": 1.237,
    "spend_currency": "XNO",
    "tool_restrictions": ["delete:*", "admin:*"],
    "max_depth": 3,
    "current_depth": 1,
    "expires_at": "2026-04-12T17:42:00Z"
  }
}
```

### 3.2 Signed envelope (JWS compact, target shape for `/api/v1/public/trust/:agentId/attestation`)

```json
{
  "issuer": "https://gateway.aeoess.com",
  "type": "governance_attestation",
  "kid": "gateway-v1",
  "alg": "EdDSA",
  "jwks": "https://gateway.aeoess.com/.well-known/jwks.json",
  "signed": { "...": "the unsigned claim above" },
  "jws": "eyJhbGciOiJFZERTQSIsImtpZCI6ImdhdGV3YXktdjEifQ.eyJzaWduYWxfdHlwZSI6Imdvdm…Vudl9pc3N1ZSJ9.mZ4rK7PNCqP9h2n7Y4fVx8j3bLcKNhT5Xc-wFx8g2sYqDvA3tR1m7P0ZqR4nL2sC8vB9xT6fW3yH7dG4kJpM5Aw"
}
```

### 3.3 JWKS entry (publicly fetched)

```json
{
  "keys": [{
    "crv": "Ed25519",
    "x": "dvueukplyAkApX4kkIxblvU57u9KuOsAbyUgDv1HekY",
    "kty": "OKP",
    "kid": "gateway-v1",
    "alg": "EdDSA",
    "use": "sig"
  }]
}
```

---

## 4. Verification Snippet

Copy-pasteable TypeScript. Uses standard `jose` + `fetch`. Zero APS dependencies.

```ts
import { jwtVerify, createRemoteJWKSet } from 'jose'

interface ActiveConstraints {
  scopes: string[]
  spend_limit: number | null
  spend_used: number
  spend_currency?: string
  tool_restrictions?: string[]
  max_depth?: number
  current_depth?: number
  expires_at?: string
}

interface GovernanceAttestation {
  signal_type: 'governance_attestation'
  active_constraints: ActiveConstraints
  delegation_chain_hash: string
  evaluation_timestamp: string
  policy_version?: string
  gateway_id?: string
  attestation_grade?: 0 | 1 | 2 | 3
  expires_at?: string
}

interface SignedEnvelope {
  issuer: string
  type: string
  kid: string
  alg: 'EdDSA'
  jwks: string
  signed: GovernanceAttestation
  jws: string
}

export async function verifyGovernanceAttestation(
  envelope: SignedEnvelope,
  opts: { requiredScope?: string; maxAgeSeconds?: number } = {},
): Promise<{ valid: true; claim: GovernanceAttestation } | { valid: false; reason: string }> {
  // 1. Resolve JWKS
  const JWKS = createRemoteJWKSet(new URL(envelope.jwks))

  // 2. Verify EdDSA signature
  let payload: GovernanceAttestation
  try {
    const { payload: p } = await jwtVerify(envelope.jws, JWKS, {
      issuer: envelope.issuer,
    })
    payload = p as unknown as GovernanceAttestation
  } catch (e) {
    return { valid: false, reason: `signature invalid: ${(e as Error).message}` }
  }

  // 3. Validate signal type
  if (payload.signal_type !== 'governance_attestation') {
    return { valid: false, reason: `wrong signal_type: ${payload.signal_type}` }
  }

  // 4. Validate freshness
  const now = Date.now()
  const evaluated = Date.parse(payload.evaluation_timestamp)
  if (!Number.isFinite(evaluated)) {
    return { valid: false, reason: 'bad evaluation_timestamp' }
  }
  const maxAgeMs = (opts.maxAgeSeconds ?? 300) * 1000
  if (now - evaluated > maxAgeMs) {
    return { valid: false, reason: `attestation stale (>${opts.maxAgeSeconds ?? 300}s)` }
  }
  if (payload.expires_at && Date.parse(payload.expires_at) < now) {
    return { valid: false, reason: 'attestation expired' }
  }

  // 5. Validate constraint set
  const c = payload.active_constraints
  if (!Array.isArray(c.scopes) || c.scopes.length === 0) {
    return { valid: false, reason: 'no scopes granted' }
  }
  if (typeof c.spend_used !== 'number' || c.spend_used < 0) {
    return { valid: false, reason: 'invalid spend_used' }
  }
  if (c.spend_limit !== null && c.spend_used > c.spend_limit) {
    return { valid: false, reason: 'spend budget exhausted' }
  }
  if (opts.requiredScope && !c.scopes.includes(opts.requiredScope)) {
    return { valid: false, reason: `scope "${opts.requiredScope}" not granted` }
  }

  return { valid: true, claim: payload }
}

// Example usage
const envelope: SignedEnvelope = await fetch(
  'https://gateway.aeoess.com/api/v1/public/trust/did:aps:agent-xyz/attestation',
).then(r => r.json())

const result = await verifyGovernanceAttestation(envelope, {
  requiredScope: 'write:issue-comments',
  maxAgeSeconds: 300,
})

if (!result.valid) {
  throw new Error(`refuse action: ${result.reason}`)
}
console.log('attested constraints:', result.claim.active_constraints)
```

---

## 5. Open questions (extension review)

1. Should `delegation_chain_hash` bind the *full resolved chain* (root delegation → current) or only the current delegation? Current APS implementation canonicalizes the full chain.
2. Is `spend_limit: null` too permissive for unattested agents? Suggest: require non-null for `attestation_grade < 2`.
3. Does `governance_attestation` need a replay nonce distinct from `evaluation_timestamp`? Current design relies on `expires_at` + short TTL (default 5 min).
4. Format alignment with SPIFFE JWT-SVID claim set and OpenID Federation 1.0 trust marks.

---

## 6. References

- `src/core/policy.ts` — 3-signature chain implementation (`createActionIntent`, `evaluateIntent`, `createPolicyReceipt`)
- `src/types/policy.ts` — `ActionIntent`, `PolicyDecision`, `PolicyReceipt` type definitions
- `src/core/attestation.ts` — `computePassportGrade`, `classifyEvidenceQuality`
- `src/core/canonical.ts` — RFC 8785 canonicalization
- Gateway `/api/v1/public/trust/:agentId` — `active_constraints` source
- Gateway `/api/v1/public/trust/:agentId/attestation` — signed JWS envelope
- Gateway `/.well-known/jwks.json` — EdDSA verification keys
