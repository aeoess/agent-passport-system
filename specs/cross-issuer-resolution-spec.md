# Cross-Issuer Proof Resolution Spec (DRAFT)

> Working Group Draft — April 2, 2026
> Authors: aeoess (primary), desiorac (co-design)
> Source: A2A#1672 convergence over 3 rounds
> Status: DRAFT for WG review

## Abstract

When multiple governance systems produce receipts (APS, ArkForge, AgentID, MolTrust),
verifiers need to resolve proof references across system boundaries. This spec defines:

1. **Proof ID namespacing** — which system issued the receipt
2. **Resolution convention** — how to fetch the receipt
3. **Equivalence binding** — what must be bound at signing time
4. **Temporal anchoring** — independent timestamp proof via transparency log

## 1. Proof ID Format

### 1.1 Simple Namespace
```
aps:drv_abc123
arkforge:prf_xyz
```

### 1.2 DID-Style (recommended for cross-org)
```
did:web:gateway.aeoess.com:proof:drv_abc123
did:web:arkforge.dev:proof:prf_xyz
```

The DID document's `service` array provides the resolution endpoint.
No out-of-band configuration required.

### 1.3 Parsing Rules

- `aps:local_id` → namespace=`aps`, id=`local_id`
- `did:web:issuer:proof:local_id` → namespace=`did:web:issuer`, id=`local_id`
- Bare `local_id` (no colon) → namespace=null (local-only, not cross-resolvable)

Implementation: `parseNamespacedId()` in `agent-passport-system` SDK.

## 2. Resolution Convention

### 2.1 Well-Known Endpoint

Every issuer MUST expose:
```
GET /.well-known/receipts/{receiptId}
```

Response:
```json
{
  "proofId": "aps:drv_abc123",
  "proofType": "policy_receipt | access_receipt | derivation_receipt | settlement",
  "issuer": "https://gateway.aeoess.com",
  "issuedAt": "2026-04-02T05:30:00Z",
  "agentId": "did:aps:agent_123",
  "signature": "<Ed25519 signature over body>",
  "body": { ... },
  "jwksUrl": "https://gateway.aeoess.com/.well-known/jwks.json",
  "resolvedAt": "2026-04-02T05:31:00Z"
}
```

### 2.2 Resolution Flow
1. Parse the namespaced proof ID
2. Resolve the namespace to a base URL (via DID document `service` or static registry)
3. Fetch `{baseUrl}/{receiptId}`
4. Verify signature using JWKS from `jwksUrl`
5. Verify `agentId` matches expected agent

### 2.3 Caching
- Receipts are immutable → long cache safe (Cache-Control: max-age=600)
- Rate limit: 120 req/min per IP (MUST)
- TTL bounds: 60-3600 seconds (SHOULD)

## 3. Equivalence Binding (Phase 2)

### 3.1 Problem
Resolving a proof tells you WHICH receipt and FROM WHOM.
Equivalence verification tells you WHAT WAS IN THE PROOF at signing time.
Both must be specced together to avoid a breaking change when cross-issuer flows go live.

### 3.2 Bound Fields
The following fields MUST be included in the signed receipt body at creation time:

| Field | Purpose | Required |
|-------|---------|----------|
| `delegation_chain_hash` | Proves authorization context | YES |
| `agent_did` | Proves agent identity | YES |
| `parameter_hash` | Proves what was authorized/executed | YES |
| `authorization_scope` | Proves scope at decision time | YES |
| `agent_version` | Enables equivalence comparison | RECOMMENDED |
| `prompt_hash` | Enables behavioral equivalence | RECOMMENDED |

### 3.3 Key Reference (not inline)
Resolved artifacts MUST carry a `verificationMethod` reference by key ID (`kid`),
NOT an inline public key. Inline keys break on rotation — the key ID stays stable
across rotations and resolves via the issuer's DID document.

Source: desiorac on A2A#1672 — tested on ArkForge DID binding during key rotation.

### 3.4 Delegation Chain Decoupling
The delegation chain is hashed separately. Only the hash is included in the
anchor payload. Schema evolution changes the chain representation but NOT the
hash construction, so old proofs remain verifiable.

`computeCompoundDigest()` already implements this pattern.

## 4. Temporal Anchoring (Rekor)

### 4.1 Minimum Anchor Payload (4 fields)
```json
{
  "receipt_hash": "sha256:<hex>",
  "agent_did": "did:aps:<id>",
  "issuer": "https://gateway.aeoess.com",
  "anchored_at": "2026-04-02T05:30:00Z"
}
```

### 4.2 Verification Without Issuer Access
A verifier with no access to the issuer can confirm:
- This receipt existed at this time with this hash
- Produced by this agent
- The Rekor entry proves existence and timing
- The issuer endpoint provides the evidence (when available)

Two independent layers: Rekor proves WHEN. Issuer proves WHAT.

### 4.3 Anchor Flow
1. Gateway signs receipt with Ed25519
2. Gateway computes `sha256(canonicalize(receipt_body))`
3. Gateway submits 4-field payload to Rekor
4. Rekor returns log index + inclusion proof
5. Gateway stores `rekor_log_index` in receipt metadata
6. Verifier checks Rekor independently of the gateway

### 4.4 Canonicalization
All hash inputs MUST use JCS (RFC 8785):
- Sorted keys by Unicode code point
- Compact separators (`","` and `":"`)
- Number normalization (`1.0` → `1`, `-0` → `0`)
- Consistent Unicode escaping

Cross-verified with Python `json.dumps(data, sort_keys=True, separators=(",", ":"))`.
14 test vectors passing across TypeScript + Python (Harold AgentID confirmation).

## 5. Implementation Status

| Component | Status | Module |
|-----------|--------|--------|
| Proof ID namespacing | ✅ Shipped | `proof-namespace.ts` |
| `/.well-known/receipts/` endpoint | ✅ Live | Gateway v0.3.1 |
| JWKS endpoint | ✅ Live | Gateway `/.well-known/jwks.json` |
| JCS canonicalization | ✅ Shipped | `canonical-jcs.ts` |
| Compound digest (chain hash) | ✅ Shipped | `execution-attestation.ts` |
| Rekor anchoring | 🔲 Planned | Gateway feature |
| DID document service resolution | 🔲 Planned | `did.ts` extension |

## 6. Open Questions for WG

1. Should the canonical benign drift list be normative or informational?
2. Should resolution failures produce a structured error or HTTP 404?
3. What's the minimum TTL for receipt caching? (Proposed: 60 seconds)
4. Should the spec require Rekor specifically, or allow any transparency log?

---

*This spec is a WG draft. Comments welcome on A2A#1672 or qntm#6.*
