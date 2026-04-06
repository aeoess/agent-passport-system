# Build Spec: IETF Draft Envelope Test Receipts

## Context
crewAI #5283. We committed to producing 3 test receipts in the IETF draft envelope format from real APS ProxyGateway executions, verifiable by `@veritasacta/verify`.

## What
Generate 3 JSON receipt files that follow the IETF `draft-farley-acta-signed-receipts` envelope format, populated with real APS ProxyGateway execution data.

## Where
- `examples/interop/ietf-envelope/` (new directory)
- 3 JSON files: `receipt-permit.json`, `receipt-deny.json`, `receipt-commerce.json`
- `examples/interop/ietf-envelope/README.md`
- `examples/interop/ietf-envelope/verify.sh` — shell script that runs `@veritasacta/verify` against all 3

## IETF Envelope Format

Each receipt follows this structure (from `draft-farley-acta-signed-receipts-01`):

```json
{
  "spec": "draft-farley-acta-signed-receipts-01",
  "receipt_id": "sha256:<content-addressed-hash>",
  "issued_at": "2026-04-06T...",
  "issuer_id": "did:key:z6Mk...",
  "previousReceiptHash": "<sha256 of previous receipt or null>",
  "payload": {
    "agentId": "...",
    "delegationId": "...",
    "action": { "tool": "...", "scopeUsed": "...", "params": {} },
    "result": { "success": true/false },
    "extensions": {
      "aps": {
        "delegationChain": "...",
        "scope": ["..."],
        "spend": { "amount": 0, "currency": "usd" },
        "finality": "executed",
        "intentSignature": "...",
        "decisionSignature": "..."
      }
    }
  },
  "signature": {
    "alg": "EdDSA",
    "kid": "did:key:z6Mk...",
    "sig": "<hex-encoded Ed25519 signature>"
  }
}
```

## How to generate

1. Create a passport + delegation using SDK functions
2. Run 3 actions through the enforcement pipeline:
   - Receipt 1: Permitted tool call (code_execution scope)
   - Receipt 2: Denied tool call (scope violation)
   - Receipt 3: Commerce preflight (spend within budget)
3. For each, take the APS ActionReceipt and reformat into the IETF envelope structure
4. Canonicalize payload using JCS (RFC 8785) — use `canonicalizeJCS()` from SDK
5. Sign the canonical payload with Ed25519 — use `sign()` from SDK
6. Compute `receipt_id` as `sha256:<hash of canonical payload>`
7. Chain: receipt 2's `previousReceiptHash` = receipt 1's `receipt_id`, receipt 3's = receipt 2's

## Verification

```bash
# Install verifier
npm install -g @veritasacta/verify@0.2.5

# Verify each receipt
npx @veritasacta/verify receipt-permit.json --key <public-key-hex>
# Expected: exit 0

npx @veritasacta/verify receipt-deny.json --key <public-key-hex>
# Expected: exit 0

npx @veritasacta/verify receipt-commerce.json --key <public-key-hex>
# Expected: exit 0
```

Write `verify.sh` that extracts the public key from the first receipt and verifies all three.

## After building
- Commit with message referencing crewAI #5283
- Post comment on crewAI #5283 via `gh issue comment 5283 --repo crewAIInc/crewAI` with link to the receipts directory and verification instructions
