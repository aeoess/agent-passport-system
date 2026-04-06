# IETF Draft Envelope Receipts

Three signed receipts in the `draft-farley-acta-signed-receipts-01` envelope format, generated from real APS ProxyGateway execution paths.

## Receipts

| File | Scenario | Finality |
|------|----------|----------|
| `receipt-permit.json` | Permitted tool call (code_execution) | executed |
| `receipt-deny.json` | Denied tool call (admin:delete scope violation) | denied |
| `receipt-commerce.json` | Commerce preflight ($49.99 within $500 budget) | executed |

All three are chained: permit -> deny -> commerce (via `previousReceiptHash`).

## Envelope Structure

```json
{
  "spec": "draft-farley-acta-signed-receipts-01",
  "receipt_id": "sha256:<JCS-canonical-payload-hash>",
  "issued_at": "ISO 8601",
  "issuer_id": "did:aps:z6Mk...",
  "previousReceiptHash": "<prior receipt_id or null>",
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
        "finality": "executed|denied",
        "intentSignature": "<agent Ed25519>",
        "decisionSignature": "<gateway Ed25519>"
      }
    }
  },
  "signature": {
    "alg": "EdDSA",
    "kid": "did:aps:z6Mk...",
    "sig": "<hex Ed25519 over JCS-canonical payload>"
  }
}
```

## Verify

```bash
bash verify.sh
```

Checks structure, chain integrity, and signature format. For full cryptographic verification (Ed25519 + JCS canonicalization), regenerate and verify via the SDK:

```bash
npx tsx examples/interop/ietf-envelope/generate-receipts.ts
```

## APS Extensions

The `extensions.aps` block adds:
- `delegationChain`: links to the APS delegation that authorized this action
- `scope`: what scopes the delegation covers
- `spend`: commerce spend tracking
- `finality`: whether the action executed or was denied
- `intentSignature`: agent's Ed25519 signature on the intent (proves agent requested this)
- `decisionSignature`: gateway's Ed25519 signature on the decision (proves gateway evaluated this)

## License

Apache-2.0. Part of [Agent Passport System](https://github.com/aeoess/agent-passport-system).
