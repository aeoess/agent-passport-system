# Build Spec: Signet-AI Interop Spec PR

## Context
Signet-AI/signetai #312. We committed to sketching a minimal interop spec as a PR.

## What
A spec document defining how APS delegation credentials embed inside Signet chain links, how verification works from both sides, and how revocation propagates.

## Where
- `specs/signet-interop.md` in this repo (the spec itself)
- PR to Signet-AI/signetai referencing the spec

## Spec structure

### 1. Combined Credential Envelope

```json
{
  "signet_link": {
    "linkId": "...",
    "chain": "...",
    "status": "active",
    "metadata": {
      "aps_delegation": {
        "delegationId": "...",
        "delegatedTo": "<agent-public-key>",
        "delegatedBy": "<principal-public-key>",
        "scope": ["tools:readFile", "tools:writeFile"],
        "spendLimit": 0,
        "expiresAt": "...",
        "signature": "..."
      },
      "aps_delegation_hash": "sha256:<hash of canonical aps_delegation>"
    }
  }
}
```

The `aps_delegation_hash` binds the APS credential to the Signet link. If the delegation is modified, the hash changes, and the Signet link no longer matches.

### 2. Verification Flows

**APS-only verifier:**
- Extracts `metadata.aps_delegation` from the Signet link
- Verifies Ed25519 signature on the delegation
- Checks scope, expiry, spend limit
- Treats Signet wrapper as provenance metadata (acknowledged, not verified)

**Signet-only verifier:**
- Verifies chain integrity (Signet's own verification)
- Treats `metadata.aps_delegation` as opaque
- Returns link status (active/revoked)

**Both (full verification):**
- Signet verifies chain integrity
- APS verifies delegation
- Cross-check: `aps_delegation_hash` matches the actual delegation content

### 3. Revocation Propagation

When Signet revokes a chain link:
- The APS delegation inside is cryptographically valid but unreachable
- An APS-only service that cached the delegation can check revocation via:
  `GET /chain/{linkId}/status → { "status": "active" | "revoked" }`
- This is the one cross-protocol call needed

### 4. Test Vectors (3)

1. **Issuance:** Create Signet link containing APS delegation → verify from both sides
2. **Presentation:** Agent presents combined credential to APS-only service → service verifies delegation, ignores Signet wrapper
3. **Revocation:** Signet revokes link → APS-only service queries status endpoint → rejects cached credential

## How to build
1. Write `specs/signet-interop.md` with the above content
2. Generate 3 test vector JSON files in `specs/test-vectors/signet/`
3. Commit to this repo
4. Open PR on Signet-AI/signetai via `gh pr create` (or open issue with link if PRs aren't accepted from outside)
5. Post comment on Signet-AI/signetai #312 with link
