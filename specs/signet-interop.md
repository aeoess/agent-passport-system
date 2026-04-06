# APS-Signet Interop Specification

**Version:** 0.1.0 (Draft)
**Authors:** AEOESS (Tymofii Pidlisnyi)
**Status:** Proposal for Signet-AI/signetai #312

---

## Abstract

This specification defines how Agent Passport System (APS) delegation credentials embed inside Signet chain links, how verification works from both sides independently, and how revocation propagates across the two systems. The goal is minimal coupling: each system verifies what it owns, with a single cross-protocol call for revocation status.

---

## 1. Combined Credential Envelope

An APS delegation credential is embedded in a Signet chain link's `metadata` field. The Signet link provides chain provenance. The APS delegation provides scoped authorization. Neither system needs to understand the other's internals.

```json
{
  "signet_link": {
    "linkId": "<signet-link-uuid>",
    "chain": "<signet-chain-id>",
    "status": "active",
    "created_at": "<ISO 8601>",
    "metadata": {
      "aps_delegation": {
        "delegationId": "<aps-delegation-id>",
        "delegatedTo": "<agent-ed25519-public-key-hex>",
        "delegatedBy": "<principal-ed25519-public-key-hex>",
        "scope": ["tools:readFile", "tools:writeFile"],
        "spendLimit": 0,
        "expiresAt": "<ISO 8601>",
        "maxDepth": 1,
        "currentDepth": 0,
        "createdAt": "<ISO 8601>",
        "signature": "<ed25519-hex-signature>"
      },
      "aps_delegation_hash": "sha256:<hash-of-canonical-aps-delegation>"
    }
  }
}
```

### Binding Integrity

The `aps_delegation_hash` is the SHA-256 hash of the APS delegation object canonicalized per APS rules (`canonicalize()` from the SDK). If any field in the delegation is modified, the hash changes, and the Signet link's metadata no longer matches. This is the binding between the two systems.

A verifier that understands both protocols checks:
1. Signet chain integrity (Signet's verification)
2. APS delegation signature (Ed25519 over canonical delegation)
3. `aps_delegation_hash` matches the actual delegation content

---

## 2. Verification Flows

### 2.1 APS-Only Verifier

An APS-only service encounters a combined credential. It:

1. Extracts `metadata.aps_delegation` from the Signet link
2. Verifies the Ed25519 signature against `delegatedBy` (principal's public key)
3. Checks scope covers the requested action
4. Checks `expiresAt` is in the future
5. Checks `spendLimit` if applicable
6. Treats the Signet wrapper as provenance metadata (acknowledged, not verified)
7. Optionally logs `signet_link.linkId` for cross-reference

The APS-only verifier does not need Signet libraries. It treats the Signet wrapper as an opaque envelope.

### 2.2 Signet-Only Verifier

A Signet-only service encounters a combined credential. It:

1. Verifies chain integrity using Signet's own verification
2. Checks `signet_link.status` is `active`
3. Treats `metadata.aps_delegation` as opaque metadata
4. Returns link status to the caller

The Signet-only verifier does not need APS libraries. It treats the APS delegation as opaque metadata.

### 2.3 Full Verification (Both)

A service that understands both protocols:

1. Signet verifies chain integrity and link status
2. APS verifies delegation signature, scope, expiry, spend
3. Cross-check: `aps_delegation_hash` matches `sha256(canonicalize(aps_delegation))`
4. Both checks must pass for the credential to be valid

---

## 3. Revocation Propagation

Revocation can originate from either system.

### 3.1 Signet Revokes Link

When Signet revokes a chain link:
- The APS delegation inside is still cryptographically valid (signature checks pass)
- But the Signet link status changes to `revoked`
- An APS-only service that cached the delegation can check revocation via Signet's status endpoint:

```
GET /chain/{chainId}/link/{linkId}/status
Response: { "status": "active" | "revoked", "revokedAt": "ISO 8601 | null" }
```

This is the one cross-protocol call needed. APS services SHOULD cache the status with a TTL (recommended: 60 seconds).

### 3.2 APS Revokes Delegation

When APS revokes the delegation (via `revokeDelegation()`):
- The APS delegation signature still verifies, but the delegation is in APS's revocation registry
- The Signet link remains `active` in Signet's chain
- A Signet-only service is unaware of the APS revocation
- A full verifier checks both and rejects the credential

### 3.3 Recommendation

For maximum safety, implementations SHOULD check both revocation sources. If only one is available, prefer the source that owns the authorization decision:
- For access control decisions: check APS revocation (APS owns authorization)
- For chain provenance decisions: check Signet revocation (Signet owns chain integrity)

---

## 4. Test Vectors

Three test vectors demonstrate the interop flows. JSON files are in `specs/test-vectors/signet/`.

### Vector 1: Issuance

Create a Signet link containing an APS delegation. Verify from both sides.

See: `specs/test-vectors/signet/vector-1-issuance.json`

### Vector 2: Presentation

Agent presents the combined credential to an APS-only service. Service verifies the delegation and ignores the Signet wrapper.

See: `specs/test-vectors/signet/vector-2-presentation.json`

### Vector 3: Revocation

Signet revokes the link. APS-only service queries the status endpoint and rejects the cached credential.

See: `specs/test-vectors/signet/vector-3-revocation.json`

---

## References

- [Agent Passport System](https://www.npmjs.com/package/agent-passport-system) (npm)
- [Signet-AI](https://github.com/Signet-AI/signetai)
- Signet-AI/signetai #312 (interop discussion)
- APS canonicalization: `canonicalize()` from SDK (deterministic JSON serialization)
- Ed25519 signatures: RFC 8032
