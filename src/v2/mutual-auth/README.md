# Mutual Authentication v1 (APS v2.2.0)

**Status:** shipped primitive, v1.0.
**Scope:** two-way authentication between an Agent and an Information System
(IS), ending in a shared signed session record.
**Apache 2.0.**

## Why

APS v2.1.0 and earlier are asymmetric: agents authenticate to systems
(passport + delegation + action receipts), but systems do not
authenticate to agents. This module closes that asymmetry.

The asymmetry matters because an agent that unconditionally trusts
whatever endpoint it is told to hit is phishable. A bank that issues
a scoped passport to an agent cannot tell the agent which DMS / API
/ MCP server is actually theirs without a protocol-level way to sign
that claim.

## What this ships

- `MutualAuthCertificate`: small signed envelope identifying either party
- `TrustAnchorBundle`: portable, signed, versioned bundle of trusted roots
  each party carries locally
- `MutualAuthHello`, `MutualAuthAttest`: handshake messages
- `MutualAuthSession`: derived shared record after a successful handshake
- Handshake primitives: build + sign + verify + derive
- Downgrade-attack defence baked into the Attest signature
- Replay defence via nonces + timestamp + max_clock_skew_ms
- Local anchor check with binding constraints and revocation
- Two adapters: `mutual-auth-a2a.ts`, `mutual-auth-mcp.ts`

## What this does NOT ship

Deliberately out of scope:

- Federation protocol between gateway nodes
- Gossip layer
- Certificate Transparency-equivalent append-only log
- Consensus revocation
- Multi-root cross-signing topology
- Issuer economics / billing
- Hosted CA infrastructure
- Legal entity / governance model

Mutual auth is a protocol primitive that stands on its own merits. A
future federation layer, if one ever ships, would compose on top of
these primitives without changing them. Nothing in this module
assumes federation exists.

## Handshake flow

```
Agent                              Information System
  |                                       |
  |  1. Hello(agent_nonce, supp_versions) |
  |-------------------------------------->|
  |                                       |
  |  2. Attest(chosen_version,            |
  |            agent_nonce,               |
  |            is_nonce,                  |
  |            is_certificate,            |
  |            sig)                       |
  |<--------------------------------------|
  |                                       |
  |  verifyAttest(is_attest, policy, anchors) |
  |                                       |
  |  3. Attest(chosen_version,            |
  |            is_nonce,                  |
  |            agent_nonce,               |
  |            agent_certificate,         |
  |            sig)                       |
  |-------------------------------------->|
  |                                       |
  |     verifyAttest(agent_attest, policy, anchors)
  |                                       |
  |  4. deriveSession(agent_attest, is_attest)
  |     (both sides compute identical session_id)
  |                                       |
```

## Downgrade defence

The Attest signature commits to `chosen_version || own_nonce ||
peer_nonce || certificate`. An attacker who tampers with
`supported_versions` at transport to force a lower version cannot
forge a valid Attest that advertises that version without also
breaking the signature. The verifier additionally recomputes
`chooseVersion(peer.cert.supported_versions, policy.accepted_versions)`
and compares against the attested `chosen_version`: any mismatch
fails with `downgrade_detected`.

## Replay defence

- 128-bit random nonces (`newNonce()`)
- Attest timestamp must be within `max_clock_skew_ms` of the verifier's
  clock (clamped to at least 60s to absorb NTP drift)
- Session ID derivation hashes both nonces; a replayed session has a
  different session_id

## Revocation

Local, cache-based. Each party carries a `TrustAnchorBundle` with a
`refresh_after` timestamp and a `revoked_anchors` list. The verifier
consults these at handshake time. No OCSP, no CRL distribution point
fetch per handshake. If a richer revocation model is needed in the
future (federation, transparency log), it layers on top without
changing the on-wire handshake.

## Policy knobs

```ts
interface MutualAuthPolicy {
  accepted_versions: string[]          // ordered by preference
  min_agent_grade?: 0 | 1 | 2 | 3      // APS attestation grade
  required_capabilities?: string[]     // required cert capability tags
  max_clock_skew_ms?: number           // default 0, clamped to >= 60s
  max_session_ms?: number              // default = min(cert expiries)
}
```

## Adapters

### A2A (`adapters/mutual-auth-a2a.ts`)

Layers mutual auth on Google's Agent-to-Agent Protocol. Adds a
`mutualAuthCertificate` field to the A2A Agent Card's `agentPassport`
extension. Handshake functions mirror the four-step flow above with
A2A wire semantics.

### MCP (`adapters/mutual-auth-mcp.ts`)

Layers mutual auth on Anthropic's Model Context Protocol. Binds the
IS certificate to an `mcp://host/path` binding string so that an
established session can be reused across multiple tool calls against
the same server, with `mcpIsToolCallPermitted` checking the session
is live and the binding matches.

## Conformance

`src/conformance/mutual-auth-vectors/` contains five JSON vectors
covering canonical forms of certificate, bundle, attest, and
session_id derivation. Downstream language implementations (Python,
Go, Rust) pass conformance iff they produce identical canonical
bytes and SHA-256 hashes for the same inputs. Ed25519 signatures are
not part of conformance because library choice produces
byte-different-but-equivalent signatures.

Regenerate vectors: `npx tsx scripts/build-mutual-auth-vectors.ts`.

## Tests

`tests/v2/mutual-auth/handshake.test.ts` (happy path, 12 tests) and
`tests/v2/mutual-auth/adversarial.test.ts` (13 attack vectors) run
as part of the main `npm test` suite.

Adversarial tests cover: downgrade, replay (nonce mismatch + clock
skew), MITM cert swap, attest signed by wrong key, expired cert,
revoked anchor, insufficient attestation grade, missing capability,
role misuse in session derivation.

## Non-goals for v1

Anything that requires coordination across multiple parties not
present at the handshake (federation, cross-CA gossip,
transparency-log auditing) is deferred to a hypothetical v2. If
such a layer is ever built, it will do so by adding new message
types and new certificate fields while keeping v1 wire-compatible.
