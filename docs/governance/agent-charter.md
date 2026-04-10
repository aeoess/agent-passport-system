# Agent Charter — Persistent Identity Layer

This document declares which SDK modules implement the persistent agent
identity layer that `agent-governance-check@1.0.0` looks for under
"Who is your agent between invocations?". It exists so that the
checker reports FOUND, not PARTIAL, against a real implementation
rather than against marketing prose.

## What the layer provides

The Agent Passport System carries persistent agent identity in two
complementary modules. The first binds an agent to a human or
organizational principal with a signed endorsement chain. The second
keeps that binding stable across cryptographic key rotation, so an
agent that rotates its signing key remains the same agent for the
purposes of governance, reputation, and revocation.

## Modules

### `src/core/principal.ts` — principal identity and endorsement

Source: [`src/core/principal.ts`](../../src/core/principal.ts)
Tests: [`tests/principal.test.ts`](../../tests/principal.test.ts)

The principal-identity module implements the cryptographic chain from
a human (or organizational) principal down to the agents acting under
their authority.

Canonical types and functions exported from `src/core/principal.ts`:

- `createPrincipalIdentity(opts)` — generates an Ed25519 keypair and a
  `PrincipalIdentity` record for the human or organization at the
  root of an agent's authority chain.
- `endorseAgent(opts)` — produces a signed `PrincipalEndorsement`
  binding a specific agent (by `agentId` and public key) to a
  principal. Endorsements name the scope and purpose for which the
  principal accepts responsibility.
- `verifyEndorsement(endorsement)` — verifies the endorsement
  signature against the principal's public key and surfaces any
  tampering or expiry.
- `revokeEndorsement(endorsement, principalPrivateKey, reason)` — the
  principal explicitly withdraws responsibility. Downstream
  delegations cascade-revoke through the gateway.
- `createDisclosure(...)` and `verifyDisclosure(...)` — selective
  disclosure of principal attributes. The agent presents only the
  fields the relying party needs.
- `createFleet`, `addToFleet`, `getFleetStatus`, `revokeFromFleet` —
  fleet management for principals running multiple agents under one
  identity.

### `src/core/identity.ts` — identity continuity through key rotation

Source: [`src/core/identity.ts`](../../src/core/identity.ts)
Tests: [`tests/identity.test.ts`](../../tests/identity.test.ts), [`tests/identity-pipeline.test.ts`](../../tests/identity-pipeline.test.ts)

Persistent identity has to survive key rotation, otherwise an agent
that rotates becomes a new agent and loses its history. This module
provides the rotation log and the proof that "agent X with old key K0
and new key K1" is the same agent.

Canonical exports:

- `createIdentityDocument(opts)` — creates the `IdentityDocument` that
  carries the agent's current key plus the full rotation log.
- `rotateKey(opts)` — planned rotation. Old key signs the rotation
  request (proves authorization), new key signs the activation
  (proves possession). Both signatures are stored in the rotation
  log.
- `emergencyRotate(opts)` — rotation under a pre-committed recovery
  key, for the case where the active key is compromised or lost.
- `verifyRotation(entry)` and `verifyRotationLog(identity)` — verify
  that every entry in the rotation chain is dual-signed and that the
  chain has no gaps.
- `resolveCurrentKey(identity)` — returns the currently active public
  key for the agent, traversing the rotation log.
- `wasKeyActive(identity, publicKey)` — answers "was this public key
  ever a valid key for this agent" so historical receipts and
  signatures verify even after rotation.

## Charter commitments

These are the protocol commitments the modules above enforce:

1. **An agent cannot exist without a principal.** Every passport
   issued through `endorseAgent` names a principal public key, and
   downstream delegations carry that principal forward. Receipts
   trace back to a human or organization, not an opaque service
   account.

2. **A principal can withdraw at any time.** `revokeEndorsement` is a
   single signed call that propagates through the delegation chain
   via cascade revocation. The protocol does not let an agent outlive
   its principal's consent.

3. **Identity is stable across key rotation.** Rotating a signing key
   does not create a new agent. The rotation log carries forward
   reputation, delegations, and any cryptographic scarring from past
   demotions. An agent cannot escape its history by rotating.

4. **Old signatures still verify.** `wasKeyActive` ensures that
   receipts and delegations signed under a previous key remain
   verifiable after rotation. History is append-only.

5. **Rotation is dual-signed.** `rotateKey` requires both the old key
   (authorization) and the new key (possession). A stolen new key
   alone cannot impersonate an agent. A stolen old key alone cannot
   silently install a new key without the agent noticing.

## Runnable example

```typescript
import {
  createPrincipalIdentity, endorseAgent, verifyEndorsement,
  createIdentityDocument, rotateKey, verifyRotationLog,
  resolveCurrentKey, wasKeyActive,
  generateKeyPair,
} from 'agent-passport-system'

// 1. The principal: a human or organization at the root of authority.
const principal = createPrincipalIdentity({
  name: 'Tima',
  type: 'human',
  contact: 'signal@aeoess.com',
})

// 2. The agent: a keypair plus an endorsement signed by the principal.
const agentKeys = generateKeyPair()
const endorsement = endorseAgent({
  principal,
  agentId: 'aeoess-bound-demo',
  agentPublicKey: agentKeys.publicKey,
  scope: ['governance:read', 'commerce:checkout'],
  purpose: 'Demonstrate persistent identity layer',
})

console.log('Endorsement valid:', verifyEndorsement(endorsement).valid)

// 3. Identity continuity: the rotation log carries forward when the
//    agent rotates its signing key.
const identity = createIdentityDocument({
  agentId: 'aeoess-bound-demo',
  initialPublicKey: agentKeys.publicKey,
  initialPrivateKey: agentKeys.privateKey,
})

const newKeys = generateKeyPair()
const rotated = rotateKey({
  identity,
  oldPrivateKey: agentKeys.privateKey,
  newPublicKey: newKeys.publicKey,
  newPrivateKey: newKeys.privateKey,
  reason: 'planned rotation, 90 day cycle',
})

// The agent is the SAME agent, with a new active key.
console.log('Rotation log valid:', verifyRotationLog(rotated).valid)
console.log('Current key:', resolveCurrentKey(rotated))
console.log('Old key still recognized:', wasKeyActive(rotated, agentKeys.publicKey))
```

This produces a continuous identity record. The agent that signed the
endorsement above and the agent operating under the rotated key are,
by protocol, the same agent. Reputation, delegations, and outstanding
receipts all carry forward.
