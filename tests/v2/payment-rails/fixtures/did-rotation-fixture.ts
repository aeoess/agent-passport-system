// Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// ══════════════════════════════════════════════════════════════════
// DID-rotation fixture for Phase 4.1 / P12 tests
// ══════════════════════════════════════════════════════════════════
// Tiny mock RotatableDIDDocument with two keys and helpers for
// constructing variations (active-only, both-active, key-1 retired).
// Avoids the heavy createDIDDocument/announceKeyRotation path so the
// tests stay focused on signer_did behavior, not rotation mechanics.
// ══════════════════════════════════════════════════════════════════

import { generateKeyPair, type KeyPair } from '../../../../src/crypto/keys.js'
import { hexToMultibase } from '../../../../src/core/did.js'
import type {
  RotatableDIDDocument,
  RotatableVerificationMethod,
} from '../../../../src/types/passport.js'

const DID_CONTEXT = [
  'https://www.w3.org/ns/did/v1',
  'https://w3id.org/security/suites/ed25519-2020/v1',
]

export interface RotationFixture {
  /** Agent DID (e.g. `did:agent:abc123`). */
  agentId: string
  /** First-key keypair + DID URI. */
  key1: KeyPair & { keyRef: string; didUri: string }
  /** Second-key keypair + DID URI. */
  key2: KeyPair & { keyRef: string; didUri: string }
}

/**
 * Build a deterministic-shape rotation fixture. Caller may pass a
 * pre-generated KeyPair to pin a specific public key (useful for
 * test reproducibility); otherwise fresh keys are generated.
 */
export function makeRotationFixture(opts: {
  agentId?: string
  key1?: KeyPair
  key2?: KeyPair
} = {}): RotationFixture {
  const agentId = opts.agentId ?? 'did:agent:p12-test'
  const k1 = opts.key1 ?? generateKeyPair()
  const k2 = opts.key2 ?? generateKeyPair()
  return {
    agentId,
    key1: { ...k1, keyRef: 'key-1', didUri: `${agentId}#key-1` },
    key2: { ...k2, keyRef: 'key-2', didUri: `${agentId}#key-2` },
  }
}

/**
 * DID document where key-1 is the sole active key. Used to verify
 * receipts signed before any rotation.
 */
export function docKey1Active(fx: RotationFixture, createdAt: string): RotatableDIDDocument {
  const vm1: RotatableVerificationMethod = {
    id: fx.key1.didUri,
    type: 'Ed25519VerificationKey2020',
    controller: fx.agentId,
    publicKeyMultibase: hexToMultibase(fx.key1.publicKey),
  }
  return {
    '@context': DID_CONTEXT,
    id: fx.agentId,
    controller: fx.agentId,
    verificationMethod: [vm1],
    authentication: [fx.key1.didUri],
    assertionMethod: [fx.key1.didUri],
    capabilityDelegation: [fx.key1.didUri],
    rotationLog: [],
    created: createdAt,
    updated: createdAt,
  }
}

/**
 * DID document AFTER a planned rotation: key-1 is retired AT
 * `key1RetiredAt`, key-2 is active. The retired key remains in
 * verificationMethod[] so historic receipts can still be verified
 * when their signing instant fell before key1RetiredAt.
 */
export function docAfterRotation(
  fx: RotationFixture,
  createdAt: string,
  key1RetiredAt: string,
): RotatableDIDDocument {
  const vm1: RotatableVerificationMethod = {
    id: fx.key1.didUri,
    type: 'Ed25519VerificationKey2020',
    controller: fx.agentId,
    publicKeyMultibase: hexToMultibase(fx.key1.publicKey),
    retiredAt: key1RetiredAt,
  }
  const vm2: RotatableVerificationMethod = {
    id: fx.key2.didUri,
    type: 'Ed25519VerificationKey2020',
    controller: fx.agentId,
    publicKeyMultibase: hexToMultibase(fx.key2.publicKey),
  }
  return {
    '@context': DID_CONTEXT,
    id: fx.agentId,
    controller: fx.agentId,
    verificationMethod: [vm1, vm2],
    authentication: [fx.key2.didUri],
    assertionMethod: [fx.key2.didUri],
    capabilityDelegation: [fx.key2.didUri],
    rotationLog: [],
    created: createdAt,
    updated: key1RetiredAt,
  }
}

/**
 * Caller-supplied resolver that maps agentId → RotatableDIDDocument.
 * Tests build a small in-memory map and pass `resolver(map)` into the
 * verifier. Returns null on miss to exercise the not-found path.
 */
export function makeResolver(
  docs: Record<string, RotatableDIDDocument>,
): (agentId: string) => Promise<RotatableDIDDocument | null> {
  return async (agentId) => docs[agentId] ?? null
}
