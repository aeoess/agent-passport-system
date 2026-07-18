// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0

import { hexToMultibase, multibaseToHex } from '../../core/did.js'

/**
 * Legacy APS self-certifying identifier support. New PassportV2 issuance uses
 * did:key by default; this parser exists so previously emitted did:aps values
 * remain verifiable without implying that their identifier survives rotation.
 */
export function legacyDidApsFromPublicKey(publicKeyHex: string): string {
  assertEd25519PublicKey(publicKeyHex)
  return `did:aps:${hexToMultibase(publicKeyHex)}`
}

export function publicKeyFromLegacyDidAps(did: string): string {
  if (!/^did:aps:z[1-9A-HJ-NP-Za-km-z]+$/.test(did)) {
    throw new Error('Invalid did:aps identifier')
  }
  const publicKey = multibaseToHex(did.slice('did:aps:'.length))
  assertEd25519PublicKey(publicKey)
  if (legacyDidApsFromPublicKey(publicKey) !== did) {
    throw new Error('Non-canonical did:aps identifier')
  }
  return publicKey
}

export function publicKeyFromDidKey(did: string): string {
  if (!/^did:key:z[1-9A-HJ-NP-Za-km-z]+$/.test(did)) throw new Error('Invalid did:key identifier')
  const publicKey = multibaseToHex(did.slice('did:key:'.length))
  assertEd25519PublicKey(publicKey)
  if (didKeyFromPublicKey(publicKey) !== did) throw new Error('Non-canonical did:key identifier')
  return publicKey
}

export function didKeyFromPublicKey(publicKeyHex: string): string {
  assertEd25519PublicKey(publicKeyHex)
  return `did:key:${hexToMultibase(publicKeyHex)}`
}

export function selfCertifyingPublicKey(did: string): string | null {
  if (did.startsWith('did:key:')) return publicKeyFromDidKey(did)
  if (did.startsWith('did:aps:')) return publicKeyFromLegacyDidAps(did)
  return null
}

export function defaultVerificationMethod(agentId: string): string {
  if (agentId.startsWith('did:key:')) return `${agentId}#${agentId.slice('did:key:'.length)}`
  return `${agentId}#key-1`
}

function assertEd25519PublicKey(value: string): void {
  if (!/^[0-9a-f]{64}$/.test(value)) throw new Error('Invalid Ed25519 public key')
}
