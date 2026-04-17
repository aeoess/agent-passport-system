// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
/**
 * Entity Verification v1.0 — pure primitives
 *
 * Adopted from WG conformance testing (OATR #2). Behaviors:
 *   1. Fail-closed: if DID resolution fails, proof MUST NOT be created
 *      with unbound identity
 *   2. Explicit did_resolution_status: 'live' | 'cached' | 'failed' on
 *      every result
 *
 * The DID resolution cache (cacheDIDResolution / getCachedDIDResolution /
 * clearDIDCache) MOVED to @aeoess/gateway src/sdk-migrated/core/did-cache.ts
 * on 2026-04-17. Caching is gateway product policy — TTL choice and
 * cross-tenant isolation are operational concerns, not protocol primitives.
 *
 * verifyEntityChain in this module is pure: it does live DID resolution
 * only. To get the cache-with-staleness behavior described in the original
 * WG paper, callers wrap this function with the gateway's CachedEntityResolver
 * (or any caller-supplied cache).
 */

import { createHash } from 'node:crypto'
import { resolveDID, isValidDID } from './did.js'
import type {
  DIDResolutionStatus, DIDResolutionCacheEntry,
  PublicProofSurface, EntityVerificationResult,
} from '../types/did.js'

// ═══════════════════════════════════════
// Sender ID derivation (QSP-1 §4)
// ═══════════════════════════════════════

/** Compute sender_id per QSP-1 §4: Trunc16(SHA-256(pubkey)) */
export function computeSenderId(publicKeyHex: string): string {
  return createHash('sha256')
    .update(Buffer.from(publicKeyHex, 'hex'))
    .digest().subarray(0, 16).toString('hex')
}

// ═══════════════════════════════════════
// DID Cache — moved to gateway
// ═══════════════════════════════════════

const CACHE_MIGRATED_MSG =
  'DID resolution cache moved to @aeoess/gateway ' +
  'src/sdk-migrated/core/did-cache.ts (2026-04-17). SDK keeps verifyEntityChain ' +
  'as a pure live-resolution primitive; wrap it with a caller-supplied cache.'

export function cacheDIDResolution(
  _did: string, _publicKey: string, _ttlMs?: number,
): DIDResolutionCacheEntry {
  throw new Error(CACHE_MIGRATED_MSG)
}

export function getCachedDIDResolution(_did: string): DIDResolutionCacheEntry | null {
  throw new Error(CACHE_MIGRATED_MSG)
}

export function clearDIDCache(): void {
  throw new Error(CACHE_MIGRATED_MSG)
}

// ═══════════════════════════════════════
// Entity Verification Chain — pure
// ═══════════════════════════════════════

/**
 * Verify the full entity chain: DID → public key → entity → status.
 *
 * Pure primitive — performs live DID resolution every call. To cache,
 * wrap this function or supply a memoized entityLookup function.
 *
 * @param did - Agent's DID (did:aps:... or did:key:...)
 * @param entityLookup - Function that fetches entity from Corpo API or equivalent
 * @param opts.entityId - Entity identifier to look up
 */
export async function verifyEntityChain(
  did: string,
  entityLookup: (entityId: string) => Promise<PublicProofSurface | null>,
  opts: {
    entityId: string
    /** Accepted for backward compatibility; ignored — caching is gateway concern. */
    allowCached?: boolean
    /** Accepted for backward compatibility; ignored — caching is gateway concern. */
    cacheTtlMs?: number
  },
): Promise<EntityVerificationResult> {
  const errors: string[] = []
  let resolvedKey: string | null = null
  let status: DIDResolutionStatus = 'failed'
  let resolvedAt: string | null = null

  // Step 1: DID Resolution (live only)
  if (isValidDID(did)) {
    try {
      const resolution = resolveDID(did)
      if (resolution.didDocument) {
        const vm = resolution.didDocument.verificationMethod?.[0]
        if (vm?.publicKeyMultibase) {
          const { multibaseToHex } = await import('./did.js')
          resolvedKey = multibaseToHex(vm.publicKeyMultibase)
          status = 'live'
          resolvedAt = new Date().toISOString()
        }
      }
    } catch {
      // Live resolution failed.
    }
  } else {
    errors.push(`Invalid DID: ${did}`)
  }

  // FAIL-CLOSED: if DID resolution failed, stop here.
  if (!resolvedKey) {
    errors.push('DID resolution failed. Fail-closed: proof MUST NOT be created.')
    return {
      verified: false,
      didResolutionStatus: 'failed',
      resolvedPublicKey: null,
      entity: null,
      resolvedAt: null,
      senderId: null,
      errors,
    }
  }

  // Step 2: Sender ID derivation (QSP-1 §4)
  const senderId = computeSenderId(resolvedKey)

  // Step 3: Entity verification via lookup function
  let entity: PublicProofSurface | null = null
  try {
    entity = await entityLookup(opts.entityId)
  } catch (e: any) {
    errors.push(`Entity lookup failed: ${e.message || e}`)
  }

  if (!entity) {
    errors.push(`Entity "${opts.entityId}" not found or lookup failed`)
    return {
      verified: false,
      didResolutionStatus: status,
      resolvedPublicKey: resolvedKey,
      entity: null,
      resolvedAt,
      senderId,
      errors,
    }
  }

  // Step 4: Entity status check
  if (entity.status !== 'active') {
    errors.push(`Entity "${opts.entityId}" status is "${entity.status}", not "active"`)
    return {
      verified: false,
      didResolutionStatus: status,
      resolvedPublicKey: resolvedKey,
      entity,
      resolvedAt,
      senderId,
      errors,
    }
  }

  return {
    verified: true,
    didResolutionStatus: status,
    resolvedPublicKey: resolvedKey,
    entity,
    resolvedAt,
    senderId,
    errors: [],
  }
}
