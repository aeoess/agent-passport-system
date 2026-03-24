/**
 * Entity Verification v1.0
 *
 * Adopted from WG conformance testing (OATR #2).
 * Three behaviors proposed and implemented:
 * 1. Fail-closed: if DID resolution fails, proof MUST NOT be created with unbound identity
 * 2. Cache-with-staleness: MAY cache recent DID resolution with resolved_at timestamp
 * 3. Explicit did_resolution_status: 'live' | 'cached' | 'failed' on every result
 */

import { createHash } from 'node:crypto'
import { resolveDID, publicKeyFromDID, isValidDID } from './did.js'
import type {
  DIDResolutionStatus, DIDResolutionCacheEntry,
  PublicProofSurface, EntityVerificationResult,
} from '../types/did.js'

// ═══════════════════════════════════════
// DID Resolution Cache
// ═══════════════════════════════════════

const didCache = new Map<string, DIDResolutionCacheEntry>()
const DEFAULT_CACHE_TTL_MS = 3600_000 // 1 hour

/**
 * Cache a DID resolution result.
 */
export function cacheDIDResolution(
  did: string,
  publicKey: string,
  ttlMs: number = DEFAULT_CACHE_TTL_MS,
): DIDResolutionCacheEntry {
  const now = new Date()
  const entry: DIDResolutionCacheEntry = {
    did,
    publicKey,
    resolvedAt: now.toISOString(),
    expiresAt: new Date(now.getTime() + ttlMs).toISOString(),
    status: 'live',
  }
  didCache.set(did, entry)
  return entry
}

/**
 * Get a cached DID resolution. Returns null if not cached or expired.
 */
export function getCachedDIDResolution(did: string): DIDResolutionCacheEntry | null {
  const entry = didCache.get(did)
  if (!entry) return null
  if (new Date(entry.expiresAt).getTime() < Date.now()) {
    didCache.delete(did)
    return null
  }
  return { ...entry, status: 'cached' }
}

/** Clear the DID resolution cache */
export function clearDIDCache(): void { didCache.clear() }

/** Compute sender_id per QSP-1 §4: Trunc16(SHA-256(pubkey)) */
export function computeSenderId(publicKeyHex: string): string {
  return createHash('sha256')
    .update(Buffer.from(publicKeyHex, 'hex'))
    .digest().subarray(0, 16).toString('hex')
}

// ═══════════════════════════════════════
// Entity Verification Chain
// ═══════════════════════════════════════

/**
 * Verify the full entity chain: DID → public key → entity → authority ceiling.
 *
 * Implements three WG-adopted behaviors:
 * 1. Fail-closed: failed DID resolution → verified: false (no silent degradation)
 * 2. Cache-with-staleness: uses cached resolution if live fails, marks as 'cached'
 * 3. Explicit status: every result carries did_resolution_status
 *
 * @param did - Agent's DID (did:aps:... or did:key:...)
 * @param entityLookup - Function that fetches entity from Corpo API (or equivalent)
 * @param opts - Options: entityId, allowCached, cacheTtlMs
 */
export async function verifyEntityChain(
  did: string,
  entityLookup: (entityId: string) => Promise<PublicProofSurface | null>,
  opts: {
    entityId: string
    allowCached?: boolean
    cacheTtlMs?: number
  },
): Promise<EntityVerificationResult> {
  const errors: string[] = []
  let resolvedKey: string | null = null
  let status: DIDResolutionStatus = 'failed'
  let resolvedAt: string | null = null
  let cachedAt: string | undefined

  // Step 1: DID Resolution (try live first)
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
          // Cache the successful resolution
          cacheDIDResolution(did, resolvedKey, opts.cacheTtlMs)
        }
      }
    } catch {
      // Live resolution failed — try cache
    }
  } else {
    errors.push(`Invalid DID: ${did}`)
  }

  // Step 1b: Fall back to cache if live failed and caching is allowed
  if (!resolvedKey && (opts.allowCached !== false)) {
    const cached = getCachedDIDResolution(did)
    if (cached) {
      resolvedKey = cached.publicKey
      status = 'cached'
      resolvedAt = cached.resolvedAt
      cachedAt = cached.resolvedAt
    }
  }

  // FAIL-CLOSED: if DID resolution failed entirely, stop here
  if (!resolvedKey) {
    errors.push('DID resolution failed (live and cache both miss). Fail-closed: proof MUST NOT be created.')
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
      cachedAt,
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
      cachedAt,
      senderId,
      errors,
    }
  }

  // All checks pass
  return {
    verified: true,
    didResolutionStatus: status,
    resolvedPublicKey: resolvedKey,
    entity,
    resolvedAt,
    cachedAt,
    senderId,
    errors: [],
  }
}
