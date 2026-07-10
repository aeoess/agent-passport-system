// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0
// ══════════════════════════════════════════════════════════════════
// CyclesKeyResolver: reference KeyResolver implementation (M3)
// ══════════════════════════════════════════════════════════════════
// A single resolver that handles three locator families behind ONE
// interface:
//   - did:key   : self-certifying, no network (existing fromDIDKey).
//   - did:web   : fetch the DID Document (existing resolveDIDWeb),
//                 select a verificationMethod by fragment.
//   - did:cycles / direct jwksUrl : fetch a JWKS, select an Ed25519
//                 key by kid (this module's did-cycles mapping).
//
// The existing did:key/did:web logic in core/did-interop.ts is reused
// UNCHANGED and registered behind this interface. No existing function
// is modified.
//
// This is a REFERENCE resolver, not a hosted service. It holds an
// in-process TTL cache with distinct hit/miss handling, an explicit
// fail-open vs fail-closed policy defaulting to fail-closed, and a
// fetch timeout mirroring the did:web resolver. It does not aggregate
// across tenants, expose an endpoint, or alert.
// ══════════════════════════════════════════════════════════════════

import { createHash } from 'node:crypto'
import { fromDIDKey, resolveDIDWeb } from '../../core/did-interop.js'
import { multibaseToHex } from '../../core/did.js'
import type { ScopeOfClaim } from '../accountability/types/base.js'
import {
  asJWKS,
  cyclesJwksUrl,
  isDIDCycles,
  parseDIDCycles,
  selectKey,
} from './did-cycles.js'
import { decodeBase64Url, bytesToHex } from './base64url.js'
import {
  DEFAULT_CACHE_POLICY,
  DEFAULT_TIMEOUT_MS,
  type CachePolicy,
  type FailurePolicy,
  type KeyLocator,
  type KeyResolution,
  type KeyResolver,
  type KeyResolverConfig,
} from './types.js'

interface CacheEntry {
  expiresAt: number
  resolution: KeyResolution
}

/** Scope-of-claim for a successful key resolution. */
function resolvedScope(): ScopeOfClaim {
  return {
    asserts:
      'aps:key.resolve. At resolution time, the named DID or JWKS endpoint asserted this Ed25519 public key under the requested kid.',
    does_not_assert: [
      'the key is uncompromised or under sole control of the named party',
      'the endpoint asserts the same key at any later time',
      'any signature made with the key is authorized',
    ],
    capture_mode: 'gateway_observed',
    completeness: 'complete',
    self_attested: false,
  }
}

/** Scope-of-claim for a degraded (fail-open, unreachable) outcome. */
function degradedScope(): ScopeOfClaim {
  return {
    asserts:
      'aps:key.resolve:degraded. The key endpoint was unreachable and a fail-open policy produced a non-rejecting result with NO key material.',
    does_not_assert: [
      'any public key was resolved',
      'a positive verification (a degraded result MUST NOT be read as valid)',
      'the endpoint or key exists at all',
    ],
    capture_mode: 'unknown',
    completeness: 'best_effort',
    self_attested: false,
  }
}

export class CyclesKeyResolver implements KeyResolver {
  private readonly failurePolicy: FailurePolicy
  private readonly timeoutMs: number
  private readonly cachePolicy: CachePolicy
  private readonly fetchImpl: typeof fetch
  private readonly now: () => number
  private readonly cache = new Map<string, CacheEntry>()

  constructor(config: KeyResolverConfig = {}) {
    this.failurePolicy = config.failurePolicy ?? 'closed'
    this.timeoutMs = config.timeoutMs ?? DEFAULT_TIMEOUT_MS
    this.cachePolicy = { ...DEFAULT_CACHE_POLICY, ...(config.cache ?? {}) }
    // Bind to preserve `this` when a global fetch is used.
    this.fetchImpl = config.fetchImpl ?? ((...a: Parameters<typeof fetch>) => fetch(...a))
    this.now = config.now ?? Date.now
  }

  canResolve(locator: KeyLocator): boolean {
    if (locator.jwksUrl) return true
    const did = locator.did
    if (!did) return false
    // did:cycles is handled here, but is hash-bound: it resolves only with a
    // serverId (the resolver checks sha256(serverId) against the DID subject and
    // derives the JWKS URL). A did:cycles locator without serverId fails closed
    // in resolve(); canResolve reports the method is handled.
    return did.startsWith('did:key:') || did.startsWith('did:web:') || did.startsWith('did:cycles:')
  }

  async resolve(locator: KeyLocator): Promise<KeyResolution> {
    if (!locator || (!locator.did && !locator.jwksUrl)) {
      return this.fail('unsupported', 'locator must carry a did or a jwksUrl')
    }
    const did = locator.did

    // did:key: self-certifying, no network, no cache needed.
    if (did && did.startsWith('did:key:')) {
      return this.resolveDidKey(did)
    }
    // did:web: fetch the DID Document, pick a verificationMethod.
    if (did && did.startsWith('did:web:')) {
      return this.resolveDidWeb(did, locator.kid)
    }
    // did:cycles or a direct JWKS URL: JWKS path with caching.
    if ((did && isDIDCycles(did)) || locator.jwksUrl) {
      return this.resolveJwks(locator)
    }
    return this.fail('unsupported', `unsupported locator: ${did ?? locator.jwksUrl}`)
  }

  // ── did:key (existing logic, unchanged) ──────────────────────────

  private resolveDidKey(did: string): KeyResolution {
    try {
      // Strip any DID-URL fragment before handing to fromDIDKey.
      const core = did.split('#')[0]
      const hex = fromDIDKey(core)
      if (!/^[0-9a-f]{64}$/i.test(hex)) {
        return this.fail('malformed', 'did:key did not decode to a 32-byte key')
      }
      return {
        ok: true,
        status: 'resolved',
        publicKeyHex: hex.toLowerCase(),
        cacheHit: false,
        scope_of_claim: resolvedScope(),
      }
    } catch (err) {
      return this.fail('malformed', `did:key parse failed: ${safeMsg(err)}`)
    }
  }

  // ── did:web (existing resolveDIDWeb, unchanged) ──────────────────

  private async resolveDidWeb(did: string, explicitKid?: string): Promise<KeyResolution> {
    const cacheKey = `web:${did}|kid:${explicitKid ?? ''}`
    const cached = this.readCache(cacheKey)
    if (cached) return cached

    const hashIndex = did.indexOf('#')
    const fragment = hashIndex >= 0 ? did.slice(hashIndex + 1) : undefined
    const core = hashIndex >= 0 ? did.slice(0, hashIndex) : did
    const wantKid = this.reconcileKid(fragment, explicitKid)
    if (wantKid === AMBIGUOUS) {
      return this.fail('ambiguous', 'did-url fragment and explicit kid disagree')
    }

    let doc: Record<string, unknown>
    try {
      doc = (await resolveDIDWeb(core)) as Record<string, unknown>
    } catch (err) {
      return this.unreachable(cacheKey, `did:web fetch failed: ${safeMsg(err)}`)
    }

    const methods = doc.verificationMethod
    if (!Array.isArray(methods) || methods.length === 0) {
      return this.storeFail(cacheKey, 'malformed', 'did:web document has no verificationMethod')
    }
    const selected = this.selectVerificationMethod(methods, core, wantKid)
    if ('error' in selected) {
      return this.storeFail(cacheKey, selected.error.status, selected.error.reason)
    }
    const res: KeyResolution = {
      ok: true,
      status: 'resolved',
      publicKeyHex: selected.hex,
      kid: selected.kid,
      cacheHit: false,
      scope_of_claim: resolvedScope(),
    }
    this.writeCache(cacheKey, res, this.cachePolicy.ttlMs)
    return res
  }

  private selectVerificationMethod(
    methods: unknown[],
    coreDid: string,
    wantKid?: string,
  ):
    | { hex: string; kid?: string }
    | { error: { status: 'not_found' | 'ambiguous' | 'malformed'; reason: string } } {
    const candidates: { id: string; hex: string }[] = []
    for (const m of methods) {
      if (!m || typeof m !== 'object') continue
      const vm = m as Record<string, unknown>
      const id = typeof vm.id === 'string' ? vm.id : ''
      const hex = vmToHex(vm)
      if (hex) candidates.push({ id, hex })
    }
    if (candidates.length === 0) {
      return { error: { status: 'malformed', reason: 'no usable Ed25519 verificationMethod' } }
    }
    if (wantKid !== undefined) {
      // Match the fragment against the verificationMethod id fragment.
      const matches = candidates.filter(c => fragmentOf(c.id) === wantKid)
      if (matches.length === 0) {
        return { error: { status: 'not_found', reason: `no verificationMethod #${wantKid}` } }
      }
      if (matches.length > 1) {
        return { error: { status: 'ambiguous', reason: `duplicate verificationMethod #${wantKid}` } }
      }
      return { hex: matches[0].hex, kid: wantKid }
    }
    if (candidates.length > 1) {
      return { error: { status: 'ambiguous', reason: 'multiple verificationMethods and no fragment' } }
    }
    void coreDid
    return { hex: candidates[0].hex, kid: fragmentOf(candidates[0].id) }
  }

  // ── did:cycles / direct JWKS (this module's mapping) ─────────────

  private async resolveJwks(locator: KeyLocator): Promise<KeyResolution> {
    let fragmentKid: string | undefined
    let jwksUrl: string | undefined

    if (locator.did && isDIDCycles(locator.did)) {
      // did:cycles is HASH-BOUND. The resolver enforces the binding itself and
      // derives the JWKS URL — it never accepts an unbound did:cycles:
      //   1. parse the subject hash + kid fragment;
      //   2. require server_id, and check sha256(server_id) === subject hash
      //      (fail closed on mismatch) — anchors authority to that server_id;
      //   3. derive the JWKS URL from server_id (cyclesJwksUrl), NOT from a
      //      caller-supplied URL (which could point at a different server);
      //   4. the validity-window gate (issued_at_ms) is MANDATORY here.
      let serverIdHash: string
      try {
        ;({ serverIdHash, kid: fragmentKid } = parseDIDCycles(locator.did))
      } catch (err) {
        return this.fail('unsupported', `did:cycles parse failed: ${safeMsg(err)}`)
      }
      // The canonical signer_did form is did:cycles:<hash>#<kid>; the fragment
      // names the key in the set and is REQUIRED for resolution.
      if (!fragmentKid) {
        return this.fail('unsupported', 'did:cycles requires a #<kid> fragment')
      }
      if (!locator.serverId) {
        return this.fail('unsupported', 'did:cycles requires serverId to establish the sha256 binding')
      }
      const computed = createHash('sha256').update(locator.serverId, 'utf8').digest('hex')
      if (computed !== serverIdHash) {
        return this.fail(
          'not_found',
          'did:cycles subject does not match sha256(server_id) — signer not bound to this server',
        )
      }
      if (typeof locator.issuedAtMs !== 'number' || !Number.isInteger(locator.issuedAtMs)) {
        return this.fail('not_found', 'did:cycles resolution requires an integer issuedAtMs (validity window)')
      }
      jwksUrl = cyclesJwksUrl(locator.serverId)
    } else {
      jwksUrl = locator.jwksUrl
    }

    if (!jwksUrl) {
      return this.fail('unsupported', 'no did:cycles (with serverId) or jwksUrl present')
    }

    // HTTPS only.
    if (!jwksUrl.startsWith('https://')) {
      return this.fail('unsupported', 'JWKS endpoint must be https')
    }

    const wantKid = this.reconcileKid(fragmentKid, locator.kid)
    if (wantKid === AMBIGUOUS) {
      return this.fail('ambiguous', 'did:cycles fragment and explicit kid disagree')
    }

    // Cache the SELECTED key. Selection now depends on the validity window
    // (issuedAtMs) and the raw-hex signer match (publicKeyHex) too, so both
    // MUST be in the cache key — otherwise a key selected for one receipt's
    // issuance window could be wrongly reused for another across a rotation
    // (the [nbf, exp) gate would be bypassed). (A JWKS-document cache keyed by
    // URL, with selection re-run per call, would also dedup the fetch across
    // distinct issuance times — a future optimization.)
    const cacheKey =
      `jwks:${jwksUrl}|kid:${wantKid ?? ''}` +
      `|iat:${locator.issuedAtMs ?? ''}|pk:${locator.publicKeyHex?.toLowerCase() ?? ''}`
    const cached = this.readCache(cacheKey)
    if (cached) return cached

    // Fetch.
    let response: Response
    try {
      response = await this.fetchImpl(jwksUrl, {
        headers: { Accept: 'application/jwk-set+json, application/json' },
        signal: AbortSignal.timeout(this.timeoutMs),
        redirect: 'error',
      })
    } catch (err) {
      return this.unreachable(cacheKey, `JWKS fetch failed: ${safeMsg(err)}`)
    }
    if (!response.ok) {
      return this.unreachable(cacheKey, `JWKS endpoint returned HTTP ${response.status}`)
    }

    let body: unknown
    try {
      body = await response.json()
    } catch {
      // A 200 with a non-JSON body is treated as unreachable/transient:
      // the endpoint answered but did not deliver a parseable document.
      return this.unreachable(cacheKey, 'JWKS body was not valid JSON')
    }

    const jwks = asJWKS(body)
    if (!jwks) {
      // Loaded but structurally wrong: fail-closed even under fail-open.
      return this.storeFail(cacheKey, 'malformed', 'JWKS missing non-empty keys[] array')
    }

    const selection = selectKey(jwks, {
      kid: wantKid,
      issuedAtMs: locator.issuedAtMs,
      publicKeyHex: locator.publicKeyHex,
    })
    if (!selection.ok) {
      return this.storeFail(cacheKey, selection.status, selection.reason)
    }
    const res: KeyResolution = {
      ok: true,
      status: 'resolved',
      publicKeyHex: selection.publicKeyHex,
      kid: selection.kid,
      cacheHit: false,
      scope_of_claim: resolvedScope(),
    }
    this.writeCache(cacheKey, res, this.cachePolicy.ttlMs)
    return res
  }

  // ── kid reconciliation ───────────────────────────────────────────

  /** Reconcile a DID-URL fragment kid with an explicit locator.kid.
   *  Returns the agreed kid, undefined if neither is set, or the
   *  AMBIGUOUS sentinel when the two are both set and disagree. */
  private reconcileKid(fragment?: string, explicit?: string): string | undefined | typeof AMBIGUOUS {
    if (fragment !== undefined && explicit !== undefined) {
      return fragment === explicit ? fragment : AMBIGUOUS
    }
    return fragment ?? explicit
  }

  // ── cache ────────────────────────────────────────────────────────

  private readCache(key: string): KeyResolution | undefined {
    const entry = this.cache.get(key)
    if (!entry) return undefined
    if (this.now() >= entry.expiresAt) {
      this.cache.delete(key)
      return undefined
    }
    // Re-anchor LRU ordering on hit.
    this.cache.delete(key)
    this.cache.set(key, entry)
    return { ...entry.resolution, cacheHit: true }
  }

  private writeCache(key: string, resolution: KeyResolution, ttlMs: number): void {
    if (ttlMs <= 0) return
    // Never cache a key with its transient cacheHit flag set true.
    const stored: KeyResolution = { ...resolution, cacheHit: false }
    this.cache.set(key, { expiresAt: this.now() + ttlMs, resolution: stored })
    this.evictIfNeeded()
  }

  private evictIfNeeded(): void {
    while (this.cache.size > this.cachePolicy.maxEntries) {
      const oldest = this.cache.keys().next().value
      if (oldest === undefined) break
      this.cache.delete(oldest)
    }
  }

  /** Inspect current cache size (observability / tests). */
  cacheSize(): number {
    return this.cache.size
  }

  /** Clear the cache (operational reset / tests). */
  clearCache(): void {
    this.cache.clear()
  }

  // ── failure helpers ──────────────────────────────────────────────

  private fail(status: KeyResolution['status'], reason: string): KeyResolution {
    return { ok: false, status, reason, cacheHit: false }
  }

  private storeFail(
    cacheKey: string,
    status: 'not_found' | 'ambiguous' | 'malformed',
    reason: string,
  ): KeyResolution {
    const res = this.fail(status, reason)
    // Cache negative results briefly so a miss is not re-fetched in a
    // hot loop. A cached miss is NEVER promoted to a key on read.
    this.writeCache(cacheKey, res, this.cachePolicy.negativeTtlMs)
    return res
  }

  /**
   * Handle an unreachable / transient-network condition under the
   * configured failure policy.
   *  - fail-closed (default): no key; status 'unreachable'; rejects.
   *  - fail-open: a documented-degraded result with NO key material and
   *    degraded=true. It MUST NOT be read as a positive verification.
   * In both modes the result carries no publicKeyHex.
   */
  private unreachable(cacheKey: string, reason: string): KeyResolution {
    if (this.failurePolicy === 'open') {
      const res: KeyResolution = {
        ok: false,
        status: 'unreachable',
        degraded: true,
        reason: `fail-open degraded: ${reason}`,
        cacheHit: false,
        scope_of_claim: degradedScope(),
      }
      // Cache the degraded miss briefly too.
      this.writeCache(cacheKey, res, this.cachePolicy.negativeTtlMs)
      return res
    }
    const res: KeyResolution = {
      ok: false,
      status: 'unreachable',
      degraded: false,
      reason: `fail-closed: ${reason}`,
      cacheHit: false,
    }
    this.writeCache(cacheKey, res, this.cachePolicy.negativeTtlMs)
    return res
  }
}

// ── module-private helpers ─────────────────────────────────────────

const AMBIGUOUS = Symbol('kid-ambiguous')

function safeMsg(err: unknown): string {
  return err instanceof Error ? err.message : String(err)
}

/** Fragment after the first '#', or undefined. */
function fragmentOf(id: string): string | undefined {
  const i = id.indexOf('#')
  return i >= 0 ? id.slice(i + 1) : undefined
}

/**
 * Extract a 32-byte Ed25519 public key (hex) from a DID-Document
 * verificationMethod, supporting both publicKeyMultibase (the shape
 * passportToDIDDocument emits) and publicKeyJwk (OKP/Ed25519).
 * Returns null if the method does not carry a usable Ed25519 key.
 */
function vmToHex(vm: Record<string, unknown>): string | null {
  // publicKeyMultibase (Ed25519VerificationKey2020 / multibase).
  if (typeof vm.publicKeyMultibase === 'string') {
    try {
      const hex = multibaseToHex(vm.publicKeyMultibase)
      if (/^[0-9a-f]{64}$/i.test(hex)) return hex.toLowerCase()
    } catch {
      // fall through to publicKeyJwk
    }
  }
  // publicKeyJwk (OKP/Ed25519).
  const jwk = vm.publicKeyJwk
  if (jwk && typeof jwk === 'object') {
    const k = jwk as Record<string, unknown>
    if (k.kty === 'OKP' && k.crv === 'Ed25519' && typeof k.x === 'string') {
      const bytes = decodeBase64Url(k.x)
      if (bytes && bytes.length === 32) return bytesToHex(bytes)
    }
  }
  return null
}
