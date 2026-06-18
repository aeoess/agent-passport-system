// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// ══════════════════════════════════════════════════════════════════
// KeyResolver: interface, policy, and result types (M3)
// ══════════════════════════════════════════════════════════════════
// A KeyResolver maps a key locator (a DID, a DID URL with a #kid
// fragment, or a direct JWKS endpoint plus an optional kid) to a
// single Ed25519 verification key, expressed as the 64-char hex
// string the existing crypto/keys.ts verify() consumes.
//
// This file defines ONLY the protocol surface. It introduces no
// network behavior, no registry, and no hosted service. Concrete
// resolution lives in resolver.ts (reference implementation) and
// did-cycles.ts (the did:cycles -> JWKS mapping).
//
// SECURITY POSTURE: every resolver in this module defaults to
// fail-closed. "Could not fetch the key" is never "signature valid".
// ══════════════════════════════════════════════════════════════════

import type { ScopeOfClaim } from '../accountability/types/base.js'

/**
 * RFC 7517 JSON Web Key, narrowed to the OKP / Ed25519 signing case
 * (RFC 8037). This resolver supports no other key type. X-curve
 * members (X25519/X448) are ECDH key-agreement keys, not signature
 * keys, and are rejected at selection time.
 */
export interface Ed25519JWK {
  /** RFC 8037: MUST be "OKP" (Octet Key Pair). */
  kty: 'OKP'
  /** RFC 8037: MUST be "Ed25519". */
  crv: 'Ed25519'
  /** base64url (no padding) of the raw 32-byte Ed25519 public key. */
  x: string
  /** Opaque key selector. Optional in RFC 7517, but REQUIRED here for
   *  unambiguous rotation. Compared by exact, case-sensitive equality. */
  kid?: string
  /** If present MUST be "sig". An "enc" key is rejected. */
  use?: 'sig' | string
  /** If present MUST be "EdDSA". */
  alg?: 'EdDSA' | string
  /** If present MUST include "verify". */
  key_ops?: string[]
  /** Cycles validity window — valid-from, epoch ms, INCLUSIVE. Present on
   *  did:cycles JWK Sets; selection by window requires it (see selectKey).
   *  Not an RFC 7517 member; ignored by non-cycles consumers. */
  cycles_nbf_ms?: number
  /** Cycles validity window — valid-until, epoch ms, EXCLUSIVE. Absent/null
   *  ⇒ open-ended (the active key). */
  cycles_exp_ms?: number | null
  /** Advisory rotation status; selection is by window, never by status. */
  status?: 'active' | 'retired' | string
}

/**
 * RFC 7517 JWK Set. The single REQUIRED member is `keys`, an array of
 * JWK objects. A published verification set must contain public keys
 * only: a JWK carrying a private `d` member is a misconfiguration (leaked
 * private material), so it is REJECTED as a signing candidate and never
 * selected — fail-closed rather than silently stripped-and-used.
 */
export interface JWKS {
  keys: Ed25519JWK[]
}

/**
 * How a resolution finished. `ok` resolutions carry a key; every other
 * status carries no key and a verifier MUST reject.
 *
 *  - 'resolved'      : a single Ed25519 key was selected.
 *  - 'not_found'     : endpoint loaded but no candidate matched the kid.
 *  - 'ambiguous'     : more than one candidate matched (or no kid and
 *                      more than one signing key). Fail-closed.
 *  - 'malformed'     : endpoint loaded but the body / JWKS / JWK / x
 *                      was structurally invalid. Fail-closed even under
 *                      fail-open: a body that loads but is wrong is NOT
 *                      a transient-network condition.
 *  - 'unreachable'   : network error, timeout, non-200, or non-JSON
 *                      body. The ONLY status fail-open may relax.
 *  - 'unsupported'   : the locator named a method this resolver does
 *                      not handle.
 */
export type KeyResolutionStatus =
  | 'resolved'
  | 'not_found'
  | 'ambiguous'
  | 'malformed'
  | 'unreachable'
  | 'unsupported'

/**
 * Result of a single resolution. When `ok` is true, `publicKeyHex` is
 * a 64-char lowercase hex Ed25519 public key consumable by
 * crypto/keys.ts verify(). When `ok` is false, `publicKeyHex` is
 * undefined and `status`/`reason` explain why; the caller MUST treat
 * this as "no key" and fail the signature check closed.
 *
 * `degraded` is true only when a fail-open policy turned an
 * 'unreachable' condition into a non-rejecting outcome. A degraded
 * result MUST NOT be read as a positive verification.
 */
export interface KeyResolution {
  ok: boolean
  status: KeyResolutionStatus
  /** 64-char lowercase hex Ed25519 public key, present iff ok. */
  publicKeyHex?: string
  /** The kid that was selected (echoed back), when applicable. */
  kid?: string
  /** Whether cache served this result, for observability. */
  cacheHit?: boolean
  /** True iff a fail-open policy produced a non-rejecting degraded
   *  outcome from an unreachable endpoint. */
  degraded?: boolean
  /** Human-readable, non-sensitive explanation. */
  reason?: string
  /** Scope-of-claim for any resolution that feeds a receipt check. */
  scope_of_claim?: ScopeOfClaim
}

/**
 * What to resolve. Exactly one of `did` or `jwksUrl` is the anchor.
 *  - `did`     : a DID or DID URL. A `#fragment` is read as the kid.
 *  - `jwksUrl` : a direct https JWKS endpoint (reference / testing).
 *  - `kid`     : explicit kid selector. When both a DID-URL fragment
 *                and an explicit `kid` are present they MUST agree, or
 *                resolution fails closed (ambiguous request).
 */
export interface KeyLocator {
  did?: string
  jwksUrl?: string
  kid?: string
  /** Cycles window selection: pick the key whose
   *  [cycles_nbf_ms, cycles_exp_ms) covers this issuance time (epoch ms).
   *  When set, selection is window-gated; when absent, legacy kid-only. */
  issuedAtMs?: number
  /** Cycles raw-hex signer match: when the envelope's signer_did is a raw
   *  64-hex Ed25519 key (not a did:cycles), select the JWK whose `x` decodes
   *  to these bytes (confirming the raw key is published) rather than by kid. */
  publicKeyHex?: string
  /** Cycles authority binding: the envelope's `server_id`. REQUIRED for a
   *  `did:cycles` locator — the resolver checks `sha256(server_id)` against the
   *  DID subject hash and derives the JWKS URL from it (cyclesJwksUrl), failing
   *  closed on mismatch. A `did:cycles` locator without `serverId` is rejected
   *  (the binding cannot be established). */
  serverId?: string
}

/**
 * Failure posture.
 *  - 'closed' (DEFAULT): any resolution failure yields no key; the
 *    signature check rejects. This is the only safe default.
 *  - 'open': an explicit, opt-in, documented-degraded mode. It relaxes
 *    ONLY the 'unreachable'/transient-network case into a degraded
 *    result. A malformed JWKS, an absent kid, or an unsupported key
 *    type STILL fails closed. fail-open is never "accept anything".
 */
export type FailurePolicy = 'closed' | 'open'

/**
 * Caching policy. The cache distinguishes hits from misses and never
 * promotes a cached negative/miss into a key.
 *  - `ttlMs`         : positive-result lifetime in ms.
 *  - `negativeTtlMs` : miss/negative lifetime in ms (default: short).
 *  - `maxEntries`    : bound on distinct cache keys (LRU-style evict).
 */
export interface CachePolicy {
  ttlMs: number
  negativeTtlMs: number
  maxEntries: number
}

/**
 * Resolver-wide configuration.
 *  - `failurePolicy` : defaults to 'closed'.
 *  - `timeoutMs`     : fetch timeout, mirrors the did:web resolver.
 *  - `cache`         : caching policy (TTL hit/miss).
 *  - `fetchImpl`     : injectable fetch for tests; defaults to global.
 *  - `now`           : injectable clock for tests; defaults to Date.now.
 */
export interface KeyResolverConfig {
  failurePolicy?: FailurePolicy
  timeoutMs?: number
  cache?: Partial<CachePolicy>
  fetchImpl?: typeof fetch
  now?: () => number
}

/**
 * The standardized KeyResolver interface. A resolver answers "which
 * public key does this locator assert?" and nothing more. It performs
 * no signature verification itself; the caller passes the returned
 * `publicKeyHex` to crypto/keys.ts verify().
 */
export interface KeyResolver {
  /** True iff this resolver handles the given locator's method. */
  canResolve(locator: KeyLocator): boolean
  /** Resolve a locator to a single Ed25519 verification key. Always
   *  resolves the promise; failure is reported via the result's
   *  status/ok, never by rejecting (except for programmer errors). */
  resolve(locator: KeyLocator): Promise<KeyResolution>
}

/** Default fetch timeout, matching the existing did:web resolver. */
export const DEFAULT_TIMEOUT_MS = 10_000

/** Conservative cache defaults: 5 min positive, 30 s negative. */
export const DEFAULT_CACHE_POLICY: CachePolicy = {
  ttlMs: 5 * 60_000,
  negativeTtlMs: 30_000,
  maxEntries: 256,
}
