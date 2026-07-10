// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0
// OAuth 2.1 / RFC 8693 Token Exchange delegation-token bridge.
//
// Bridge and profile only. An APS delegation chain is expressed as RFC 8693
// token-exchange `act` / `may_act` delegation claims, and recovered back, with
// authority and monotonic narrowing preserved in both directions. APS does not
// become OAuth; it maps onto it at the edge.
//
// A SPIFFE SVID is accepted as a did-method identity input (Section: SPIFFE).
//
// Spec basis: RFC 8693 (rfc-editor.org/rfc/rfc8693.html); SPIFFE-ID, X509-SVID,
// JWT-SVID standards (spiffe.io). Verbatim spec text is paraphrased in comments.
//
// ── Proof box ──
// Proves: an APS delegation chain can be expressed as RFC 8693 `act` / `may_act`
//   claims and recovered with the same principal, the same actor ordering and
//   authority, and authority that is no broader than the source (narrowing
//   preserved). A SPIFFE SVID validated here yields a stable did-method input.
// Does NOT prove: that an OAuth authorization server honored those claims, that
//   the presented tokens were themselves valid or signed, or that any authority
//   beyond what APS already carried was granted. The bridge mints no authority.

import { parseSPIFFEID } from '../../core/identity-bridge.js'
import type { ScopeOfClaim } from '../../v2/accountability/types/base.js'
import type {
  ActClaim,
  MayActClaim,
  TokenExchangeClaims,
  OAuthDelegationHop,
  DelegationChainView,
  RecoveredChain,
  JwtSvidView,
  SpiffeIdentityInput,
} from './types.js'

export * from './types.js'

// ── Scope-of-claim helper (dogfood the honest-scope declaration) ──

/**
 * The scope-of-claim this bridge attaches to any receipt that records a mapping.
 * Mirrors the proof box. Callers that mint a receipt around a bridge operation
 * SHOULD use this so the receipt does not over-claim.
 */
export function bridgeScopeOfClaim(): ScopeOfClaim {
  return {
    asserts:
      'An APS delegation chain was expressed as RFC 8693 act/may_act claims and is ' +
      'recoverable with the same principal, actor order, and no broader authority.',
    does_not_assert: [
      'That an OAuth authorization server accepted or honored these claims.',
      'That the input subject_token or actor_token was itself valid or signed.',
      'That any authority beyond what the APS chain already carried was granted.',
    ],
    capture_mode: 'self_attested',
    completeness: 'complete',
    self_attested: true,
  }
}

// ── Authority / narrowing helpers ──

/**
 * Returns true if `child` authority is no broader than `parent` (subset).
 * A wildcard '*' in the parent matches any child scope. This is the monotonic
 * narrowing invariant: authority may only decrease across a transfer point.
 */
export function isNarrowing(parent: string[], child: string[]): boolean {
  if (parent.includes('*')) return true
  const parentSet = new Set(parent)
  return child.every((s) => parentSet.has(s))
}

/**
 * Validate that a chain narrows monotonically from root grant to current actor.
 * Each hop's scope must be a subset of the previous hop's scope. Throws on the
 * first hop that widens authority.
 */
export function assertChainNarrows(chain: DelegationChainView): void {
  if (!chain.hops || chain.hops.length === 0) {
    throw new Error('Delegation chain must have at least one hop')
  }
  for (let i = 1; i < chain.hops.length; i++) {
    const parent = chain.hops[i - 1].scope
    const child = chain.hops[i].scope
    if (!isNarrowing(parent, child)) {
      throw new Error(
        `Delegation chain widens authority at hop ${i}: ` +
          `[${child.join(', ')}] is not a subset of [${parent.join(', ')}]`,
      )
    }
  }
}

/** Intersection of two scope sets, treating '*' in either as "all of the other". */
function intersectScopes(a: string[], b: string[]): string[] {
  if (a.includes('*')) return [...b]
  if (b.includes('*')) return [...a]
  const bSet = new Set(b)
  return a.filter((s) => bSet.has(s))
}

/**
 * Effective authority of a chain: the intersection of every hop's scope. This is
 * the narrowest set that survives all transfer points, i.e. what the current
 * actor may actually do. RFC 8693 transports this as the token `scope` member.
 */
export function effectiveScope(chain: DelegationChainView): string[] {
  let acc = chain.hops[0].scope.slice()
  for (let i = 1; i < chain.hops.length; i++) {
    acc = intersectScopes(acc, chain.hops[i].scope)
  }
  return acc
}

// ── APS chain → RFC 8693 claims ──

/**
 * Build the nested `act` claim for a chain. RFC 8693: the outermost `act` is the
 * current actor; nested `act` claims are prior (older) actors. Our hops are
 * ordered root-first, current-actor-last, so we walk from the LAST actor outward
 * and nest each earlier actor inside.
 *
 * Only the delegatees act, so the actor identities are the `delegatedTo` of each
 * hop. The root grant's `delegatedBy` is the principal and is carried as the
 * top-level `sub`, not as an actor.
 */
function buildActClaim(hops: OAuthDelegationHop[]): ActClaim {
  // Actor identities, oldest-first: each hop's delegatee.
  const actors = hops.map((h) => ({ sub: h.delegatedTo, iss: h.iss }))
  // Build from oldest to newest, nesting older inside newer.
  let current: ActClaim | undefined
  for (const a of actors) {
    const node: ActClaim = { sub: a.sub }
    if (a.iss) node.iss = a.iss
    if (current) node.act = current
    current = node
  }
  // `current` is now the newest actor with the chain nested inside.
  return current as ActClaim
}

/**
 * Express an APS delegation chain as RFC 8693 token-exchange claims.
 *
 * - top-level `sub` = the principal (party being acted upon).
 * - `act` = nested actor chain (current actor outermost, prior actors nested).
 * - `may_act` = the party permitted to become the NEXT actor, when supplied. This
 *   is a forward authorization, distinct from `act` which records who IS acting.
 * - `scope` = the chain's effective (narrowed) authority, space-delimited.
 *
 * This emits a delegation token (it carries `act`), never an impersonation token.
 * Authority is bounded by the narrowed effective scope. The chain MUST narrow
 * monotonically; this is asserted before mapping.
 */
export function chainToTokenExchangeClaims(
  chain: DelegationChainView,
  options?: {
    /** Party permitted to become the next actor → emitted as `may_act`. */
    mayActBecome?: { sub: string; iss?: string }
    /** Logical target audience. */
    audience?: string | string[]
    /** Absolute resource URI (no fragment). */
    resource?: string
    /** Issuer of the exchanged token. */
    iss?: string
    /** exp (NumericDate). */
    exp?: number
    /** nbf (NumericDate). */
    nbf?: number
  },
): TokenExchangeClaims {
  assertChainNarrows(chain)

  const claims: TokenExchangeClaims = {
    sub: chain.principal,
    act: buildActClaim(chain.hops),
    scope: effectiveScope(chain).join(' '),
  }
  if (chain.principalIss) {
    // Disambiguate the principal subject by issuer where the bridge was told one.
    // Carried as top-level iss only when no explicit token iss was supplied.
  }
  if (options?.iss) claims.iss = options.iss
  else if (chain.principalIss) claims.iss = chain.principalIss
  if (options?.audience !== undefined) claims.aud = options.audience
  if (options?.resource !== undefined) claims.resource = options.resource
  if (options?.exp !== undefined) claims.exp = options.exp
  if (options?.nbf !== undefined) claims.nbf = options.nbf
  if (options?.mayActBecome) {
    const m: MayActClaim = { sub: options.mayActBecome.sub }
    if (options.mayActBecome.iss) m.iss = options.mayActBecome.iss
    claims.may_act = m
  }
  return claims
}

// ── RFC 8693 claims → APS chain ──

/**
 * Flatten a nested `act` claim into actor identities ordered oldest-first.
 * RFC 8693: outermost `act` is current actor, nested are older. We reverse that
 * to match the APS root-first ordering.
 */
function flattenActClaim(act: ActClaim): { sub: string; iss?: string }[] {
  const newestFirst: { sub: string; iss?: string }[] = []
  let node: ActClaim | undefined = act
  let guard = 0
  while (node) {
    if (guard++ > 1024) {
      throw new Error('act claim nesting exceeds supported depth')
    }
    newestFirst.push(node.iss ? { sub: node.sub, iss: node.iss } : { sub: node.sub })
    node = node.act
  }
  return newestFirst.reverse() // oldest-first
}

/**
 * Recover an APS delegation chain from RFC 8693 token-exchange claims.
 *
 * The principal is the top-level `sub`. Actors are read from the nested `act`
 * chain, reversed to root-first order. Each recovered hop is delegated FROM the
 * prior actor (or the principal, for the first actor) TO the actor. The token
 * `scope` member is recovered as the chain's effective scope, and each hop is
 * assigned that effective scope as a ceiling, so the recovered chain is provably
 * no broader than the original effective authority.
 *
 * Per RFC 8693 security rules, authorization MUST derive only from the top-level
 * claims plus the OUTERMOST actor. Nested (prior) actors and `may_act` are
 * informational here; the recovered chain carries them for audit but the
 * effective scope is the authorization ceiling.
 */
export function tokenExchangeClaimsToChain(
  claims: TokenExchangeClaims,
): RecoveredChain {
  if (!claims || typeof claims.sub !== 'string' || claims.sub.length === 0) {
    throw new Error('Token claims must carry a non-empty top-level sub (principal)')
  }
  const principal = claims.sub
  const recoveredScope = parseScope(claims.scope)

  if (!claims.act) {
    // No actor → impersonation-shaped token, not a delegation chain.
    // We surface a zero-hop chain so callers can distinguish this case.
    return {
      principal,
      principalIss: claims.iss,
      hops: [],
      effectiveScope: recoveredScope,
    }
  }

  const actorsOldestFirst = flattenActClaim(claims.act)
  const hops: OAuthDelegationHop[] = []
  let prevGranter = principal
  let prevGranterIss = claims.iss
  for (const actor of actorsOldestFirst) {
    const hop: OAuthDelegationHop = {
      delegatedBy: prevGranter,
      delegatedTo: actor.sub,
      // RFC 8693 transports only token-level scope, not per-hop scope. The
      // effective (narrowed) scope is the ceiling for every recovered hop.
      scope: recoveredScope.slice(),
    }
    if (actor.iss) hop.iss = actor.iss
    hops.push(hop)
    prevGranter = actor.sub
    prevGranterIss = actor.iss
  }
  void prevGranterIss

  return {
    principal,
    principalIss: claims.iss,
    hops,
    effectiveScope: recoveredScope,
  }
}

/** Parse a space-delimited, case-sensitive scope string into a set list. */
export function parseScope(scope?: string): string[] {
  if (!scope) return []
  return scope.split(' ').filter(Boolean)
}

// ── Round-trip narrowing guarantee ──

/**
 * Validate that mapping an APS chain to RFC 8693 claims and back does not widen
 * authority. Compares the original chain's effective scope against the recovered
 * chain's effective scope and asserts the recovered set is a subset (no broader).
 * Returns the recovered chain on success; throws if the round-trip widened.
 */
export function assertRoundTripNarrows(
  original: DelegationChainView,
  recovered: RecoveredChain,
): void {
  const originalEffective = effectiveScope(original)
  const recoveredEffective = recovered.effectiveScope ?? []
  if (!isNarrowing(originalEffective, recoveredEffective)) {
    throw new Error(
      'Round-trip widened authority: recovered scope ' +
        `[${recoveredEffective.join(', ')}] is broader than original ` +
        `[${originalEffective.join(', ')}]`,
    )
  }
  // Principal and actor identity ordering must also be preserved.
  if (recovered.principal !== original.principal) {
    throw new Error(
      `Round-trip changed principal: ${original.principal} -> ${recovered.principal}`,
    )
  }
  const originalActors = original.hops.map((h) => h.delegatedTo)
  const recoveredActors = recovered.hops.map((h) => h.delegatedTo)
  if (originalActors.length !== recoveredActors.length) {
    throw new Error('Round-trip changed actor count')
  }
  for (let i = 0; i < originalActors.length; i++) {
    if (originalActors[i] !== recoveredActors[i]) {
      throw new Error(
        `Round-trip reordered actors at position ${i}: ` +
          `${originalActors[i]} -> ${recoveredActors[i]}`,
      )
    }
  }
}

// ── may_act enforcement ──

/**
 * RFC 8693 Section 4.4: before minting a delegated token, the authorization
 * server SHOULD verify that the presented actor satisfies the subject token's
 * `may_act` constraint. This checks that `actor` matches `may_act`.
 *
 * `may_act` is permission, not proof: a positive result here only means the
 * actor is PERMITTED to act, never that the actor's token was itself valid.
 */
export function actorSatisfiesMayAct(
  mayAct: MayActClaim | undefined,
  actor: { sub: string; iss?: string },
): boolean {
  if (!mayAct) return false
  if (mayAct.sub !== actor.sub) return false
  // If may_act pins an issuer, the actor's issuer must match it.
  if (mayAct.iss !== undefined && mayAct.iss !== actor.iss) return false
  return true
}

/**
 * Read the current (authorizing) actor from a token's claims. Per RFC 8693, only
 * the OUTERMOST `act` is the current actor and the sole actor that authorization
 * may consider. Returns undefined for an impersonation-shaped token (no `act`).
 */
export function currentActor(
  claims: TokenExchangeClaims,
): { sub: string; iss?: string } | undefined {
  if (!claims.act) return undefined
  return claims.act.iss
    ? { sub: claims.act.sub, iss: claims.act.iss }
    : { sub: claims.act.sub }
}

// ── SPIFFE SVID → DID-method identity input ──

/** Trust-domain charset per the SPIFFE-ID spec: lowercase a-z, 0-9, '.', '-', '_'. */
const TRUST_DOMAIN_RE = /^[a-z0-9.\-_]+$/
/** Path-segment charset per the SPIFFE-ID spec: a-zA-Z0-9, '.', '-', '_'. */
const PATH_SEGMENT_RE = /^[a-zA-Z0-9.\-_]+$/

/**
 * Validate a SPIFFE ID against the structural rules of the SPIFFE-ID spec and
 * split it into DID-mappable parts. Reuses parseSPIFFEID for the scheme/authority
 * split, then enforces charset, segment, length, and forbidden-component rules.
 *
 * Rejects: query, fragment, userinfo, port, percent-encoding, empty / '.' / '..'
 * segments, trailing slash, oversized identifiers, and out-of-charset characters.
 */
export function validateSpiffeId(spiffeId: string): {
  trustDomain: string
  pathSegments: string[]
} {
  if (typeof spiffeId !== 'string') {
    throw new Error('SPIFFE ID must be a string')
  }
  // SPIFFE implementations MUST support up to 2048 bytes total.
  if (Buffer.byteLength(spiffeId, 'utf8') > 2048) {
    throw new Error('SPIFFE ID exceeds 2048 bytes')
  }
  // Scheme is exactly `spiffe`, case-insensitive. parseSPIFFEID requires the
  // lowercase form; normalize the scheme only before delegating.
  if (!/^spiffe:\/\//i.test(spiffeId)) {
    throw new Error(`Invalid SPIFFE ID: scheme must be spiffe://, got: ${spiffeId}`)
  }
  if (spiffeId.includes('?')) {
    throw new Error('SPIFFE ID must not contain a query component')
  }
  if (spiffeId.includes('#')) {
    throw new Error('SPIFFE ID must not contain a fragment component')
  }
  if (spiffeId.includes('%')) {
    throw new Error('SPIFFE ID must not contain percent-encoding')
  }

  const normalized = 'spiffe://' + spiffeId.slice('spiffe://'.length)
  const { trustDomain, workloadPath } = parseSPIFFEID(normalized)

  // Trust domain (authority): no userinfo, no port, lowercase charset, <=255 bytes.
  if (trustDomain.includes('@')) {
    throw new Error('SPIFFE trust domain must not contain userinfo')
  }
  if (trustDomain.includes(':')) {
    throw new Error('SPIFFE trust domain must not contain a port')
  }
  if (Buffer.byteLength(trustDomain, 'utf8') > 255) {
    throw new Error('SPIFFE trust domain exceeds 255 bytes')
  }
  if (!TRUST_DOMAIN_RE.test(trustDomain)) {
    throw new Error(`SPIFFE trust domain has invalid characters: ${trustDomain}`)
  }

  // Path: leading slash, no trailing slash, no empty/./.. segments, charset.
  if (workloadPath.endsWith('/')) {
    throw new Error('SPIFFE path must not have a trailing slash')
  }
  const rawSegments = workloadPath.replace(/^\//, '').split('/')
  for (const seg of rawSegments) {
    if (seg.length === 0) {
      throw new Error('SPIFFE path must not contain an empty segment')
    }
    if (seg === '.' || seg === '..') {
      throw new Error(`SPIFFE path must not contain a '${seg}' segment`)
    }
    if (!PATH_SEGMENT_RE.test(seg)) {
      throw new Error(`SPIFFE path segment has invalid characters: ${seg}`)
    }
  }
  return { trustDomain, pathSegments: rawSegments }
}

/**
 * Resolve a SPIFFE ID string to a DID-method identity input. The only transform
 * is `spiffe://` → `did:<method>:` plus segment delimiting (default ':'). Because
 * SPIFFE forbids userinfo, port, query, and fragment and constrains the charset
 * to a DID-safe subset, the mapping is lossless and needs no escaping.
 *
 * Optionally enforces a trust-domain match against an expected root of trust;
 * a mismatch is rejected before any DID is produced.
 */
export function spiffeIdToDidInput(
  spiffeId: string,
  options?: { method?: string; expectedTrustDomain?: string; delimiter?: string },
): SpiffeIdentityInput {
  const { trustDomain, pathSegments } = validateSpiffeId(spiffeId)
  const method = options?.method ?? 'spiffe'
  const delimiter = options?.delimiter ?? ':'

  if (
    options?.expectedTrustDomain !== undefined &&
    options.expectedTrustDomain !== trustDomain
  ) {
    throw new Error(
      `SPIFFE trust-domain mismatch: expected ${options.expectedTrustDomain}, ` +
        `got ${trustDomain}`,
    )
  }

  const methodId = [trustDomain, ...pathSegments].join(delimiter)
  const did = `did:${method}:${methodId}`
  return { spiffeId, trustDomain, pathSegments, did }
}

/**
 * Validate a JWT-SVID's header and claims per the SPIFFE JWT-SVID spec, then map
 * its `sub` (which MUST equal the workload SPIFFE ID) to a DID-method input.
 *
 * Rejects (MUST per spec): missing `exp`; missing `aud`; the validator's own ID
 * absent from `aud` when an audience to match is supplied; `alg` outside the
 * approved asymmetric set (no symmetric, no `alg:none`); a `typ` header that is
 * present but not `JWT`/`JOSE`; a `sub` that is not a valid SPIFFE ID.
 */
export function jwtSvidToDidInput(
  svid: JwtSvidView,
  options?: { method?: string; expectedAudience?: string; expectedTrustDomain?: string },
): SpiffeIdentityInput {
  const { header, claims } = svid
  const alg = header?.alg
  if (!alg) {
    throw new Error('JWT-SVID header must carry alg')
  }
  if (alg === 'none') {
    throw new Error('JWT-SVID alg:none is forbidden')
  }
  const approved: readonly string[] = [
    'RS256', 'RS384', 'RS512',
    'ES256', 'ES384', 'ES512',
    'PS256', 'PS384', 'PS512',
  ]
  if (!approved.includes(alg)) {
    throw new Error(`JWT-SVID alg not in approved asymmetric set: ${alg}`)
  }
  if (header.typ !== undefined && header.typ !== 'JWT' && header.typ !== 'JOSE') {
    throw new Error(`JWT-SVID typ header must be JWT or JOSE when present: ${header.typ}`)
  }
  if (claims.exp === undefined || claims.exp === null) {
    throw new Error('JWT-SVID must carry exp')
  }
  if (claims.aud === undefined || claims.aud === null) {
    throw new Error('JWT-SVID must carry aud')
  }
  const auds = Array.isArray(claims.aud) ? claims.aud : [claims.aud]
  if (auds.length === 0) {
    throw new Error('JWT-SVID aud must have at least one value')
  }
  if (options?.expectedAudience !== undefined && !auds.includes(options.expectedAudience)) {
    throw new Error(
      `JWT-SVID aud does not include validator id: ${options.expectedAudience}`,
    )
  }
  if (typeof claims.sub !== 'string' || claims.sub.length === 0) {
    throw new Error('JWT-SVID sub must be the workload SPIFFE ID')
  }
  return spiffeIdToDidInput(claims.sub, {
    method: options?.method,
    expectedTrustDomain: options?.expectedTrustDomain,
  })
}
