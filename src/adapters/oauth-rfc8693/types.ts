// Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// OAuth 2.1 / RFC 8693 Token Exchange bridge. Type definitions.
//
// This is a bridge and profile only. An APS delegation chain is expressed as
// RFC 8693 token-exchange `act` / `may_act` delegation claims at the edge, and
// recovered back. APS does not become OAuth. The mapping preserves authority
// and monotonic narrowing in both directions.
//
// Spec basis: RFC 8693 (Section 4.1 act, 4.4 may_act, Section 2 request/response).

// ── Token-type URNs (RFC 8693 Section 3, verbatim) ──

export const TOKEN_TYPE_URN = {
  access_token: 'urn:ietf:params:oauth:token-type:access_token',
  refresh_token: 'urn:ietf:params:oauth:token-type:refresh_token',
  id_token: 'urn:ietf:params:oauth:token-type:id_token',
  saml1: 'urn:ietf:params:oauth:token-type:saml1',
  saml2: 'urn:ietf:params:oauth:token-type:saml2',
  jwt: 'urn:ietf:params:oauth:token-type:jwt',
} as const

/** REQUIRED grant_type value for token exchange (RFC 8693 Section 2.1). */
export const TOKEN_EXCHANGE_GRANT_TYPE =
  'urn:ietf:params:oauth:grant-type:token-exchange'

// ── RFC 8693 actor (`act`) claim ──

/**
 * The `act` (actor) claim (RFC 8693 Section 4.1). A JSON object whose `sub`
 * identifies the current acting party. A chain of delegation is expressed by
 * nesting one `act` within another: the OUTERMOST `act` is the current actor,
 * nested `act` claims represent prior (older) actors as you recurse inward.
 */
export interface ActClaim {
  /** Identifier of this actor. Conventionally the `sub` of the acting party. */
  sub: string
  /** Optional issuer, included to disambiguate when `sub` is not globally unique. */
  iss?: string
  /** Nested prior actor (the actor that acted before this one). */
  act?: ActClaim
}

/**
 * The `may_act` claim (RFC 8693 Section 4.4). A forward-authorization assertion
 * placed on a subject token naming who is PERMITTED to become the actor. This is
 * permission, not proof, and MUST NOT itself be used as an authorization input.
 */
export interface MayActClaim {
  sub: string
  iss?: string
}

/**
 * A JWT claim set as produced/consumed by an RFC 8693 token exchange. Only the
 * members this bridge maps are typed; arbitrary additional claims are allowed.
 */
export interface TokenExchangeClaims {
  /** Issuer of this exchanged token. */
  iss?: string
  /** Audience: logical name(s) of the target service. */
  aud?: string | string[]
  /** Expiration (NumericDate, seconds since epoch). */
  exp?: number
  /** Not-before (NumericDate, seconds since epoch). */
  nbf?: number
  /** The principal / party on whose behalf the request is made (top-level subject). */
  sub: string
  /** Current actor and nested prior actors. Absent for plain impersonation. */
  act?: ActClaim
  /** Forward-authorization: who may become the actor for this subject. */
  may_act?: MayActClaim
  /** Space-delimited, case-sensitive scope (RFC 8693 Section 2.1). */
  scope?: string
  /** Absolute URI of the target resource (no fragment). */
  resource?: string
  [claim: string]: unknown
}

// ── APS delegation-chain view used by the bridge ──

/**
 * One hop of an APS delegation chain, reduced to the fields the bridge maps.
 * `delegatedBy` is the party that granted authority; `delegatedTo` is the party
 * that received it (and may act). `scope` is that hop's authority set.
 *
 * The first element of a chain is the root grant (closest to the principal); the
 * last element is the current/most-recent actor.
 */
export interface OAuthDelegationHop {
  /** Party that granted this hop (the delegator). */
  delegatedBy: string
  /** Party that received this hop and may act (the delegatee / actor). */
  delegatedTo: string
  /** Authority granted at this hop. Must be a subset of the parent hop's scope. */
  scope: string[]
  /** Optional issuer for disambiguation when identifiers are not globally unique. */
  iss?: string
  /** Optional expiry (ISO 8601). */
  expiresAt?: string
}

/**
 * An APS delegation chain as the bridge sees it: the principal on whose behalf
 * the chain acts, plus the ordered hops from root grant to current actor.
 */
export interface DelegationChainView {
  /** The principal / beneficiary the whole chain ultimately acts for. */
  principal: string
  /** Optional issuer/root-of-trust for the principal subject. */
  principalIss?: string
  /** Ordered hops, root grant first, current actor last. Length >= 1. */
  hops: OAuthDelegationHop[]
}

// ── Recovered chain (mapping back from RFC 8693) ──

/**
 * The result of recovering a chain from RFC 8693 claims. `hops` are ordered the
 * same way as DelegationChainView (root first, current actor last). `scope`
 * carries the narrowed authority recovered from the token `scope` member where
 * present; per-hop scope is not transported by RFC 8693 itself, so the recovered
 * chain reflects the actor ordering and the token-level effective scope.
 */
export interface RecoveredChain {
  principal: string
  principalIss?: string
  hops: OAuthDelegationHop[]
  /** Token-level effective scope recovered from the `scope` member, if any. */
  effectiveScope?: string[]
}

// ── SPIFFE SVID identity input ──

/** Approved asymmetric JWT algorithms for a JWT-SVID (SPIFFE JWT-SVID spec). */
export const JWT_SVID_APPROVED_ALGS = [
  'RS256', 'RS384', 'RS512',
  'ES256', 'ES384', 'ES512',
  'PS256', 'PS384', 'PS512',
] as const

/** Minimal JWT-SVID view: decoded JOSE header plus the claims the spec requires. */
export interface JwtSvidView {
  header: { alg?: string; typ?: string; kid?: string; [k: string]: unknown }
  claims: { sub?: string; aud?: string | string[]; exp?: number; [k: string]: unknown }
}

/** Result of resolving a SPIFFE SVID to a DID-method identity input. */
export interface SpiffeIdentityInput {
  /** The validated SPIFFE ID (spiffe://trust-domain/path). */
  spiffeId: string
  /** Trust domain (authority component), the method-specific namespace root. */
  trustDomain: string
  /** Workload path (without leading slash), segment list. */
  pathSegments: string[]
  /** A did:<method>:<trust-domain>:<segments...> identifier built from the SPIFFE ID. */
  did: string
}
