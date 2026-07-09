// Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// ══════════════════════════════════════════════════════════════════
// Key Resolution (M3): public surface
// ══════════════════════════════════════════════════════════════════
// A standardized KeyResolver interface plus a reference resolver that
// maps a DID (did:key / did:web / did:cycles) or a direct JWKS
// endpoint to a single Ed25519 verification key, so a Cycles envelope
// signature check can be completed end to end.
//
// PROOF BOX
// ─────────
// PROVES:    Resolving a key shows which public key a DID or JWKS
//            endpoint asserts FOR that locator AT resolution time. The
//            returned publicKeyHex is exactly the key the named
//            endpoint published under the requested kid.
//
// DOES NOT PROVE:
//            - that the key is uncompromised or under sole control of
//              the named party;
//            - that the endpoint asserts the same key at any later
//              time (keys rotate; resolution is a point-in-time read);
//            - any signature made with the key is authorized.
//            Under FAIL-OPEN, an unreachable endpoint yields a
//            DEGRADED result that carries NO key material and MUST NOT
//            be read as a positive verification. The default policy is
//            FAIL-CLOSED: any resolution failure rejects.
//
// This module is the SDK protocol primitive (interface + reference
// resolver). It is NOT a hosted resolution service: no cross-tenant
// aggregation, no registry, no alerting, no endpoint.
// ══════════════════════════════════════════════════════════════════

export type {
  Ed25519JWK,
  JWKS,
  KeyResolutionStatus,
  KeyResolution,
  KeyLocator,
  FailurePolicy,
  CachePolicy,
  KeyResolverConfig,
  KeyResolver,
} from './types.js'

export { DEFAULT_TIMEOUT_MS, DEFAULT_CACHE_POLICY } from './types.js'

export { decodeBase64Url, bytesToHex } from './base64url.js'

export {
  parseDIDCycles,
  isDIDCycles,
  cyclesJwksUrl,
  asJWKS,
  selectKey,
  type ParsedDIDCycles,
  type SelectKeyOptions,
  type JWKSelection,
} from './did-cycles.js'

export { CyclesKeyResolver } from './resolver.js'
