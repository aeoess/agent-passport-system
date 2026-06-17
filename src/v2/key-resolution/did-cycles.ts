// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// ══════════════════════════════════════════════════════════════════
// did:cycles: hash-bound DID → JWKS mapping and Ed25519 JWK selection
// ══════════════════════════════════════════════════════════════════
// did:cycles is an AEOESS-defined method for Cycles evidence signers.
// The design is settled with the Cycles maintainers on
// runcycles/cycles-protocol (issue #43, spec drafts/cycles-evidence-v0.1).
// There is no external registry to conform to; this file IS its
// specification on the APS side.
//
// SUBJECT IS A HASH, NOT A HOST (the load-bearing difference from a
// did:web-style method):
//
//   did:cycles:<sha256(server_id)>            (optionally with #<kid>)
//
// The subject is the lowercase hex sha256 of the envelope's `server_id`
// string — a BINDING, not a locator. The DID does NOT encode where the
// keys live; a hash cannot be reversed to a URL. The JWK Set is located
// from the envelope's own `server_id`:
//
//   {server_id}/.well-known/cycles-jwks.json            (API-base-relative)
//
// and the DID's hash is checked against `sha256(server_id)` so the key
// authority stays anchored to the exact `server_id` (path included) the
// envelope claims — closing the cross-tenant key-confusion path that an
// origin-rooted JWKS would open under a path-multi-tenant host. (The
// sha256 binding check itself is performed by the cycles verify layer,
// which holds the envelope's `server_id` and the sha256 primitive.)
//
// A DID-URL fragment is the kid:  did:cycles:<hash>#2026-06  selects the
// JWK whose kid === "2026-06" from the resolved set.
//
// Key selection adds a validity-WINDOW gate over the M3 kid match: pick
// the key whose [cycles_nbf_ms, cycles_exp_ms) covers the envelope's
// issued_at_ms, never "the current key" — so a receipt verified after a
// rotation is checked against the key valid when it was signed.
// ══════════════════════════════════════════════════════════════════

import { decodeBase64Url, bytesToHex } from './base64url.js'
import type { Ed25519JWK, JWKS } from './types.js'

export interface ParsedDIDCycles {
  /** Lowercase hex sha256 of `server_id`, as carried in the DID subject.
   *  A BINDING value: the cycles verify layer checks it against
   *  sha256(envelope.server_id). Not a locator. */
  serverIdHash: string
  /** kid taken from the DID-URL fragment, if present. */
  kid?: string
}

const SERVER_ID_HASH_RE = /^[0-9a-f]{64}$/

/**
 * Parse a did:cycles identifier (optionally with a #fragment) into its
 * `server_id` hash and kid. The fragment is split off BEFORE the subject
 * is read so a `#` never lands inside the hash.
 *
 * Throws on a structurally invalid did:cycles string (wrong method, or a
 * subject that is not a 64-char lowercase hex sha256).
 */
export function parseDIDCycles(did: string): ParsedDIDCycles {
  if (typeof did !== 'string') {
    throw new Error('did:cycles must be a string')
  }
  const hashIndex = did.indexOf('#')
  let kid: string | undefined
  let core = did
  if (hashIndex >= 0) {
    kid = did.slice(hashIndex + 1)
    core = did.slice(0, hashIndex)
    if (kid.length === 0) {
      throw new Error('did:cycles fragment (kid) must not be empty when "#" is present')
    }
  }

  const parts = core.split(':')
  if (parts.length !== 3 || parts[0] !== 'did' || parts[1] !== 'cycles') {
    throw new Error(`Invalid did:cycles format: ${core}`)
  }
  const serverIdHash = parts[2]
  if (!SERVER_ID_HASH_RE.test(serverIdHash)) {
    throw new Error('did:cycles subject must be a 64-char lowercase hex sha256(server_id)')
  }
  return { serverIdHash, kid }
}

/** True if the value looks like a did:cycles identifier. */
export function isDIDCycles(value: string): boolean {
  return typeof value === 'string' && value.startsWith('did:cycles:')
}

/**
 * The JWK Set URL for a Cycles server, API-base-relative: append
 * `/.well-known/cycles-jwks.json` to the verbatim `server_id` (collapsing
 * only a doubled `/` at the join). Deliberately NOT origin-rooted —
 * `server_id` carries its path (e.g. `https://cycles.example.com/v1`), so
 * the set lives at `…/v1/.well-known/cycles-jwks.json`, keeping key
 * authority anchored to the base the DID hash commits to.
 */
export function cyclesJwksUrl(serverId: string): string {
  const base = serverId.endsWith('/') ? serverId.slice(0, -1) : serverId
  return `${base}/.well-known/cycles-jwks.json`
}

export type JWKSelection =
  | { ok: true; jwk: Ed25519JWK; publicKeyHex: string; kid?: string }
  | { ok: false; status: 'not_found' | 'ambiguous' | 'malformed'; reason: string }

/** Selection criteria. Legacy callers pass a bare kid string; the cycles
 *  path passes the window + raw-key form. */
export interface SelectKeyOptions {
  /** Match the JWK whose kid strictly equals this (exact, case-sensitive). */
  kid?: string
  /** Window gate: keep only keys whose [cycles_nbf_ms, cycles_exp_ms) covers
   *  this issuance time (epoch ms). Omitted ⇒ no window gate (legacy). */
  issuedAtMs?: number
  /** Raw-hex signer match: keep only keys whose `x` decodes to these 32 bytes
   *  (64-char hex). Used when the envelope's signer_did is a raw key. */
  publicKeyHex?: string
}

/**
 * Is this JWK an admissible Ed25519 SIGNING candidate?
 *   kty === "OKP" && crv === "Ed25519"
 *   (use absent || use === "sig")
 *   (alg absent || alg === "EdDSA")
 *   (key_ops absent || includes "verify")
 */
function isEd25519SigningCandidate(jwk: unknown): jwk is Ed25519JWK {
  if (!jwk || typeof jwk !== 'object') return false
  const k = jwk as Record<string, unknown>
  if (k.kty !== 'OKP') return false
  if (k.crv !== 'Ed25519') return false
  if (typeof k.x !== 'string' || k.x.length === 0) return false
  if (k.use !== undefined && k.use !== 'sig') return false
  if (k.alg !== undefined && k.alg !== 'EdDSA') return false
  if (k.key_ops !== undefined) {
    if (!Array.isArray(k.key_ops) || !k.key_ops.includes('verify')) return false
  }
  return true
}

/** Decode a candidate's `x` to a 32-byte key as 64-char lowercase hex, or
 *  null if `x` does not base64url-decode to exactly 32 bytes. */
function candidateToHex(jwk: Ed25519JWK): string | null {
  const bytes = decodeBase64Url(jwk.x)
  if (!bytes || bytes.length !== 32) return null
  return bytesToHex(bytes)
}

/** `cycles_nbf_ms <= t AND (cycles_exp_ms absent/null OR t < cycles_exp_ms)`.
 *  A non-integer `cycles_nbf_ms` (or a non-integer present `cycles_exp_ms`)
 *  makes the window unusable → the key does not cover `t`. */
function windowCovers(jwk: Ed25519JWK, t: number): boolean {
  const nbf = jwk.cycles_nbf_ms
  if (typeof nbf !== 'number' || !Number.isInteger(nbf)) return false
  if (t < nbf) return false
  const exp = jwk.cycles_exp_ms
  if (exp === undefined || exp === null) return true
  if (typeof exp !== 'number' || !Number.isInteger(exp)) return false
  return t < exp
}

/**
 * Select exactly one Ed25519 verification key from a JWKS. Filters, in
 * order: Ed25519 signing candidacy, optional raw-hex `x` match, optional
 * kid match, optional validity-window gate; then requires the survivor to
 * be unique. Never silently falls back to a different key. Legacy callers
 * may pass a bare kid string.
 */
export function selectKey(jwks: JWKS, sel?: string | SelectKeyOptions): JWKSelection {
  const opts: SelectKeyOptions = typeof sel === 'string' ? { kid: sel } : (sel ?? {})

  let candidates = jwks.keys.filter(isEd25519SigningCandidate)
  if (candidates.length === 0) {
    return { ok: false, status: 'not_found', reason: 'no Ed25519 signing key in JWKS' }
  }

  // Raw-hex signer match (cycles): the published key must carry the signer's bytes.
  if (opts.publicKeyHex !== undefined) {
    const want = opts.publicKeyHex.toLowerCase()
    candidates = candidates.filter((c) => candidateToHex(c) === want)
    if (candidates.length === 0) {
      return { ok: false, status: 'not_found', reason: 'no JWK carries the raw signer key' }
    }
  }

  // kid match (exact, case-sensitive).
  if (opts.kid !== undefined) {
    const matches = candidates.filter((c) => c.kid === opts.kid)
    if (matches.length === 0) {
      return { ok: false, status: 'not_found', reason: `no key with kid='${opts.kid}'` }
    }
    candidates = matches
  }

  // Validity-window gate (cycles): the key valid AT ISSUANCE, never the newest.
  if (opts.issuedAtMs !== undefined) {
    const t = opts.issuedAtMs
    candidates = candidates.filter((c) => windowCovers(c, t))
    if (candidates.length === 0) {
      return { ok: false, status: 'not_found', reason: 'no key whose validity window covers issued_at_ms' }
    }
  }

  if (candidates.length > 1) {
    return { ok: false, status: 'ambiguous', reason: 'more than one key matches the selection criteria' }
  }
  const jwk = candidates[0]
  const hex = candidateToHex(jwk)
  if (!hex) {
    return { ok: false, status: 'malformed', reason: 'selected key x is not a 32-byte key' }
  }
  return { ok: true, jwk, publicKeyHex: hex, kid: jwk.kid }
}

/**
 * Validate that a parsed object is a well-formed JWKS with a non-empty
 * `keys` array. Returns the JWKS on success or null on any structural
 * problem.
 */
export function asJWKS(body: unknown): JWKS | null {
  if (!body || typeof body !== 'object') return null
  const keys = (body as Record<string, unknown>).keys
  if (!Array.isArray(keys) || keys.length === 0) return null
  return { keys: keys as Ed25519JWK[] }
}
