// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
/**
 * @fileoverview RFC 9421 + RFC 9530 request-binding profile: sign and verify.
 *
 * ── PROOF BOX ──────────────────────────────────────────────────────────────
 * What a valid request-binding proof PROVES:
 *   The signer, holding the private key for the named DID verification method,
 *   authorized this exact HTTP request (method, authority, path, and, when
 *   content-digest is covered, body bytes) at the signing time `created`.
 *
 * What it does NOT prove:
 *   - It does NOT show the request reached its destination, was acted on, or
 *     produced any effect. It binds intent at signing time, not delivery.
 *   - It does NOT, by itself, show authority. Authority is established by the APS
 *     delegation receipt linked via `receiptHash`. The HTTP signature shows
 *     "this exact request was the one authorized"; the APS layer shows the
 *     signer was authorized to make it.
 *   - action_ref does NOT bind the HTTP request and is not used here. The link
 *     between this request and a delegation receipt is the content hash carried
 *     in `receiptHash`, plus the inner HTTP Message Signature (not action_ref).
 *   - A covered content-digest binds the body ONLY if the verifier recomputes
 *     the digest over received bytes and byte-compares. content-digest alone,
 *     unsigned or unrecomputed, shows nothing about the body.
 * ───────────────────────────────────────────────────────────────────────────
 *
 * This module composes the byte-exact serialization in signature-base.ts with
 * the existing Ed25519 sign/verify primitives. It does not reimplement crypto
 * and it does not touch the APS receipt-signing path, the action_ref preimage,
 * or canonical-jcs.
 *
 * Reference scope: this is a protocol primitive plus a reference verifier. The
 * nonce store is an in-memory reference implementation behind an interface; a
 * production replay cache is a deployment concern and is out of scope.
 */

import crypto from 'node:crypto'
import { sign as ed25519Sign, verify as ed25519Verify } from '../../../crypto/keys.js'
import { buildSignatureBase, buildSignatureParamsValue } from './signature-base.js'
import type {
  CoveredComponent,
  RequestBindingProfile,
  RequestContext,
  RequestSignature,
  SignatureParams,
  SignerKey,
  VerifierKey,
  VerifyPolicy,
  VerifyResult,
} from './types.js'
import type { ScopeOfClaim } from '../../accountability/types/base.js'

/** Fixed profile tag for this version. Scopes signatures to this profile. */
export const APS_REQUEST_BINDING_TAG = 'aps-rfc9421-request-binding-v1'

/** Fixed profile identifier. */
export const APS_REQUEST_BINDING_PROFILE = 'aps:rfc9421-request-binding:v1' as const

/** Default covered components for request binding (RFC 9421 §7.2.1 minimum). */
export const DEFAULT_COVERED: CoveredComponent[] = ['@method', '@authority', '@path']

/**
 * Default honest scope declaration for a request-binding profile. Callers
 * SHOULD override `does_not_assert` with delegation-specific context, but the
 * floor below is always true for this primitive.
 */
export function defaultScopeOfClaim(): ScopeOfClaim {
  return {
    asserts:
      'The named verification method signed this exact HTTP method, authority, path, and covered body digest at the stated created time.',
    does_not_assert: [
      'Does not prove the request was delivered or acted on.',
      'Does not by itself prove authority; authority comes from the linked delegation receipt.',
      'Does not bind action_ref to the HTTP request.',
      'Does not prove the body unless content-digest is covered and the verifier recomputes it.',
    ],
    capture_mode: 'self_attested',
    completeness: 'partial',
    self_attested: true,
  }
}

/** Encode a raw signature (bytes) as an SF Byte Sequence: :BASE64:. */
function toByteSequence(sigBytesHex: string): string {
  const b64 = Buffer.from(sigBytesHex, 'hex').toString('base64')
  return `:${b64}:`
}

/** Decode an SF Byte Sequence (:BASE64:) back to hex, or null if malformed. */
function fromByteSequence(value: string): string | null {
  const trimmed = value.trim()
  if (!trimmed.startsWith(':') || !trimmed.endsWith(':') || trimmed.length < 2) {
    return null
  }
  const b64 = trimmed.slice(1, -1)
  try {
    return Buffer.from(b64, 'base64').toString('hex')
  } catch {
    return null
  }
}

export interface SignRequestInput {
  request: RequestContext
  signer: SignerKey
  /** created, nonce, and any overrides. keyid defaults to the signer VM. */
  params: Omit<SignatureParams, 'keyid' | 'tag'> & {
    keyid?: string
    tag?: string
  }
  /** Covered components in signed order. Defaults to DEFAULT_COVERED. */
  covered?: CoveredComponent[]
  /** Structured-Fields label for this signature. Defaults to 'aps'. */
  label?: string
  /** Content hash of the linked APS delegation receipt (hex sha-256). */
  receiptHash?: string
  /** Override the scope-of-claim. Defaults to defaultScopeOfClaim(). */
  scopeOfClaim?: ScopeOfClaim
}

/**
 * Sign a request, producing a RequestBindingProfile whose inner proof is a
 * byte-exact RFC 9421 HTTP Message Signature.
 */
export function signRequest(input: SignRequestInput): RequestBindingProfile {
  const covered = input.covered ?? DEFAULT_COVERED
  if (covered.length === 0) {
    // Empty covered set is unsafe (RFC 9421 §7.2.1): such a signature can be
    // lifted onto an unrelated message. Refuse to produce one.
    throw new Error('refusing to sign with an empty covered set')
  }
  const label = input.label ?? 'aps'
  const tag = input.params.tag ?? APS_REQUEST_BINDING_TAG
  const keyid = input.params.keyid ?? input.signer.verificationMethod

  const params: SignatureParams = {
    created: input.params.created,
    keyid,
    nonce: input.params.nonce,
    tag,
    ...(input.params.alg !== undefined ? { alg: input.params.alg } : {}),
    ...(input.params.expires !== undefined ? { expires: input.params.expires } : {}),
  }

  const { base, contentDigest } = buildSignatureBase(covered, input.request, params)

  const sigHex = ed25519Sign(base, input.signer.privateKeyHex)
  const sigBytes = toByteSequence(sigHex)

  // The Signature-Input RHS MUST be byte-identical to the @signature-params
  // line value in the base; reuse the same serializer to guarantee it.
  const signatureInput = `${label}=${buildSignatureParamsValue(covered, params)}`
  const signatureField = `${label}=${sigBytes}`

  const inner: RequestSignature = {
    label,
    signatureInput,
    signature: signatureField,
    ...(contentDigest !== undefined ? { contentDigest } : {}),
    signatureBase: base,
  }

  return {
    profile: APS_REQUEST_BINDING_PROFILE,
    covered,
    inner,
    verificationMethod: keyid,
    created: params.created,
    nonce: params.nonce,
    tag,
    ...(input.receiptHash !== undefined ? { receiptHash: input.receiptHash } : {}),
    scopeOfClaim: input.scopeOfClaim ?? defaultScopeOfClaim(),
  }
}

/**
 * A pluggable replay store. The verifier records and checks nonces. This is the
 * interface; production stores (shared, persistent, cross-tenant) are out of
 * scope. A reference in-memory store is provided.
 */
export interface NonceStore {
  /** Returns true if the nonce was already seen (i.e. a replay). */
  seen(nonce: string): boolean
  /** Records the nonce as seen. */
  record(nonce: string): void
}

/** Reference in-memory nonce store. Not a service; for tests and local use. */
export class InMemoryNonceStore implements NonceStore {
  private readonly set = new Set<string>()
  seen(nonce: string): boolean {
    return this.set.has(nonce)
  }
  record(nonce: string): void {
    this.set.add(nonce)
  }
}

export interface VerifyRequestInput {
  /** The profile artifact carried with the request. */
  profile: RequestBindingProfile
  /** The request as received, for independent base reconstruction. */
  request: RequestContext
  /** Verifier key(s) keyed by verification method. */
  keys: VerifierKey[]
  /** Acceptance policy. */
  policy: VerifyPolicy
  /** Optional replay store. When provided, replayed nonces are rejected. */
  nonceStore?: NonceStore
}

/**
 * Verify a request against a profile. Performs, in order: covered-set safety,
 * required-component presence, tag match, freshness (created within skew),
 * key resolution, content-digest recomputation (when covered), independent base
 * reconstruction and byte-compare, Ed25519 signature check, and replay check.
 *
 * Verification is fail-closed: any check that does not pass returns valid:false
 * with a precise reason and does NOT consume the nonce.
 */
export function verifyRequest(input: VerifyRequestInput): VerifyResult {
  const { profile, request, keys, policy } = input

  try {
    // 1. Empty covered set is always unsafe.
    if (profile.covered.length === 0) {
      return { valid: false, reason: 'empty_covered_set' }
    }

    // 2. Required components must all be present.
    const required = policy.requiredComponents ?? ['@method', '@authority', '@path']
    for (const req of required) {
      if (!profile.covered.includes(req)) {
        return { valid: false, reason: 'missing_required_component' }
      }
    }

    // 3. Tag must match the expected profile tag.
    if (profile.tag !== policy.expectedTag) {
      return { valid: false, reason: 'tag_mismatch' }
    }

    // 4. Freshness: created within +/- maxSkewSeconds of now.
    const now = policy.nowSeconds ?? Math.floor(Date.now() / 1000)
    if (Math.abs(now - profile.created) > policy.maxSkewSeconds) {
      return { valid: false, reason: 'stale_created' }
    }

    // 5. Resolve the verifying key for this verification method.
    const key = keys.find(k => k.verificationMethod === profile.verificationMethod)
    if (key === undefined) {
      return { valid: false, reason: 'unknown_verification_method' }
    }

    // 6. content-digest: recompute over received body and byte-compare.
    if (profile.covered.includes('content-digest')) {
      const presented = profile.inner.contentDigest
      if (presented === undefined) {
        return { valid: false, reason: 'content_digest_missing' }
      }
      if (request.body === undefined) {
        return { valid: false, reason: 'content_digest_mismatch' }
      }
      const recomputed = computeDigestForCompare(request.body)
      if (recomputed !== presented) {
        return { valid: false, reason: 'content_digest_mismatch' }
      }
    }

    // 7. Independent base reconstruction. Reconstruct the base from the
    //    received request plus the signed params, and byte-compare against the
    //    base the signature was produced over. This catches a wrong method,
    //    swapped path, or substituted authority even before the crypto check.
    const reconstructed = reconstructBase(profile, request)
    if (reconstructed === null) {
      return { valid: false, reason: 'base_reconstruction_mismatch' }
    }
    if (reconstructed !== profile.inner.signatureBase) {
      return { valid: false, reason: 'base_reconstruction_mismatch' }
    }

    // 8. Ed25519 signature check over the reconstructed base.
    const sigHex = extractSignatureHex(profile.inner.signature, profile.inner.label)
    if (sigHex === null) {
      return { valid: false, reason: 'malformed_input' }
    }
    const ok = ed25519Verify(reconstructed, sigHex, key.publicKeyHex)
    if (!ok) {
      return { valid: false, reason: 'signature_invalid' }
    }

    // 9. Replay: reject a previously-seen nonce. Only consume the nonce after
    //    every other check passed, so failed attempts cannot poison the store.
    //    When no nonceStore is supplied the request is NOT replay-checked: the
    //    signature is valid but the same signed request can be presented again.
    //    replayChecked surfaces this so a caller cannot mistake an unchecked pass
    //    for a replay-enforced one. Supply a nonceStore for replay protection.
    const replayChecked = input.nonceStore !== undefined
    if (input.nonceStore !== undefined) {
      if (input.nonceStore.seen(profile.nonce)) {
        return { valid: false, reason: 'replayed_nonce' }
      }
      input.nonceStore.record(profile.nonce)
    }

    return { valid: true, verificationMethod: profile.verificationMethod, replayChecked }
  } catch {
    return { valid: false, reason: 'malformed_input' }
  }
}

/** Recompute the content-digest value over body bytes for byte-comparison. */
function computeDigestForCompare(body: Uint8Array): string {
  const hash = crypto.createHash('sha256').update(Buffer.from(body)).digest('base64')
  return `sha-256=:${hash}:`
}

/**
 * Reconstruct the signature base from the received request and the signed
 * params recorded in the profile. Returns null if reconstruction is not
 * possible (e.g. a body-covered request with no body).
 *
 * The params (created, keyid, nonce, tag, alg, expires) are taken from the
 * profile because they are signer-asserted and are part of the signed bytes;
 * the component VALUES are taken from the RECEIVED request so that a tampered
 * method/authority/path/body changes the reconstructed base and fails the
 * compare.
 */
function reconstructBase(
  profile: RequestBindingProfile,
  request: RequestContext,
): string | null {
  const params: SignatureParams = {
    created: profile.created,
    keyid: profile.verificationMethod,
    nonce: profile.nonce,
    tag: profile.tag,
  }
  // Recover optional alg/expires from the signed Signature-Input if present.
  const rhs = stripLabel(profile.inner.signatureInput, profile.inner.label)
  if (rhs === null) return null
  const algMatch = rhs.match(/;alg="([^"]*)"/)
  if (algMatch) (params as SignatureParams).alg = algMatch[1] as SignatureParams['alg']
  const expiresMatch = rhs.match(/;expires=(\d+)/)
  if (expiresMatch) (params as SignatureParams).expires = Number(expiresMatch[1])

  try {
    const { base } = buildSignatureBase(profile.covered, request, params)
    return base
  } catch {
    return null
  }
}

/** Strip 'label=' from a Signature-Input field value, returning the RHS. */
function stripLabel(field: string, label: string): string | null {
  const prefix = `${label}=`
  if (!field.startsWith(prefix)) return null
  return field.slice(prefix.length)
}

/** Extract the raw signature hex from a Signature field value for a label. */
function extractSignatureHex(field: string, label: string): string | null {
  const rhs = stripLabel(field, label)
  if (rhs === null) return null
  return fromByteSequence(rhs)
}
