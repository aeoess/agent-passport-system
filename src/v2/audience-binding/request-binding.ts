// Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
/**
 * @fileoverview Compose audience binding with the M1 RFC 9421 request-binding
 * profile WITHOUT changing the signed bytes of the HTTP Message Signature.
 *
 * The request-binding profile already covers @authority in its signed base
 * (signature-base.ts: deriveAuthority). @authority IS the request-host
 * audience: a signature whose base names host A cannot be lifted onto a request
 * to host B, because reconstructing the base over host B yields a different
 * string and the signature check fails. This module does NOT redefine
 * @authority and does NOT add a new covered component (which would bump the
 * profile version and change bytes). Instead it offers a VERIFIER-SIDE policy
 * overlay: a relying party that knows the expected request host can assert it
 * explicitly and get a precise audience-style result, composed with the
 * existing verifyRequest pipeline.
 *
 * This keeps audience binding additive and optional-until-profile-required:
 *   - A caller that does not set expectedAuthority gets the unchanged
 *     verifyRequest behavior.
 *   - A caller that sets it gets an extra, precisely-labeled check that runs
 *     AFTER the cryptographic verification (so a forged base can never satisfy
 *     it) and never consumes the nonce on its own.
 */

import { deriveAuthority } from '../transport/rfc9421/signature-base.js'
import { verifyRequest } from '../transport/rfc9421/profile.js'
import type {
  RequestBindingProfile,
  RequestContext,
  VerifierKey,
  VerifyPolicy,
  VerifyResult,
} from '../transport/rfc9421/types.js'

/** A verifier-side audience overlay for the request-binding profile. */
export interface RequestAudiencePolicy {
  /**
   * The request host[:port] the relying party expects, in the SAME normalized
   * form @authority uses (lowercased host, non-default port appended). When
   * set, the derived @authority of the received request MUST equal it. Reuses
   * deriveAuthority so the comparison is byte-identical to the signed base.
   */
  expectedAuthority?: string
}

/** Outcome of a request-binding verification composed with an audience check. */
export interface RequestAudienceResult {
  /** The underlying RFC 9421 verification result. */
  inner: VerifyResult
  /**
   * The audience overlay status. 'pass' when the expected authority matched (or
   * none was required), 'fail' when it did not, 'not_applicable' when no
   * expectedAuthority was set, 'unknown' when inner verification did not pass
   * (so the request bytes are not trustworthy enough to compare).
   */
  audienceStatus: 'pass' | 'fail' | 'not_applicable' | 'unknown'
  /** True only when inner.valid AND the audience overlay did not fail. */
  valid: boolean
  /** Precise reason for an audience overlay failure, when applicable. */
  reason?: 'authority_audience_mismatch'
}

/**
 * Verify a request-binding profile and, when an expected request host is
 * supplied, additionally assert that the request's derived @authority matches
 * it. The crypto check runs first via verifyRequest; the authority audience
 * check is a verifier-side overlay layered on top.
 *
 * Composition order matters: we only trust the request's @authority once
 * verifyRequest has confirmed the base was reconstructed from the received
 * request and the signature is valid. Running the overlay before that would
 * let an attacker satisfy the audience check with an unsigned request.
 */
export function verifyRequestWithAudience(input: {
  profile: RequestBindingProfile
  request: RequestContext
  keys: VerifierKey[]
  policy: VerifyPolicy
  audiencePolicy?: RequestAudiencePolicy
  nonceStore?: import('../transport/rfc9421/profile.js').NonceStore
}): RequestAudienceResult {
  const inner = verifyRequest({
    profile: input.profile,
    request: input.request,
    keys: input.keys,
    policy: input.policy,
    ...(input.nonceStore !== undefined ? { nonceStore: input.nonceStore } : {}),
  })

  const expected = input.audiencePolicy?.expectedAuthority

  // No expected host: audience overlay does not apply.
  if (expected === undefined) {
    return {
      inner,
      audienceStatus: 'not_applicable',
      valid: inner.valid,
    }
  }

  // Inner verification must pass before we trust the request bytes.
  if (!inner.valid) {
    return {
      inner,
      audienceStatus: 'unknown',
      valid: false,
    }
  }

  let derived: string
  try {
    derived = deriveAuthority(new URL(input.request.url))
  } catch {
    return {
      inner,
      audienceStatus: 'fail',
      valid: false,
      reason: 'authority_audience_mismatch',
    }
  }

  if (derived !== expected) {
    return {
      inner,
      audienceStatus: 'fail',
      valid: false,
      reason: 'authority_audience_mismatch',
    }
  }

  return {
    inner,
    audienceStatus: 'pass',
    valid: true,
  }
}
