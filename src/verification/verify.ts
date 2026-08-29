// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0
// Passport Verification — validate signatures and integrity

import { verify } from '../crypto/keys.js'
import { canonicalize } from '../core/canonical.js'
import { isRecord } from '../core/is-record.js'
import { isExpired } from '../core/passport.js'
import type { SignedPassport, VerificationResult, Challenge } from '../types/passport.js'
import type { CoreVerifyClockOptions } from '../types/policy.js'
import { randomBytes } from 'node:crypto'
import { v4 as uuidv4 } from 'uuid'

/**
 * Verify passport structural integrity and signature.
 *
 * WARNING: without `trustedIssuers`, a self-signed passport still returns
 * valid: true. A passport signature verifies under the public key the
 * passport itself carries, so on its own it proves that the holder of that
 * key wrote the passport, capabilities included, and nothing about who
 * vouches for the holder. A self-signed passport declaring
 * `admin:everything` verifies here.
 *
 * That default is UNCHANGED and is relied on across the SDK; flipping it is
 * a protocol decision, not a local repair. What this function now does is
 * report the state in a form a caller can branch on: `issuerTrustChecked`
 * says whether a trust root was consulted, and `selfSignedAccepted` says
 * that the verdict rests on the passport's own signature alone. Callers
 * that must not act on a self-vouching credential read those fields; the
 * relying-party gate (v2/offline-verifier/middleware) and
 * verifySocialContract both do, and both refuse to admit on that basis
 * without an explicit posture from their own caller.
 */
export function verifyPassport(
  signed: SignedPassport,
  opts?: {
    trustedIssuers?: string[]
    /** M4. Uniform clock-skew option. When provided, passport expiry is
     *  tolerated within `allowedClockSkewMs` of the verifier clock. Omitting
     *  it preserves the prior exact-boundary behavior. This consolidates the
     *  per-verifier skews in ap2 (`clock_skew_seconds`) and
     *  instruction-provenance (`clockSkewMs`); those remain available. */
    clock?: CoreVerifyClockOptions
  },
): VerificationResult {
  const errors: string[] = []
  const warnings: string[] = []

  // Null / undefined / non-object (attacker-deliverable JSON `null`) rejects
  // with the missing-fields verdict rather than throwing on the property
  // access below.
  const issuerTrustChecked = Boolean(opts?.trustedIssuers && opts.trustedIssuers.length > 0)

  if (!isRecord(signed)) {
    return { valid: false, errors: ['Missing passport or signature'], warnings, issuerTrustChecked, selfSignedAccepted: false }
  }

  // Check required fields
  if (!signed.passport || !signed.signature) {
    return { valid: false, errors: ['Missing passport or signature'], warnings, issuerTrustChecked, selfSignedAccepted: false }
  }

  const { passport, signature } = signed

  // Verify cryptographic signature
  const canonical = canonicalize(passport)
  const sigValid = verify(canonical, signature, passport.publicKey)
  if (!sigValid) {
    errors.push('Invalid signature — passport may have been tampered with')
  }

  // If trustedIssuers provided, verify issuer countersignature
  if (issuerTrustChecked && opts?.trustedIssuers) {
    const issuerSig = (signed as any).issuerSignature
    if (!issuerSig?.signature || !issuerSig?.issuerPublicKey) {
      errors.push('No issuer countersignature — passport is self-signed')
    } else if (!opts.trustedIssuers.includes(issuerSig.issuerPublicKey)) {
      errors.push(`Issuer ${issuerSig.issuerPublicKey.slice(0, 16)}... not in trusted issuers list`)
    } else {
      // countersignPassport() signs {passport, signature, signedAt} — must match
      const issuerPayload = canonicalize({
        passport: signed.passport,
        signature: signed.signature,
        signedAt: (signed as any).signedAt,
      })
      const issuerValid = verify(issuerPayload, issuerSig.signature, issuerSig.issuerPublicKey)
      if (!issuerValid) {
        errors.push('Invalid issuer countersignature')
      }
    }
  } else {
    warnings.push('No trustedIssuers provided — self-signed passports are accepted')
  }

  // Check expiration. Default path keeps the exact prior behavior. When a
  // uniform clock skew is supplied, the passport is considered live until
  // `expiresAt` is older than (now - skew), and notBefore is honored within
  // (now + skew). This is the one millisecond-based skew option callers can
  // thread uniformly across verifiers.
  if (opts?.clock?.allowedClockSkewMs !== undefined) {
    const skewMs = opts.clock.allowedClockSkewMs
    const nowMs = (opts.clock.now ?? new Date()).getTime()
    const expMs = Date.parse(passport.expiresAt)
    if (!Number.isNaN(expMs) && expMs < nowMs - skewMs) {
      errors.push(`Passport expired at ${passport.expiresAt}`)
    }
    if (passport.notBefore) {
      const nbfMs = Date.parse(passport.notBefore)
      if (!Number.isNaN(nbfMs) && nbfMs > nowMs + skewMs) {
        errors.push(`Passport not valid before ${passport.notBefore}`)
      }
    }
  } else if (isExpired(passport)) {
    errors.push(`Passport expired at ${passport.expiresAt}`)
  }

  // Check version
  if (!passport.version) {
    warnings.push('No version field')
  }

  // Check required identity fields
  if (!passport.agentId) errors.push('Missing agentId')
  if (!passport.publicKey) errors.push('Missing publicKey')
  if (!passport.capabilities || passport.capabilities.length === 0) {
    warnings.push('No capabilities declared')
  }

  // Check delegations
  // Array.isArray guard, not just `|| []`: a present-but-non-array
  // delegations field (an object, a number, a string) is truthy, so the
  // old `passport.delegations || []` let it straight into a for...of and
  // threw TypeError instead of this function's documented contract of
  // always returning {valid: false, errors: [...]} for malformed input.
  for (const delegation of Array.isArray(passport.delegations) ? passport.delegations : []) {
    if (new Date(delegation.expiresAt) < new Date()) {
      warnings.push(`Delegation to ${delegation.delegatedTo} has expired`)
    }
    if (delegation.spendLimit && delegation.spentAmount &&
        delegation.spentAmount >= delegation.spendLimit) {
      warnings.push(`Delegation to ${delegation.delegatedTo} has exhausted spend limit`)
    }
  }

  const valid = errors.length === 0
  return {
    valid,
    errors,
    warnings,
    issuerTrustChecked,
    // The verdict rests on the passport's own signature alone: it verified,
    // and no trust root was consulted to say who stands behind it.
    selfSignedAccepted: valid && !issuerTrustChecked,
    passport: valid ? passport : undefined
  }
}

export function createChallenge(expiresInSeconds = 300): Challenge {
  return {
    challengeId: uuidv4(),
    nonce: randomBytes(32).toString('hex'),
    timestamp: new Date().toISOString(),
    expiresAt: new Date(Date.now() + expiresInSeconds * 1000).toISOString()
  }
}

export function verifyChallenge(
  challenge: Challenge,
  signatureHex: string,
  publicKeyHex: string
): boolean {
  // Check expiry
  if (new Date(challenge.expiresAt) < new Date()) return false
  // Verify signature over the nonce
  return verify(challenge.nonce, signatureHex, publicKeyHex)
}
