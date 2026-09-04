// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0
// Passport Verification — validate signatures and integrity

import { verify } from '../crypto/keys.js'
import { canonicalize } from '../core/canonical.js'
import { isRecord } from '../core/is-record.js'
import { parseRfc3339, formatRfc3339 } from '../core/rfc3339.js'
import { normalizeTrustAnchors } from './trust-anchors.js'
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
    /** Accept a passport that carries no issuer countersignature, on its own
     *  signature alone. Off by default, and consulted only when
     *  `trustedIssuers` was not supplied: a caller that named issuers asked
     *  for that check, and this flag does not rescue a failed one. */
    allowSelfSigned?: boolean
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
  let selfSignedAccepted = false

  // Null / undefined / non-object (attacker-deliverable JSON `null`) rejects
  // with the missing-fields verdict rather than throwing on the property
  // access below.
  // Normalized ONCE, at the boundary, so this guard and the one in
  // trust-posture.ts cannot disagree about what the caller passed. This line
  // used to be a positive `.length > 0` test while the gate used an equality
  // `.length === 0` test, and a value with no numeric length fell through both
  // into the permissive branch.
  const trustAnchors = normalizeTrustAnchors(opts?.trustedIssuers)
  const issuerTrustChecked = trustAnchors.anchors.length > 0

  // A malformed trustedIssuers is a caller configuration error, and it must
  // not resolve to "no anchors" (which composes into an admit) or to "all
  // anchors". It fails closed and names itself.
  if (trustAnchors.malformed) {
    return {
      valid: false,
      errors: [`Invalid trustedIssuers option: ${trustAnchors.reason}`],
      warnings,
      issuerTrustChecked: false,
      selfSignedAccepted: false,
    }
  }

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
  if (issuerTrustChecked) {
    const issuerSig = (signed as any).issuerSignature
    if (!issuerSig?.signature || !issuerSig?.issuerPublicKey) {
      errors.push('No issuer countersignature — passport is self-signed')
    } else if (!trustAnchors.anchors.includes(issuerSig.issuerPublicKey)) {
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
  } else if (opts?.allowSelfSigned === true) {
    selfSignedAccepted = true
    warnings.push('Self-signed passport accepted: no trust root was consulted')
  } else {
    // A signature over a passport says who signed it, not who vouches for it.
    // The verifying key is the one the passport carries, so a good signature
    // is available to anyone who can generate a key pair. Integrity is
    // established above; authority is the caller's to supply, and without it
    // there is nothing here to be valid ABOUT.
    errors.push(
      'Authority not established: no trustedIssuers were supplied. The key a ' +
      'passport carries is its own claim about itself. Pass trustedIssuers, or ' +
      'allowSelfSigned: true to accept a self-vouching passport deliberately.',
    )
  }

  // Check expiration. Default path keeps the exact prior behavior. When a
  // uniform clock skew is supplied, the passport is considered live until
  // `expiresAt` is older than (now - skew), and notBefore is honored within
  // (now + skew). This is the one millisecond-based skew option callers can
  // thread uniformly across verifiers.
  if (opts?.clock?.allowedClockSkewMs !== undefined) {
    const skewMs = opts.clock.allowedClockSkewMs
    const nowMs = (opts.clock.now ?? new Date()).getTime()
    // An expiry this verifier cannot read is not an expiry it can honour: the
    // skewed path reports the unreadable value and fails the passport, rather
    // than comparing it against the clock, where a value that is not an instant
    // answers "not expired" and the expiry check is skipped altogether.
    const expiry = parseRfc3339(passport.expiresAt)
    if (!expiry.ok) {
      errors.push(`Invalid expiresAt (${expiry.reason})`)
    } else if (expiry.ms < nowMs - skewMs) {
      errors.push(`Passport expired at ${passport.expiresAt}`)
    }
    // notBefore is optional: absent leaves the lower edge of the window open,
    // which is the shipped semantics. Present but unreadable is an error — the
    // verifier has seen no evidence that the window has opened, which is a
    // different claim from having seen a start date still in the future.
    if (passport.notBefore) {
      const notBefore = parseRfc3339(passport.notBefore)
      if (!notBefore.ok) {
        errors.push(`Invalid notBefore (${notBefore.reason})`)
      } else if (notBefore.ms > nowMs + skewMs) {
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
    // A delegation expiry this verifier cannot read is not an expiry it can
    // honour, so an unreadable value warns on the same footing as an elapsed
    // one and names the reason, instead of passing silently as a delegation
    // with no limit the verifier could find.
    const delegationExpiry = parseRfc3339(delegation.expiresAt)
    if (!delegationExpiry.ok) {
      warnings.push(`Delegation to ${delegation.delegatedTo} has an invalid expiresAt (${delegationExpiry.reason}) — treated as expired`)
    } else if (delegationExpiry.ms < Date.now()) {
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
    // True only when the caller opted in AND the verdict held: the passport's
    // own signature verified and no trust root was consulted to say who stands
    // behind it. A caller that must not act on a self-vouching credential
    // branches on this rather than on warning text.
    selfSignedAccepted: valid && selfSignedAccepted,
    passport: valid ? passport : undefined
  }
}

export function createChallenge(expiresInSeconds = 300): Challenge {
  return {
    challengeId: uuidv4(),
    nonce: randomBytes(32).toString('hex'),
    timestamp: new Date().toISOString(),
    expiresAt: formatRfc3339(Date.now() + expiresInSeconds * 1000)
  }
}

export function verifyChallenge(
  challenge: Challenge,
  signatureHex: string,
  publicKeyHex: string
): boolean {
  // Check expiry. An expiry this function cannot read is not one it can
  // honour: an unparseable expiresAt fails the challenge rather than comparing
  // false in both directions and leaving only the signature check.
  const expiry = parseRfc3339(challenge.expiresAt)
  if (!expiry.ok) return false
  if (expiry.ms < Date.now()) return false
  // Verify signature over the nonce
  return verify(challenge.nonce, signatureHex, publicKeyHex)
}
