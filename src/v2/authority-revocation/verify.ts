// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0

import {
  authorityDelegationBody,
  computeAuthorityDelegationId,
} from '../authority-delegation/canonical.js'
import { snapshotPlainData } from '../authority-delegation/plain-data.js'
import { validateAuthorityDelegationShape } from '../authority-delegation/schema.js'
import type {
  AuthorityDelegationV1,
  KeyResolutionFailure,
  VerificationKeyResolver,
} from '../authority-delegation/types.js'
import {
  authorityRevocationBody,
  authorityRevocationCascadeOrigin,
  computeAuthorityRevocationCascadeTransactionId,
  computeAuthorityRevocationId,
  verifyAuthorityRevocationSignature,
} from './canonical.js'
import { validateAuthorityRevocationShape } from './schema.js'
import type {
  AuthorityRevocationFailure,
  AuthorityRevocationFailureCode,
  AuthorityRevocationV1,
  AuthorityRevocationVerificationResult,
} from './types.js'

export interface AuthorityRevocationVerificationOptions {
  /** Resolves the key that signed the revocation, selected at the revocation's own
   *  `revoked_at`, per draft section 2.4: the key current at verification time is not
   *  necessarily the one that signed this record. */
  resolveVerificationKey: VerificationKeyResolver
}

const KEY_MATERIAL = /^[0-9a-fA-F]{64}$/

const UNSUPPORTED_CODES = new Set<AuthorityRevocationFailureCode>([
  'UNSUPPORTED_RECORD_TYPE',
  'UNSUPPORTED_VERSION',
])

function result(
  state: AuthorityRevocationVerificationResult['state'],
  failures: AuthorityRevocationFailure[],
): AuthorityRevocationVerificationResult {
  return { state, valid: state === 'valid', failures }
}

function invalid(
  code: AuthorityRevocationFailureCode,
  message: string,
): AuthorityRevocationVerificationResult {
  return result('invalid', [{ code, message }])
}

function indeterminate(
  code: AuthorityRevocationFailureCode,
  message: string,
): AuthorityRevocationVerificationResult {
  return result('indeterminate', [{ code, message }])
}

/** Map a resolver's answer onto the draft's section 2.5 outcomes, or null when it
 *  resolved usable key material. An unsupported identifier scheme is unsupported;
 *  everything else that is not a usable key is indeterminate, never SIGNATURE_INVALID,
 *  because in those branches no signature was checked at all. */
function keyResolutionFailure(
  resolved: string | null | KeyResolutionFailure | undefined,
): AuthorityRevocationVerificationResult | null {
  if (typeof resolved === 'string') {
    return KEY_MATERIAL.test(resolved)
      ? null
      : indeterminate('KEY_MATERIAL_MALFORMED', 'resolved key material is not a 32-byte Ed25519 public key')
  }
  if (resolved && typeof resolved === 'object' && typeof (resolved as KeyResolutionFailure).outcome === 'string') {
    switch ((resolved as KeyResolutionFailure).outcome) {
      case 'unsupported_scheme':
        return result('unsupported', [{ code: 'KEY_SCHEME_UNSUPPORTED', message: 'identifier scheme is not supported by the resolver' }])
      case 'not_found':
        return indeterminate('KEY_NOT_FOUND', 'revoker or key was not found')
      case 'ambiguous':
        return indeterminate('KEY_AMBIGUOUS', 'key resolution was ambiguous')
      case 'unreachable':
        return indeterminate('KEY_UNREACHABLE', 'key material was unreachable')
      case 'malformed':
        return indeterminate('KEY_MATERIAL_MALFORMED', 'resolved key material is structurally malformed')
      default:
        break
    }
  }
  return indeterminate('KEY_RESOLUTION_FAILED', 'revoker verification key could not be resolved')
}

/**
 * Verify one draft-03 section 3.5.1 direct revocation against the delegation it names.
 *
 * A revocation is never judged alone. Whether a record is a revocation of THIS delegation
 * and whether its signer was allowed to revoke are both questions about the target, so the
 * target is a required argument and every authorization fact is read from it.
 *
 * Checks, in order, returning at the first that fails:
 *
 *  1. closed schema and canonical values on the revocation
 *  2. `cascade_transaction_id` recomputes from the record's own origin content
 *  3. `revocation_id` recomputes from the record's own body
 *  4. closed schema and canonical values on the target delegation
 *  5. the target's `delegation_id` recomputes from the target's own body
 *  6. the revocation's `delegation_id` equals the target's
 *  7. the revocation's `revoker` equals the TARGET's `issuer` (draft section 3.5)
 *  8. the revoker's key resolves, at the revocation's `revoked_at`
 *  9. the Ed25519 signature verifies over the domain-tagged preimage
 *
 * Step 8 hands the resolver `target.issuer`, read from the target delegation, not the
 * `revoker` the record carries. The two are equal by step 7, and reading the target's
 * member is what makes the authorization external to the record: no field inside a
 * revocation selects the key that authorizes it.
 *
 * Fails closed. Anything unrecognized, any resolver that throws, any shape this schema
 * does not claim, produces invalid, indeterminate or unsupported, never valid. This
 * function does not throw.
 */
export function verifyAuthorityRevocation(
  candidate: unknown,
  delegation: unknown,
  options: AuthorityRevocationVerificationOptions,
): AuthorityRevocationVerificationResult {
  const read = (key: keyof AuthorityRevocationVerificationOptions): unknown => {
    try { return options ? options[key] : undefined } catch { return undefined }
  }
  const resolveVerificationKey = read('resolveVerificationKey') as VerificationKeyResolver | undefined

  const snapshot = snapshotPlainData(candidate)
  const shapeFailures = validateAuthorityRevocationShape(snapshot)
  if (shapeFailures.length > 0) {
    const unsupported = shapeFailures.every(item => UNSUPPORTED_CODES.has(item.code))
    return result(unsupported ? 'unsupported' : 'invalid', shapeFailures)
  }
  const revocation = snapshot as AuthorityRevocationV1

  const body = authorityRevocationBody(revocation)
  const origin = authorityRevocationCascadeOrigin(body)
  if (computeAuthorityRevocationCascadeTransactionId(origin) !== revocation.cascade_transaction_id) {
    return invalid('CASCADE_TRANSACTION_MISMATCH', 'cascade_transaction_id does not recompute from the record')
  }
  if (computeAuthorityRevocationId(body) !== revocation.revocation_id) {
    return invalid('ID_MISMATCH', 'revocation content address does not match its body')
  }

  const target = snapshotPlainData(delegation) as AuthorityDelegationV1
  const targetFailures = validateAuthorityDelegationShape(target)
  if (targetFailures.length > 0) {
    return invalid('SCHEMA_INVALID', `target delegation invalid (${targetFailures[0].code})`)
  }
  if (computeAuthorityDelegationId(authorityDelegationBody(target)) !== target.delegation_id) {
    return invalid('TARGET_ID_MISMATCH', 'target delegation content address does not match its body')
  }
  if (revocation.delegation_id !== target.delegation_id) {
    return invalid('TARGET_MISMATCH', 'revocation does not name this delegation')
  }
  // Draft section 3.5: a delegation may be revoked by its issuer, and by nobody else this
  // document names.
  if (revocation.revoker !== target.issuer) {
    return invalid('REVOKER_NOT_ISSUER', 'revoker is not the target delegation issuer')
  }

  if (typeof resolveVerificationKey !== 'function') {
    return indeterminate('KEY_RESOLUTION_FAILED', 'no verification key resolver was supplied')
  }
  let resolved: string | null | KeyResolutionFailure = null
  try {
    // target.issuer, not revocation.revoker: the authorizing identity comes from the
    // record being revoked.
    resolved = resolveVerificationKey(target.issuer, revocation.verification_method, revocation.revoked_at)
  } catch {
    resolved = null
  }
  const keyFailure = keyResolutionFailure(resolved)
  if (keyFailure) return keyFailure

  if (!verifyAuthorityRevocationSignature(revocation, resolved as string)) {
    return invalid('SIGNATURE_INVALID', 'Ed25519 signature is invalid')
  }
  return result('valid', [])
}
