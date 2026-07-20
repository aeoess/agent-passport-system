// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0

import {
  authorityDelegationBody,
  computeAuthorityDelegationId,
  verifyAuthorityDelegationSignature,
} from './canonical.js'
import { compareAuthority } from './compare.js'
import { isCanonicalTimestamp, validateAuthorityDelegationShape } from './schema.js'
import type {
  AuthorityChainVerificationOptions,
  AuthorityDelegationV1,
  AuthorityFailure,
  AuthorityValidationResult,
  AuthorityValidationState,
} from './types.js'

function result(state: AuthorityValidationState, failures: AuthorityFailure[]): AuthorityValidationResult {
  return { state, valid: state === 'valid', failures }
}

function indexed(failure: AuthorityFailure, index: number): AuthorityFailure {
  return { ...failure, index }
}

/** Full root-to-leaf structural, cryptographic, temporal, and revocation validation. */
export function verifyAuthorityDelegationChain(
  rawChain: readonly unknown[],
  options: AuthorityChainVerificationOptions,
): AuthorityValidationResult {
  if (!Array.isArray(rawChain) || rawChain.length === 0 || rawChain.length > 256) {
    return result('invalid', [{ code: 'SCHEMA_INVALID', message: 'chain must contain 1 through 256 records' }])
  }
  if (!options || !isCanonicalTimestamp(options.now)) {
    return result('invalid', [{ code: 'NONCANONICAL_VALUE', message: 'verification clock must be canonical UTC milliseconds' }])
  }
  const now = Date.parse(options.now)

  const chain: AuthorityDelegationV1[] = []
  for (let i = 0; i < rawChain.length; i++) {
    const failures = validateAuthorityDelegationShape(rawChain[i]).map(item => indexed(item, i))
    if (failures.length > 0) {
      const unsupported = failures.every(item => item.code === 'UNSUPPORTED_VERSION' || item.code === 'UNSUPPORTED_PROFILE')
      return result(unsupported ? 'unsupported' : 'invalid', failures)
    }
    chain.push(rawChain[i] as AuthorityDelegationV1)
  }

  const seen = new Set<string>()
  for (let i = 0; i < chain.length; i++) {
    const delegation = chain[i]
    if (seen.has(delegation.delegation_id)) {
      return result('invalid', [{ code: 'CHAIN_DUPLICATE_ID', index: i, message: 'delegation ID repeats in chain' }])
    }
    seen.add(delegation.delegation_id)
    const expectedId = computeAuthorityDelegationId(authorityDelegationBody(delegation))
    if (expectedId !== delegation.delegation_id) {
      return result('invalid', [{ code: 'ID_MISMATCH', index: i, message: 'delegation content address does not match body' }])
    }
    let publicKey: string | null = null
    try {
      publicKey = options.resolveVerificationKey(
        delegation.issuer,
        delegation.verification_method,
        delegation.issued_at,
      )
    } catch {
      publicKey = null
    }
    if (publicKey === null) {
      return result('indeterminate', [{ code: 'KEY_RESOLUTION_FAILED', index: i, message: 'issuer verification key could not be resolved' }])
    }
    if (!verifyAuthorityDelegationSignature(delegation, publicKey)) {
      return result('invalid', [{ code: 'SIGNATURE_INVALID', index: i, message: 'Ed25519 signature is invalid' }])
    }
  }

  const root = chain[0]
  if (root.parent_delegation_id !== null) {
    return result('invalid', [{ code: 'PARENT_MISMATCH', index: 0, message: 'full chain root must carry null parent_delegation_id' }])
  }
  if (typeof options.trustRoot !== 'function') {
    return result('indeterminate', [{ code: 'ROOT_UNTRUSTED', index: 0, message: 'root trust policy is unavailable' }])
  }
  let trustDecision: unknown
  try { trustDecision = options.trustRoot(root) } catch {
    return result('indeterminate', [{ code: 'ROOT_UNTRUSTED', index: 0, message: 'root trust policy could not decide' }])
  }
  if (typeof trustDecision !== 'boolean') {
    return result('indeterminate', [{ code: 'ROOT_UNTRUSTED', index: 0, message: 'root trust policy returned no boolean decision' }])
  }
  if (!trustDecision) {
    return result('invalid', [{ code: 'ROOT_UNTRUSTED', index: 0, message: 'root is not accepted by verifier trust policy' }])
  }

  for (let i = 1; i < chain.length; i++) {
    const parent = chain[i - 1]
    const child = chain[i]
    if (child.parent_delegation_id !== parent.delegation_id) {
      return result('invalid', [{ code: 'PARENT_MISMATCH', index: i, message: 'child does not name immediate parent content address' }])
    }
    if (child.issuer !== parent.subject) {
      return result('invalid', [{ code: 'CHAIN_CONTINUITY', index: i, message: 'child issuer is not parent subject' }])
    }
    const issued = Date.parse(child.issued_at)
    if (issued < Date.parse(parent.authority.time.not_before) ||
        issued >= Date.parse(parent.authority.time.not_after)) {
      return result('invalid', [{ code: 'ISSUED_AT_OUTSIDE_PARENT', index: i, message: 'child was issued outside parent validity window' }])
    }
    const attenuationFailures = compareAuthority(parent.authority, child.authority)
    if (attenuationFailures.length > 0) {
      const indexedFailures = attenuationFailures.map(item => indexed(item, i))
      const unsupported = indexedFailures.every(item => item.code === 'UNSUPPORTED_PROFILE')
      return result(unsupported ? 'unsupported' : 'invalid', indexedFailures)
    }
  }

  for (let i = 0; i < chain.length; i++) {
    const delegation = chain[i]
    if (now < Date.parse(delegation.authority.time.not_before)) {
      return result('invalid', [{ code: 'NOT_YET_VALID', index: i, message: 'delegation is not yet valid' }])
    }
    if (now >= Date.parse(delegation.authority.time.not_after)) {
      return result('invalid', [{ code: 'EXPIRED', index: i, message: 'delegation has expired' }])
    }
    let revocation: 'active' | 'revoked' | 'unknown' = 'unknown'
    try {
      const resolved = options.resolveRevocation(delegation)
      revocation = resolved === 'active' || resolved === 'revoked' ? resolved : 'unknown'
    } catch { revocation = 'unknown' }
    if (revocation === 'revoked') {
      return result('invalid', [{ code: 'REVOKED', index: i, message: 'delegation is revoked' }])
    }
    if (revocation === 'unknown') {
      return result('indeterminate', [{ code: 'REVOCATION_UNKNOWN', index: i, message: 'revocation status is unknown' }])
    }
  }

  return result('valid', [])
}

export function verifyAuthorityDelegation(
  delegation: unknown,
  options: AuthorityChainVerificationOptions,
): AuthorityValidationResult {
  return verifyAuthorityDelegationChain([delegation], options)
}
