// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0

import {
  authorityDelegationBody,
  computeAuthorityDelegationId,
  verifyAuthorityDelegationSignature,
} from './canonical.js'
import { compareAuthority } from './compare.js'
import { readPlainDataChainContainer, snapshotPlainData } from './plain-data.js'
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

const UNSUPPORTED_CODES = new Set(['UNSUPPORTED_VERSION', 'UNSUPPORTED_RECORD_TYPE', 'UNSUPPORTED_PROFILE'])

/**
 * The state a set of shape failures on one member produces.
 *
 * A conformance failure dominates: it is a statement about the record, where the other
 * two are statements about what could be evaluated. Between the remaining two,
 * unsupported dominates indeterminate, because a record this schema does not claim was
 * never going to be judged by it whatever ceiling it also crossed. The draft orders none
 * of this: it is fail-closed precedence inside one phase, and no vector claims it is
 * normative.
 */
function shapeState(failures: readonly AuthorityFailure[]): AuthorityValidationState {
  if (failures.some(item => !UNSUPPORTED_CODES.has(item.code) && item.code !== 'RESOURCE_LIMIT')) return 'invalid'
  if (failures.some(item => UNSUPPORTED_CODES.has(item.code))) return 'unsupported'
  return 'indeterminate'
}

/**
 * Full root-to-leaf structural, cryptographic, temporal, and revocation validation.
 *
 * Each chain member is snapshotted to plain JSON data (see plain-data.ts) before any
 * other read of it, and every later read in this function comes from that snapshot,
 * never from the caller's original chain member: the strings passed to
 * `options.resolveVerificationKey` are read from it, and `options.trustRoot` and
 * `options.resolveRevocation` are each handed a fresh copy of it.
 *
 * `options.trustRoot` is handed a copy, not the snapshot itself, because this function
 * reads that snapshot again after the callback returns: the child-to-parent linkage
 * loop, with its continuity, issuance-time and attenuation checks, and then the
 * validity and revocation checks on every member, all run after it. The root's own
 * null-parent check and the duplicate-identifier check run before it. A trust callback that wrote to what it was given would
 * otherwise change what those checks see, and a chain that widens its parent's authority
 * would verify valid. `options.resolveRevocation` is handed a copy for the same reason
 * rather than from the same need: it is called last, after every other check of that
 * member, so a write there changes nothing this function still reads. The child issuer
 * is where a revocation callback's write does reach later checks, and it copies too.
 * What a callback does to its own copy changes nothing in either place.
 *
 * The four members of `options` are read once each, immediately after the chain
 * container check, so a caller object whose property is a getter cannot answer one way
 * when a value is checked and another way when it is used. A container that fails that
 * check returns before any of them is read. A getter that throws leaves that member
 * undefined, which gives the same coded result an unusable one gives. This function
 * never throws.
 */
export function verifyAuthorityDelegationChain(
  rawChain: readonly unknown[],
  options: AuthorityChainVerificationOptions,
): AuthorityValidationResult {
  // A chain that is not a usable container at all is invalid: there is nothing to
  // verify. A chain longer than this implementation's 256-record ceiling is a different
  // answer. The draft states no maximum chain length, so the ceiling is this
  // implementation declining to judge rather than the protocol refusing the record, and
  // it is reported under its own code as indeterminate.
  const rejection = { reason: 'not-a-container' as const } as { reason: 'not-a-container' | 'over-ceiling' }
  const container = readPlainDataChainContainer(rawChain, 1, 256, rejection)
  if (!container) {
    return rejection.reason === 'over-ceiling'
      ? result('indeterminate', [{ code: 'RESOURCE_LIMIT', message: "chain exceeds this implementation's 256-record ceiling" }])
      : result('invalid', [{ code: 'SCHEMA_INVALID', message: 'chain must be a container of at least one record' }])
  }
  // Each member of `options` is read exactly once, here, and every use below is of the
  // value read here. A getter that throws leaves the member undefined, which reaches the
  // same coded result an unusable member of that name reaches.
  const read = (key: keyof AuthorityChainVerificationOptions): unknown => {
    try { return options ? options[key] : undefined } catch { return undefined }
  }
  const now = read('now') as AuthorityChainVerificationOptions['now']
  const trustRoot = read('trustRoot') as AuthorityChainVerificationOptions['trustRoot'] | undefined
  const resolveVerificationKey = read('resolveVerificationKey') as AuthorityChainVerificationOptions['resolveVerificationKey'] | undefined
  const resolveRevocation = read('resolveRevocation') as AuthorityChainVerificationOptions['resolveRevocation'] | undefined
  if (!isCanonicalTimestamp(now)) {
    return result('invalid', [{ code: 'NONCANONICAL_VALUE', message: 'verification clock must be canonical UTC milliseconds' }])
  }

  const chain: AuthorityDelegationV1[] = []
  for (let i = 0; i < container.length; i++) {
    const snapshot = snapshotPlainData(container[i])
    const failures = validateAuthorityDelegationShape(snapshot).map(item => indexed(item, i))
    if (failures.length > 0) {
      return result(shapeState(failures), failures)
    }
    chain.push(snapshot as AuthorityDelegationV1)
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
      publicKey = resolveVerificationKey!(
        delegation.issuer,
        delegation.verification_method,
        delegation.issued_at,
      )
    } catch {
      publicKey = null
    }
    if (publicKey === null || publicKey === undefined) {
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
  if (typeof trustRoot !== 'function') {
    return result('indeterminate', [{ code: 'ROOT_UNTRUSTED', index: 0, message: 'root trust policy is unavailable' }])
  }
  let trustDecision: unknown
  // A fresh copy, never the snapshot this function keeps reading: see the doc comment.
  try { trustDecision = trustRoot(snapshotPlainData(root) as AuthorityDelegationV1) } catch {
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
    const issued = child.issued_at
    if (issued < parent.authority.time.not_before ||
        issued >= parent.authority.time.not_after) {
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
    if (now < delegation.authority.time.not_before) {
      return result('invalid', [{ code: 'NOT_YET_VALID', index: i, message: 'delegation is not yet valid' }])
    }
    if (now >= delegation.authority.time.not_after) {
      return result('invalid', [{ code: 'EXPIRED', index: i, message: 'delegation has expired' }])
    }
    let revocation: 'active' | 'revoked' | 'unknown' = 'unknown'
    try {
      const resolved = resolveRevocation!(snapshotPlainData(delegation) as AuthorityDelegationV1)
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
