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
  AuthorityFailureCode,
  AuthorityValidationResult,
  AuthorityValidationState,
  KeyResolutionFailure,
} from './types.js'

function result(state: AuthorityValidationState, failures: AuthorityFailure[]): AuthorityValidationResult {
  return { state, valid: state === 'valid', failures }
}

function indexed(failure: AuthorityFailure, index: number): AuthorityFailure {
  return { ...failure, index }
}

/** Well-formed Ed25519 public key material: 32 bytes as hexadecimal. A resolver that
 *  hands back anything else has produced structurally malformed material, and the
 *  signature check must not run on it: reporting SIGNATURE_INVALID there would say the
 *  bytes were checked and failed when nothing was checked at all. Case is not narrowed
 *  here, because the verifier accepted either case before this and the ruling is about
 *  which outcome is reported, not about which keys resolve. */
const KEY_MATERIAL = /^[0-9a-fA-F]{64}$/

interface KeyFailure {
  state: AuthorityValidationState
  code: AuthorityFailureCode
  message: string
}

/** Map a resolver's answer to the draft's section 2.5 outcomes, or null when it
 *  resolved. An unsupported identifier scheme is unsupported; everything else that is
 *  not a usable key is indeterminate, each under its own code. */
function keyResolutionFailure(resolved: string | null | KeyResolutionFailure | undefined): KeyFailure | null {
  if (typeof resolved === 'string') {
    return KEY_MATERIAL.test(resolved)
      ? null
      : { state: 'indeterminate', code: 'KEY_MATERIAL_MALFORMED', message: 'resolved key material is not a 32-byte Ed25519 public key' }
  }
  if (resolved && typeof resolved === 'object' && typeof (resolved as KeyResolutionFailure).outcome === 'string') {
    switch ((resolved as KeyResolutionFailure).outcome) {
      case 'unsupported_scheme':
        return { state: 'unsupported', code: 'KEY_SCHEME_UNSUPPORTED', message: 'identifier scheme is not supported by the resolver' }
      case 'not_found':
        return { state: 'indeterminate', code: 'KEY_NOT_FOUND', message: 'subject or key was not found' }
      case 'ambiguous':
        return { state: 'indeterminate', code: 'KEY_AMBIGUOUS', message: 'key resolution was ambiguous' }
      case 'unreachable':
        return { state: 'indeterminate', code: 'KEY_UNREACHABLE', message: 'key material was unreachable' }
      case 'malformed':
        return { state: 'indeterminate', code: 'KEY_MATERIAL_MALFORMED', message: 'resolved key material is structurally malformed' }
      default:
        break
    }
  }
  return { state: 'indeterminate', code: 'KEY_RESOLUTION_FAILED', message: 'issuer verification key could not be resolved' }
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

  // Draft line 580 lists the order as phases over the whole root-to-leaf chain, not as a
  // pass over each member in turn: closed schema and canonical values; delegation_id;
  // historical signing-key resolution and signature; duplicate identifiers; root trust;
  // parent_delegation_id; issuer-to-subject continuity; child issuance time; the seven
  // facet comparisons; current validity; and revocation state for every member.
  //
  // This function used to run phases 2, 3 and 4 inside one loop over the members, so a
  // later member's signature failure could be reported where an earlier member's
  // duplicate identifier comes first in the listed order. The first failing listed phase
  // now decides the state and the code, and within that phase the lowest member index
  // wins. Two faults inside one phase that the draft does not order have no normative
  // winner, and no vector claims one.

  // Phase 1: closed schema and canonical values, member by member.
  const chain: AuthorityDelegationV1[] = []
  for (let i = 0; i < container.length; i++) {
    const snapshot = snapshotPlainData(container[i])
    const failures = validateAuthorityDelegationShape(snapshot).map(item => indexed(item, i))
    if (failures.length > 0) {
      return result(shapeState(failures), failures)
    }
    chain.push(snapshot as AuthorityDelegationV1)
  }

  // Phase 2: delegation_id.
  for (let i = 0; i < chain.length; i++) {
    const delegation = chain[i]
    if (computeAuthorityDelegationId(authorityDelegationBody(delegation)) !== delegation.delegation_id) {
      return result('invalid', [{ code: 'ID_MISMATCH', index: i, message: 'delegation content address does not match body' }])
    }
  }

  // Phase 3: historical signing-key resolution, then the signature it resolves. The
  // resolver is called with the record's own issued_at, which is what selects the key
  // version: a key current at verification time is not the one that signed this record
  // (draft lines 313-315 and 353-357).
  for (let i = 0; i < chain.length; i++) {
    const delegation = chain[i]
    let resolved: string | null | KeyResolutionFailure = null
    try {
      resolved = resolveVerificationKey!(
        delegation.issuer,
        delegation.verification_method,
        delegation.issued_at,
      )
    } catch {
      resolved = null
    }
    const failure = keyResolutionFailure(resolved)
    if (failure) return result(failure.state, [{ code: failure.code, index: i, message: failure.message }])
    if (!verifyAuthorityDelegationSignature(delegation, resolved as string)) {
      return result('invalid', [{ code: 'SIGNATURE_INVALID', index: i, message: 'Ed25519 signature is invalid' }])
    }
  }

  // Phase 4: duplicate identifiers. The index reported is the member that repeats one
  // an earlier member already carried.
  const seen = new Set<string>()
  for (let i = 0; i < chain.length; i++) {
    const id = chain[i].delegation_id
    if (seen.has(id)) {
      return result('invalid', [{ code: 'CHAIN_DUPLICATE_ID', index: i, message: 'delegation ID repeats in chain' }])
    }
    seen.add(id)
  }

  // Phase 5: root trust.
  const root = chain[0]
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

  // Phase 6: parent_delegation_id, the root's null and every child's link.
  if (root.parent_delegation_id !== null) {
    return result('invalid', [{ code: 'PARENT_MISMATCH', index: 0, message: 'full chain root must carry null parent_delegation_id' }])
  }
  for (let i = 1; i < chain.length; i++) {
    if (chain[i].parent_delegation_id !== chain[i - 1].delegation_id) {
      return result('invalid', [{ code: 'PARENT_MISMATCH', index: i, message: 'child does not name immediate parent content address' }])
    }
  }

  // Phase 7: issuer-to-subject continuity.
  for (let i = 1; i < chain.length; i++) {
    if (chain[i].issuer !== chain[i - 1].subject) {
      return result('invalid', [{ code: 'CHAIN_CONTINUITY', index: i, message: 'child issuer is not parent subject' }])
    }
  }

  // Phase 8: child issuance time.
  for (let i = 1; i < chain.length; i++) {
    const parent = chain[i - 1]
    const issued = chain[i].issued_at
    if (issued < parent.authority.time.not_before || issued >= parent.authority.time.not_after) {
      return result('invalid', [{ code: 'ISSUED_AT_OUTSIDE_PARENT', index: i, message: 'child was issued outside parent validity window' }])
    }
  }

  // Phase 9: the seven facet comparisons.
  for (let i = 1; i < chain.length; i++) {
    const attenuationFailures = compareAuthority(chain[i - 1].authority, chain[i].authority)
    if (attenuationFailures.length > 0) {
      const indexedFailures = attenuationFailures.map(item => indexed(item, i))
      const unsupported = indexedFailures.every(item => item.code === 'UNSUPPORTED_PROFILE')
      return result(unsupported ? 'unsupported' : 'invalid', indexedFailures)
    }
  }

  // Phase 10: current validity.
  for (let i = 0; i < chain.length; i++) {
    const time = chain[i].authority.time
    if (now < time.not_before) {
      return result('invalid', [{ code: 'NOT_YET_VALID', index: i, message: 'delegation is not yet valid' }])
    }
    if (now >= time.not_after) {
      return result('invalid', [{ code: 'EXPIRED', index: i, message: 'delegation has expired' }])
    }
  }

  // Phase 11: revocation state for every member.
  for (let i = 0; i < chain.length; i++) {
    let revocation: 'active' | 'revoked' | 'unknown' = 'unknown'
    try {
      const resolved = resolveRevocation!(snapshotPlainData(chain[i]) as AuthorityDelegationV1)
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
