// Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// Soundness verifier for the ID-JAG to APS binding descriptor.
// Pinned to draft-ietf-oauth-identity-assertion-authz-grant-04 (2026-05-21).
//
// This is the spec made executable. It checks structural soundness only:
// the two anchors recompute, the caller verification signature is valid, no
// spend unit was synthesized, and the draft pin is present. It does NOT decide
// whether an action is allowed, and it NEVER returns a bare safe-for-execution
// boolean: carried external constraints (audience, revocation) are unchecked
// here, so a sound descriptor reports
// structurally_valid_with_unchecked_external_constraints.

import { canonicalHashJCS } from '../../core/canonical-jcs.js'
import { computeDelegationChainRoot } from '../../decisionReceipt.js'
import { verify as verifySignature } from '../../crypto/keys.js'
import { IDJAG_DRAFT, SOURCE_GRANT_REF_TAG } from './types.js'
import type { IdJagDescriptor, IdJagVerifyResult } from './types.js'

const ALLOWED_PREIMAGE_KEYS = new Set([
  'tag', 'draft', 'iss', 'sub', 'jti', 'client_id', 'aud', 'resource', 'exp',
])
const VALID_SPEND_UNITS = new Set(['currency', 'invocations'])

/**
 * Verify an ID-JAG binding descriptor for structural soundness. Recomputes
 * delegationChainRoot over chain content and sourceGrantRef over its committed
 * preimage, confirms the preimage carries only provenance and binding-target
 * fields, confirms the caller attestation signature verifies under the caller
 * key, confirms audience is marked unenforced, and confirms no spend unit was
 * silently synthesized. Returns a status that never collapses unchecked external
 * constraints into a safe-for-execution boolean.
 */
export function verifyIdJagDescriptor(descriptor: IdJagDescriptor): IdJagVerifyResult {
  const failures: string[] = []

  const draftPinned = descriptor.draft === IDJAG_DRAFT
  if (!draftPinned) failures.push(`draft pin missing or wrong: expected ${IDJAG_DRAFT}, got ${String(descriptor.draft)}`)

  const pre = descriptor.sourceGrantRefPreimage
  const preimageKeysClean = pre !== undefined
    && pre.tag === SOURCE_GRANT_REF_TAG
    && Object.keys(pre).every((k) => ALLOWED_PREIMAGE_KEYS.has(k))
  if (!preimageKeysClean) failures.push('sourceGrantRef preimage carries fields beyond provenance and binding target, or wrong tag')

  const sourceGrantRefRecomputes = preimageKeysClean
    && canonicalHashJCS(pre as unknown as Record<string, unknown>) === descriptor.sourceGrantRef
  if (!sourceGrantRefRecomputes) failures.push('sourceGrantRef does not recompute from its preimage')

  const delegationChainRootRecomputes = computeDelegationChainRoot(descriptor.chain) === descriptor.delegationChainRoot
  if (!delegationChainRootRecomputes) failures.push('delegationChainRoot does not recompute over chain content')

  const cv = descriptor.callerVerification
  const expectedMessage = `verified grant ${descriptor.sourceGrantRef} at ${cv?.verifiedAt}`
  const attestationSignatureValid = cv !== undefined
    && cv.message === expectedMessage
    && verifySignature(cv.message, cv.signature, cv.signerPublicKey)
  if (!attestationSignatureValid) failures.push('caller verification attestation signature does not verify under the caller key')

  const audienceMarkedUnenforced = descriptor.carriedAudience?.enforcement === 'not_enforced_by_binding'
  if (!audienceMarkedUnenforced) failures.push('carriedAudience is not marked not_enforced_by_binding')

  const unitSet = descriptor.spendLimitUnit !== undefined
  const limitSet = descriptor.spendLimit !== undefined
  const noSilentSpendUnit = (unitSet === limitSet)
    && (descriptor.spendLimitUnit === undefined || VALID_SPEND_UNITS.has(descriptor.spendLimitUnit))
  if (!noSilentSpendUnit) failures.push('spend unit is synthesized, naked, or not a recognized value')

  const ok = draftPinned && preimageKeysClean && sourceGrantRefRecomputes
    && delegationChainRootRecomputes && attestationSignatureValid
    && audienceMarkedUnenforced && noSilentSpendUnit

  return {
    ok,
    status: ok ? 'structurally_valid_with_unchecked_external_constraints' : 'unsound',
    checks: {
      draftPinned,
      sourceGrantRefRecomputes,
      sourceGrantRefPreimageScopeClean: preimageKeysClean,
      delegationChainRootRecomputes,
      attestationSignatureValid,
      audienceMarkedUnenforced,
      noSilentSpendUnit,
    },
    failures,
  }
}
