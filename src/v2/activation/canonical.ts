// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0
//
// PROPOSED, OPT-IN. Canonical bytes for the two records this module owns.
// See ./types.ts for the specification position: draft-pidlisnyi-aps-03 states no
// activation-condition rule, and nothing here changes any existing exported behaviour.

import { createHash } from 'node:crypto'
import { canonicalizeJCS } from '../../core/canonical-jcs.js'
import type { ActivationAttestationV0, ActivationConditionV0 } from './types.js'

/** Domain tag for an activation attestation's signature preimage. Distinct APS tag followed
 *  by one zero byte, the same discipline `AuthorityDelegationV1` and `AuthorityRevocationV1`
 *  follow, so bytes minted for one construction can never be read as bytes minted for
 *  another. `PROPOSED` is inside the tag on purpose: if this record is ever ruled into APS
 *  under a settled name, its bytes will differ from these, and nothing signed under a
 *  proposed tag can be replayed as a specified record. */
export const ACTIVATION_ATTESTATION_SIGNATURE_DOMAIN =
  'APS-PROPOSED-ACTIVATION-ATTESTATION-SIGNATURE-V0\0'

/** Domain tag for an activation attestation's identifier preimage. */
export const ACTIVATION_ATTESTATION_ID_DOMAIN = 'APS-PROPOSED-ACTIVATION-ATTESTATION-ID-V0\0'

/** Domain tag for an activation condition's signature preimage.
 *
 *  Whether a condition record MUST be signed, and by whom, is not settled. The grant's issuer
 *  is the obvious answer and is not the only defensible one: a condition that narrows an
 *  already issued grant could come from any party with lifecycle standing over it, and where
 *  lifecycle standing comes from is itself unsettled. `verifyActivation` therefore does NOT
 *  require a signature on the condition, and this tag exists so a deployment that does sign
 *  its conditions has one preimage to sign rather than inventing one. */
export const ACTIVATION_CONDITION_SIGNATURE_DOMAIN =
  'APS-PROPOSED-ACTIVATION-CONDITION-SIGNATURE-V0\0'

function sha256Hex(value: string): string {
  return createHash('sha256').update(value, 'utf8').digest('hex')
}

/** The signed body of an attestation: every member except `attestation_id` and `signature`.
 *
 *  Both are excluded because both are derived from the body: the identifier is a digest over
 *  these bytes and the signature covers the same bytes. Every other member, including ones
 *  this module never interprets, is inside the preimage, so nothing on the record is
 *  unauthenticated. */
export function activationAttestationBody(
  attestation: ActivationAttestationV0,
): Record<string, unknown> {
  const body: Record<string, unknown> = {}
  for (const [key, value] of Object.entries(attestation)) {
    if (key === 'attestation_id' || key === 'signature') continue
    body[key] = value
  }
  return body
}

/** Exact Ed25519 input for an attestation this module owns: the domain tag plus RFC 8785 JCS
 *  of the body.
 *
 *  This is the DEFAULT preimage, used when the caller supplies no
 *  `attestationPreimage`. Which bytes a signature covers is a property of a record type, and
 *  this module owns exactly one record type, so a model that accepts condition evidence in
 *  another shape supplies its own preimage function. See ./verify.ts. */
export function activationAttestationSignatureInput(attestation: ActivationAttestationV0): string {
  return (
    ACTIVATION_ATTESTATION_SIGNATURE_DOMAIN + canonicalizeJCS(activationAttestationBody(attestation))
  )
}

/** Content-bound identifier for an attestation this module owns. Recomputable by a verifier
 *  rather than accepted as whatever the attestor wrote there. */
export function computeActivationAttestationId(attestation: ActivationAttestationV0): string {
  return `sha256:${sha256Hex(
    ACTIVATION_ATTESTATION_ID_DOMAIN + canonicalizeJCS(activationAttestationBody(attestation)),
  )}`
}

/** Exact Ed25519 input for a condition record, for a deployment that chooses to sign one. */
export function activationConditionSignatureInput(condition: ActivationConditionV0): string {
  return ACTIVATION_CONDITION_SIGNATURE_DOMAIN + canonicalizeJCS(condition)
}
