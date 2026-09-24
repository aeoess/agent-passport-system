// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0
//
// PROPOSED, OPT-IN. Whether an action through a named tool is established under a grant
// that pins that tool.
//
// SPECIFICATION POSITION. Not required by draft-pidlisnyi-aps-03. See ./types.ts.
// Concept source: aeoess/agent-authority-lifecycle, invariant candidate CAND-07 v2,
// whose statement is a verdict rule: "Where nothing pins it, the verdict records that
// referent continuity was not established rather than admitting silently. Where something
// pins it and the pin does not match, the action is denied with a mismatch reason rather
// than reported as not established."
//
// WHAT RUNS WHERE. This function decides the pin question and nothing else. Chain
// verification stays with the caller and is unchanged: run
// `verifyAuthorityDelegationChain` first, and if it does not return `valid` there is no
// capability question to ask. This module never sees a delegation, never reads a clock,
// never touches the network, and holds no policy.
//
// OPEN DESIGN QUESTIONS THIS CODE TAKES A POSITION ON, each recorded because a different
// position gives different outcomes for the same records:
//
//  1. Where a pin lives. This module implements `scope_grant_v0`, ./pins.ts states why and
//     states the narrowing side effect that follows.
//  2. What an established mismatch is. CAND-07 v2 says a denial with a mismatch reason,
//     and that is what this returns. The `aps-capability-binding-drift-v0` candidate
//     fixture family says `not_established` in a three-value vocabulary with no denial
//     member. See `projectBoundaryOutcomeToCandidateV0`.
//  3. What an unpinned grant gets. `not_established` with the coverage limb named, never a
//     silent admit. CAND-07 v2's unpinned limb, and the single highest-value thing in this
//     cluster to settle in the text, because it decides whether capability binding is
//     opt-in or the default.
//  4. Whether implementation and declared metadata are one pin or two. Two, pinned
//     separately, and an implementation pin does not cover a metadata change. A partial pin
//     is recorded as a partial pin.
//
// NOT DECIDED HERE. Whether a capability change should invalidate the grant (it does not,
// and nothing in this module makes any artifact invalid), what happens when a referent
// change NARROWS what a tool can do (CAND-07 v2 scopes that out, and this module gives an
// established mismatch in that direction too, which is a known false denial), and semantic
// drift generally, which the concept document's OPEN-QUESTIONS.md keeps open.

import { verifyToolIntegrity, type ToolRegistryEntry } from '../../core/tool-integrity.js'
import { capabilityPinIsEmpty } from './pins.js'
import {
  CapabilityBindingError,
  referentBindingResult,
  type CapabilityPin,
  type ReferentBindingResult,
  type ToolAttestationObservation,
} from './types.js'

/** Run the SDK's existing `verifyToolIntegrity` and record what it found, in the shape
 *  `evaluateCapabilityBinding` consumes.
 *
 *  `resolveTrustedAttestorKey` is keyed BY TOOL NAME, never by the `attestorId` the
 *  presented entry asserts about itself. That is the whole reason this is a callback: a
 *  valid signature establishes who signed, and standing to attest a particular tool is
 *  resolved outside the record asserting it. An entry signed by a perfectly real attestor
 *  who is not the attestor for this tool comes back with
 *  `attestor_signature_valid: false`.
 *
 *  Returns `attestor_key_resolved: false` and `attestor_signature_valid: false` when no key
 *  resolves, and does not run the signature check in that case. PROPOSED. */
export function observeToolAttestation(input: {
  registryEntry: ToolRegistryEntry
  requestedToolName: string
  /** The implementation bytes actually reachable behind the tool name now. */
  observedImplementation: string | Buffer
  resolveTrustedAttestorKey: (toolName: string) => string | null | undefined
}): ToolAttestationObservation {
  if (input === null || typeof input !== 'object') {
    throw new CapabilityBindingError('INPUT_INVALID', 'observeToolAttestation requires an input object')
  }
  const { registryEntry, requestedToolName, observedImplementation, resolveTrustedAttestorKey } = input
  if (registryEntry === null || typeof registryEntry !== 'object') {
    throw new CapabilityBindingError('REGISTRY_ENTRY_INVALID', 'registryEntry must be a ToolRegistryEntry')
  }
  if (typeof resolveTrustedAttestorKey !== 'function') {
    throw new CapabilityBindingError(
      'RESOLVER_INVALID',
      'resolveTrustedAttestorKey must be a function of the tool name',
    )
  }
  const attestorKey = resolveTrustedAttestorKey(requestedToolName)
  if (attestorKey === null || attestorKey === undefined || attestorKey.length === 0) {
    return Object.freeze({
      attested_tool_name: registryEntry.toolName,
      attested_implementation_digest: registryEntry.implementationHash,
      attestor_key_resolved: false,
      attestor_signature_valid: false,
    })
  }
  const integrity = verifyToolIntegrity({
    registryEntry,
    currentImplementation: observedImplementation,
    attestorPublicKey: attestorKey,
  })
  return Object.freeze({
    attested_tool_name: registryEntry.toolName,
    attested_implementation_digest: registryEntry.implementationHash,
    attestor_key_resolved: true,
    attestor_signature_valid: integrity.attestorSignatureValid,
  })
}

export interface CapabilityBindingInput {
  /** The tool the action is about to go through. */
  readonly requestedToolName: string
  /** Every scope grant the presented delegation carries, used for the required-scope check.
   *  Pass the leaf grant's own array: narrowing across a chain is chain verification's job
   *  and has already happened by the time this runs. */
  readonly grantedScopes: readonly string[]
  /** Scopes the action declares it needs, `scope_required` from an `aps-action-ref-v2`
   *  action reference. Default empty. */
  readonly requiredScopes?: readonly string[]
  /** The pin the grant carries for this tool. `null` means THE GRANT DOES NOT NAME THE TOOL
   *  AT ALL, which is a different answer from a grant that names it and pins nothing (a pin
   *  with both digest arrays empty). The caller passes it explicitly; there is no default,
   *  because a default here would be the design decision. Build it with
   *  `parseCapabilityPinFromScopeGrants`. */
  readonly pin: CapabilityPin | null
  /** What the caller established about the tool's attestation, from
   *  `observeToolAttestation`. `null` means none was presented. */
  readonly attestation: ToolAttestationObservation | null
  /** `sha256:` digest of the implementation reachable behind the tool name now. `null` means
   *  the caller observed nothing, which this module reports rather than assuming a match.
   *  Compute with `capabilityImplementationDigest`. */
  readonly observedImplementationDigest: string | null
  /** `sha256:` digest of the metadata the tool declares now. `null` means the caller
   *  observed nothing. Compute with `capabilityMetadataDigest`. */
  readonly observedMetadataDigest: string | null
}

/** Decide whether an action through `requestedToolName` is established under the grant that
 *  carries `pin`.
 *
 *  Five ordered steps, each one the reason a vector in the `capability-binding-drift`
 *  candidate family exists:
 *
 *  1. Does the grant name the tool, and does it carry the scopes the action declares.
 *  2. Is there an accepted attestation for this tool, from an attestor resolved for the
 *     tool, and does that signed claim still describe the implementation observed NOW. A
 *     registry entry is a claim; this step is what says the claim is not stale.
 *  3. The implementation pin. Compared against the ATTESTED digest, which step 2 has
 *     already established equals the observed digest, so the comparison is against a digest
 *     an attestor vouched for rather than against an unattested observation.
 *  4. The declared-metadata pin, pinned and checked separately from the implementation.
 *  5. Nothing left outstanding.
 *
 *  Never returns an artifact verdict and never makes any delegation invalid. PROPOSED. */
export function evaluateCapabilityBinding(input: CapabilityBindingInput): ReferentBindingResult {
  if (input === null || typeof input !== 'object') {
    throw new CapabilityBindingError('INPUT_INVALID', 'evaluateCapabilityBinding requires an input object')
  }
  const { requestedToolName, pin, attestation } = input
  if (typeof requestedToolName !== 'string' || requestedToolName.length === 0) {
    throw new CapabilityBindingError('TOOL_NAME_INVALID', 'requestedToolName must be a non-empty string')
  }
  if (!Array.isArray(input.grantedScopes)) {
    throw new CapabilityBindingError('GRANTS_INVALID', 'grantedScopes must be an array of strings')
  }
  if (pin !== null && pin.tool_name !== requestedToolName) {
    throw new CapabilityBindingError(
      'PIN_TOOL_MISMATCH',
      `pin is for ${pin.tool_name}, the action is for ${requestedToolName}`,
    )
  }

  // Step 1a. The grant has to name the tool. An established negative: the grant is in front
  // of the verifier and it does not say this.
  if (pin === null) {
    return referentBindingResult({
      outcome: 'denied',
      continuity: 'not_established',
      reason_code: 'TOOL_NOT_IN_GRANT_SCOPE',
      detail: `tool:${requestedToolName}`,
    })
  }

  // Step 1b. Scopes the action declares it needs.
  const required = input.requiredScopes ?? []
  const missingScopes = required.filter(scope => !input.grantedScopes.includes(scope))
  if (missingScopes.length > 0) {
    return referentBindingResult({
      outcome: 'denied',
      continuity: 'not_established',
      reason_code: 'SCOPE_NOT_GRANTED',
      detail: missingScopes.join(','),
    })
  }

  // Step 2. The attestation.
  if (attestation === null) {
    return referentBindingResult({
      outcome: 'not_established',
      continuity: 'not_established',
      reason_code: 'TOOL_ATTESTATION_ABSENT',
      missing: ['coverage'],
      detail: requestedToolName,
    })
  }
  if (!attestation.attestor_key_resolved) {
    return referentBindingResult({
      outcome: 'not_established',
      continuity: 'not_established',
      reason_code: 'TOOL_ATTESTOR_KEY_UNRESOLVED',
      missing: ['source'],
      detail: requestedToolName,
    })
  }
  if (!attestation.attestor_signature_valid) {
    return referentBindingResult({
      outcome: 'not_established',
      continuity: 'not_established',
      reason_code: 'TOOL_ATTESTATION_SIGNATURE_INVALID',
      missing: ['source'],
    })
  }
  if (attestation.attested_tool_name !== requestedToolName) {
    return referentBindingResult({
      outcome: 'not_established',
      continuity: 'not_established',
      reason_code: 'REGISTRY_ENTRY_TOOL_NAME_MISMATCH',
      missing: ['coverage'],
      detail: `${attestation.attested_tool_name}!=${requestedToolName}`,
    })
  }
  if (input.observedImplementationDigest === null) {
    return referentBindingResult({
      outcome: 'not_established',
      continuity: 'not_established',
      reason_code: 'OBSERVATION_ABSENT',
      missing: ['coverage'],
      detail: 'implementation',
    })
  }
  if (attestation.attested_implementation_digest !== input.observedImplementationDigest) {
    // The signed entry no longer describes what is reachable now. Freshness, not source:
    // the claim is authentic and from the right party, and it is out of date.
    return referentBindingResult({
      outcome: 'not_established',
      continuity: 'not_established',
      reason_code: 'REGISTRY_ENTRY_IMPLEMENTATION_MISMATCH',
      missing: ['freshness'],
      detail: `attested=${attestation.attested_implementation_digest} observed=${input.observedImplementationDigest}`,
    })
  }

  // Step 3. The implementation pin.
  if (pin.implementation_digests.length === 0) {
    if (capabilityPinIsEmpty(pin)) {
      // CAND-07 v2's unpinned limb. The grant gives the verifier no basis to establish that
      // the implementation behind this name is the one the principal granted against, and
      // that is recorded rather than resolved either way. Note this holds whether or not the
      // tool in fact changed: the absence of a change is not something an unpinned grant
      // establishes.
      return referentBindingResult({
        outcome: 'not_established',
        continuity: 'not_established',
        reason_code: 'NO_CAPABILITY_PIN_IN_GRANT',
        missing: ['coverage'],
        detail: `tool:${requestedToolName}`,
      })
    }
    return referentBindingResult({
      outcome: 'not_established',
      continuity: 'not_established',
      reason_code: 'IMPLEMENTATION_NOT_PINNED_IN_GRANT',
      missing: ['coverage'],
      detail: `tool:${requestedToolName}`,
    })
  }
  if (!pin.implementation_digests.includes(attestation.attested_implementation_digest)) {
    // ESTABLISHED NEGATIVE. The verifier reached a conclusion and the conclusion is that the
    // pinned referent changed. CAND-07 v2: a denial with a mismatch reason, not ignorance.
    return referentBindingResult({
      outcome: 'denied',
      continuity: 'mismatch',
      reason_code: 'PINNED_IMPLEMENTATION_DIGEST_MISMATCH',
      detail: `pinned=${pin.implementation_digests.join('|')} attested=${attestation.attested_implementation_digest}`,
    })
  }

  // Step 4. The declared-metadata pin. A tool can keep both its name and its implementation
  // digest while its declared schema and permissions change and gain a destructive
  // permission, so this axis is pinned and checked on its own.
  if (pin.metadata_digests.length === 0) {
    return referentBindingResult({
      outcome: 'not_established',
      continuity: 'not_established',
      reason_code: 'METADATA_NOT_PINNED_IN_GRANT',
      missing: ['coverage'],
      detail: `tool:${requestedToolName}`,
    })
  }
  if (input.observedMetadataDigest === null) {
    return referentBindingResult({
      outcome: 'not_established',
      continuity: 'not_established',
      reason_code: 'OBSERVATION_ABSENT',
      missing: ['coverage'],
      detail: 'metadata',
    })
  }
  if (!pin.metadata_digests.includes(input.observedMetadataDigest)) {
    return referentBindingResult({
      outcome: 'denied',
      continuity: 'mismatch',
      reason_code: 'PINNED_METADATA_DIGEST_MISMATCH',
      detail: `pinned=${pin.metadata_digests.join('|')} observed=${input.observedMetadataDigest}`,
    })
  }

  // Step 5.
  return referentBindingResult({
    outcome: 'authorized',
    continuity: 'established',
    reason_code: 'CAPABILITY_CONTINUITY_ESTABLISHED',
  })
}
