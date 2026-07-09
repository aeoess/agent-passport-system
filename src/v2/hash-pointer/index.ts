// Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// ══════════════════════════════════════════════════════════════════════
// @aeoess hash-and-pointer payloads + field-disclosure profile.
// ══════════════════════════════════════════════════════════════════════
//
// One additive, versioned receipt slot and its builder/verifier:
//
//   - A receipt commits to a payload by SHA-256 hash plus a URI pointer,
//     never embedding the raw payload.
//   - Each field carries a per-field disclosure policy (public, hash_only,
//     encrypted, redacted) with a hash binding that survives redaction, so
//     the receipt signature still verifies over the profile.
//   - The builder rejects a raw value for any field marked sensitive.
//   - A BBS selective-disclosure proof can be carried by reference, bridged
//     structurally from the isolated @aeoess/aps-bbs-credentials package
//     without importing it into core.
//
// See README.md in this directory for the full proof box.
// ══════════════════════════════════════════════════════════════════════

export type {
  FieldDisclosurePolicy,
  HashPointerAlgorithm,
  HashPointerPayload,
  DisclosedField,
  FieldDisclosureProofRef,
  FieldDisclosureProfile,
  BuildFieldDisclosureProfileInput,
  FieldDisclosureVerification,
} from './types.js'
export { REDACTED_SENTINEL } from './types.js'

export {
  buildFieldDisclosureProfile,
  verifyFieldDisclosureProfile,
  canonicalProfileBytes,
} from './profile.js'

export type { BbsDisclosureProofShape } from './bbs-bridge.js'
export {
  bbsProofToFieldDisclosureRef,
  fieldDisclosureRefToBbsProof,
} from './bbs-bridge.js'
