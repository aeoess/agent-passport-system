// Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// ══════════════════════════════════════════════════════════════════════
// Hash-and-Pointer - BBS Composition Bridge (structural, isolation-safe)
// ══════════════════════════════════════════════════════════════════════
//
// The field-disclosure profile can carry a BBS selective-disclosure proof by
// reference. The BBS implementation lives in @aeoess/aps-bbs-credentials, an
// EXPERIMENTAL, ISOLATED package that is NOT imported by core and is NOT
// core-reviewed crypto. To keep that isolation, this bridge takes the proof as
// a STRUCTURAL shape (the byte arrays the package produces) and converts it to
// the JSON-canonicalizable FieldDisclosureProofRef. It never imports the BBS
// package and never runs BBS math.
//
// A relying party that holds the isolated package can reconstruct the byte
// arrays from this reference and verify the proof out of band. The composition
// test wires the real package against this bridge.
// ══════════════════════════════════════════════════════════════════════

import type { FieldDisclosureProofRef } from './types.js'

/** The minimal structural shape this bridge consumes from a BBS disclosure
 *  proof. It mirrors @aeoess/aps-bbs-credentials' ScopeDisclosureProof by field
 *  names and types, copied (not imported) to preserve package isolation. The
 *  scopes are the field NAMES being disclosed in the receipt context. */
export interface BbsDisclosureProofShape {
  publicKey: Uint8Array
  header: Uint8Array
  presentationHeader: Uint8Array
  disclosedScopes: string[]
  disclosedIndexes: number[]
  proof: Uint8Array
  totalScopes: number
  ciphersuite: 'SHA-256' | 'SHAKE-256'
}

function toBase64(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString('base64')
}

function fromBase64(b64: string): Uint8Array {
  return new Uint8Array(Buffer.from(b64, 'base64'))
}

/**
 * Convert a BBS disclosure proof (byte-array shape) into a receipt-embeddable,
 * JSON-canonicalizable FieldDisclosureProofRef. Pure data reshaping; no crypto.
 */
export function bbsProofToFieldDisclosureRef(
  proof: BbsDisclosureProofShape
): FieldDisclosureProofRef {
  return {
    format: 'bbs-2023',
    ciphersuite: proof.ciphersuite,
    public_key_b64: toBase64(proof.publicKey),
    header_b64: toBase64(proof.header),
    presentation_header_b64: toBase64(proof.presentationHeader),
    disclosed_fields: [...proof.disclosedScopes],
    disclosed_indexes: [...proof.disclosedIndexes],
    proof_b64: toBase64(proof.proof),
    total_fields: proof.totalScopes,
  }
}

/**
 * Reconstruct the BBS disclosure proof byte-array shape from a stored
 * FieldDisclosureProofRef, so a holder of the isolated BBS package can verify
 * it. Pure data reshaping; no crypto.
 */
export function fieldDisclosureRefToBbsProof(
  ref: FieldDisclosureProofRef
): BbsDisclosureProofShape {
  return {
    publicKey: fromBase64(ref.public_key_b64),
    header: fromBase64(ref.header_b64),
    presentationHeader: fromBase64(ref.presentation_header_b64),
    disclosedScopes: [...ref.disclosed_fields],
    disclosedIndexes: [...ref.disclosed_indexes],
    proof: fromBase64(ref.proof_b64),
    totalScopes: ref.total_fields,
    ciphersuite: ref.ciphersuite,
  }
}
