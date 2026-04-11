// ══════════════════════════════════════════════════════════════════
// Behavioral Fingerprint — Three-Axis Joint Measurement Envelope
// ══════════════════════════════════════════════════════════════════
// Composes three independent behavioral measurement axes into one signed
// artifact:
//
//   Axis 1 (within-session authority-pressure fidelity):
//     AEOESS Hold/Bend/Break — src/core/fidelity-probe.ts
//
//   Axis 2 (cross-session output reliability):
//     PDR score reference — produced by NexusGuard or any pdr.score.v1 issuer
//
//   Axis 3 (within-session constraint compliance under value pressure):
//     Saebo et al. constraint score reference — produced by an external scorer
//
// The envelope does NOT combine the three axes into a single composite
// score. The orthogonality claim from Nanook PDR v2.19 §2.2 is untested,
// and baking a combinator policy into the SDK would prejudge that result.
// composeFingerprintAxes() is a pure projection helper, nothing more.
//
// Signing: Ed25519. The envelope signature covers the canonical JSON of
// {subject, fidelity, pdr_ref, constraint_ref, measurerId, signedAt} —
// every field except the signature itself. Inner FidelityAttestation
// objects retain their own signatures (signed by their own measurer); the
// envelope signature covers them as JSON content but does not replace
// their independent verifiability.
//
// Reference: Nanook PDR v2.19 §2.2 (three-axis framework), §8.10 (joint
// experiment design), gap audit §3 row 10, gap audit §5 rank 2.
// ══════════════════════════════════════════════════════════════════

import { sign, verify } from '../crypto/keys.js'
import { canonicalize } from './canonical.js'
import { verifyFidelityAttestation } from './fidelity-probe.js'
import type { FidelityAttestation } from '../types/gateway.js'

// ── PDR Score Reference (Axis 2) ──

/** Reference to a PDR (Probabilistic Delegation Reliability) score event,
 *  as defined in Nanook PDR v2.19 §6.3. The pdr.score.v1 wire format is
 *  not yet a published spec; this interface mirrors the field set the paper
 *  attributes to NexusGuard's AIP implementation (aip_identity/pdr.py).
 *
 *  This is an EXTERNAL reference — the SDK does not produce these scores,
 *  it only carries them inside a fingerprint envelope. The optional
 *  signature field is the score's own external signature (e.g. from the
 *  NexusGuard issuer); verifyBehavioralFingerprint does NOT validate it. */
export interface PDRScoreRef {
  source: 'pdr.score.v1'
  /** Composite PDR score in [0, 1]. Per Nanook §6.3: weighted combination of
   *  Calibration (0.5), Adaptation (0.2), Robustness (0.3). */
  scoreOverall: number
  /** Calibration sub-score in [0, 1]. Jaccard similarity of claimed vs delivered. */
  scoreCalibration: number
  /** Adaptation sub-score in [0, 1]. Temporal improvement slope. */
  scoreAdaptation: number
  /** Robustness sub-score in [0, 1]. Condition-based variance. */
  scoreRobustness: number
  /** Number of behavioral observations the score is computed over. */
  observationCount: number
  /** Temporal spread of those observations, in days. */
  windowDays: number
  /** Identifier of the issuing PDR scorer (e.g. 'nexusguard-aip-0.5.48'). */
  issuer: string
  /** ISO 8601 timestamp of score issuance. */
  issuedAt: string
  /** Optional external signature from the PDR issuer. NOT validated by
   *  verifyBehavioralFingerprint — see JSDoc on that function. */
  signature?: string
}

// ── Saebo Constraint Score Reference (Axis 3) ──

/** Reference to a within-session constraint compliance score, in the style
 *  of Saebo et al. arXiv:2603.03456 ("Asymmetric Goal Drift in Coding Agents
 *  Under Value Conflict"). Measures whether the agent maintained its
 *  declared value hierarchy under context pressure across a session.
 *
 *  Like PDRScoreRef, this is an external reference. The SDK does not
 *  produce Saebo scores; it carries them inside the envelope so consumers
 *  that want all three axes have one signed artifact to verify. */
export interface SaeboScoreRef {
  source: 'saebo.constraint.v1'
  /** Compliance score in [0, 1]: 1.0 = no violations across session,
   *  0.0 = constraint violated on every turn. */
  complianceScore: number
  /** Number of constraint violations observed in the session. */
  violationCount: number
  /** Total turn count of the session being scored. */
  sessionTurnCount: number
  /** Identifier of the issuing constraint scorer. */
  issuer: string
  /** ISO 8601 timestamp of score issuance. */
  issuedAt: string
  /** Optional external signature from the issuer. NOT validated by
   *  verifyBehavioralFingerprint. */
  signature?: string
}

// ── Behavioral Fingerprint Envelope ──

/** Three-axis behavioral measurement envelope. Always carries at least one
 *  HBB FidelityAttestation (axis 1). PDR and Saebo references are optional
 *  axes — a fingerprint with only fidelity is still well-formed. */
export interface BehavioralFingerprint {
  subject: {
    /** DID of the subject agent being measured (not the measurer). */
    did: string
    /** LLM substrate identifier the subject was running on at measurement
     *  time (e.g. 'claude-sonnet-4', 'gpt-5-turbo'). */
    substrate: string
  }
  /** One or more HBB attestations. Multiple attestations are common when
   *  the substrate-swap protocol from Nanook §8.10 takes pre/post probes. */
  fidelity: FidelityAttestation[]
  /** Optional axis 2: PDR cross-session reliability reference. */
  pdr_ref?: PDRScoreRef
  /** Optional axis 3: Saebo within-session constraint compliance reference. */
  constraint_ref?: SaeboScoreRef
  /** Identifier of the party that composed and signed this envelope.
   *  May or may not be the same party that produced the inner
   *  FidelityAttestations (which carry their own measuredBy). */
  measurerId: string
  /** Hex-encoded Ed25519 public key of the envelope signer. Embedded so
   *  third parties can verify offline given only the envelope. */
  measurerPublicKey: string
  /** ISO 8601 timestamp of envelope signing. */
  signedAt: string
  /** Hex-encoded Ed25519 signature over canonicalize({ subject, fidelity,
   *  pdr_ref, constraint_ref, measurerId, signedAt }). */
  signature: string
}

// ── Verification Result ──

/** Result of verifyBehavioralFingerprint. All-or-nothing validity flag plus
 *  per-field breakdown for diagnostic visibility. */
export interface FingerprintVerificationResult {
  /** True iff the envelope signature verifies AND every inner fidelity
   *  attestation signature verifies under the same public key. */
  valid: boolean
  /** Whether the envelope-level signature verified against measurerPublicKey. */
  envelopeSignatureValid: boolean
  /** One boolean per inner FidelityAttestation, in the same order as
   *  fp.fidelity. Each entry is the result of verifyFidelityAttestation
   *  against the provided measurerPublicKey. */
  innerFidelitySignaturesValid: boolean[]
  /** Human-readable diagnostic messages. Empty array on success. */
  errors: string[]
}

// ── Create ──

/** Compose and sign a BehavioralFingerprint envelope.
 *
 * Requires at least one FidelityAttestation. The envelope carries pre-built
 * fidelity attestations as-is — they retain their own measuredBy/signature
 * fields and stay independently verifiable.
 *
 * The signing key is used for the envelope signature only. Inner fidelity
 * attestations were signed earlier by their own measurers; this function
 * does not re-sign them.
 *
 * @throws if fidelity is empty.
 *
 * Reference: Nanook PDR v2.19 §2.2, §8.10. Gap audit §5 rank 2.
 */
export function createBehavioralFingerprint(
  subject: { did: string; substrate: string },
  fidelity: FidelityAttestation[],
  opts: {
    pdr?: PDRScoreRef
    constraint?: SaeboScoreRef
    measurerId: string
    measurerPublicKey: string
    signingKey: string
    /** Override the signing timestamp. Test fixtures only. */
    signedAt?: string
  },
): BehavioralFingerprint {
  if (!Array.isArray(fidelity) || fidelity.length === 0) {
    throw new Error('createBehavioralFingerprint: at least one fidelity attestation is required')
  }
  if (!opts.measurerId || typeof opts.measurerId !== 'string') {
    throw new Error('createBehavioralFingerprint: measurerId must be a non-empty string')
  }
  if (!opts.measurerPublicKey || typeof opts.measurerPublicKey !== 'string') {
    throw new Error('createBehavioralFingerprint: measurerPublicKey must be a non-empty string')
  }
  if (!opts.signingKey || typeof opts.signingKey !== 'string') {
    throw new Error('createBehavioralFingerprint: signingKey must be a non-empty string')
  }

  const signedAt = opts.signedAt ?? new Date().toISOString()

  // Build the unsigned envelope. Canonicalize will sort keys alphabetically
  // and strip null/undefined, so PDR/constraint absence produces the same
  // bytes regardless of property declaration order.
  const unsigned = {
    subject,
    fidelity,
    ...(opts.pdr ? { pdr_ref: opts.pdr } : {}),
    ...(opts.constraint ? { constraint_ref: opts.constraint } : {}),
    measurerId: opts.measurerId,
    measurerPublicKey: opts.measurerPublicKey,
    signedAt,
  }

  const payload = canonicalize(unsigned)
  const signature = sign(payload, opts.signingKey)

  return {
    ...unsigned,
    signature,
  } as BehavioralFingerprint
}

// ── Verify ──

/** Verify a BehavioralFingerprint envelope.
 *
 * Performs two checks:
 *   1. Envelope signature: verify the envelope's own Ed25519 signature
 *      against the provided measurerPublicKey.
 *   2. Inner fidelity signatures: for each FidelityAttestation in
 *      fp.fidelity, run verifyFidelityAttestation against the SAME
 *      measurerPublicKey. The per-attestation result is reported in
 *      innerFidelitySignaturesValid.
 *
 * Limitation by design: this function does NOT verify pdr_ref.signature or
 * constraint_ref.signature. Those are external axes whose issuers may use
 * different key schemes, signature formats, or canonicalization rules. If
 * those fields carry signatures, callers must verify them out-of-band with
 * the appropriate issuer's verification logic. The fingerprint envelope's
 * own signature still covers the entire pdr_ref / constraint_ref content
 * as JSON, so tampering with their fields will fail envelope verification.
 *
 * Limitation on multi-measurer fidelity attestations: if the inner
 * attestations were signed by different keys than the envelope, their per-
 * attestation entries in innerFidelitySignaturesValid will be false. The
 * envelope itself is still validly signed; callers can re-verify failed
 * inner attestations against the correct keys via verifyFidelityAttestation.
 *
 * The all-or-nothing valid flag is true iff envelope signature is valid
 * AND every inner fidelity signature is valid under the same key.
 */
export function verifyBehavioralFingerprint(
  fp: BehavioralFingerprint,
  measurerPublicKey: string,
): FingerprintVerificationResult {
  const errors: string[] = []

  // Validate input shape
  if (!fp || typeof fp !== 'object') {
    return {
      valid: false,
      envelopeSignatureValid: false,
      innerFidelitySignaturesValid: [],
      errors: ['fingerprint is not an object'],
    }
  }
  if (!Array.isArray(fp.fidelity) || fp.fidelity.length === 0) {
    return {
      valid: false,
      envelopeSignatureValid: false,
      innerFidelitySignaturesValid: [],
      errors: ['fingerprint must carry at least one fidelity attestation'],
    }
  }

  // Step 1: envelope signature.
  // Reconstruct the canonical payload exactly as createBehavioralFingerprint
  // produced it: every field except `signature`. Note that the spread-with-
  // conditional pattern in create produces no key for absent optional fields,
  // and canonicalize() strips null/undefined, so the two paths agree.
  const unsigned = {
    subject: fp.subject,
    fidelity: fp.fidelity,
    ...(fp.pdr_ref !== undefined ? { pdr_ref: fp.pdr_ref } : {}),
    ...(fp.constraint_ref !== undefined ? { constraint_ref: fp.constraint_ref } : {}),
    measurerId: fp.measurerId,
    measurerPublicKey: fp.measurerPublicKey,
    signedAt: fp.signedAt,
  }
  const payload = canonicalize(unsigned)

  let envelopeSignatureValid = false
  try {
    envelopeSignatureValid = verify(payload, fp.signature, measurerPublicKey)
  } catch {
    envelopeSignatureValid = false
  }
  if (!envelopeSignatureValid) {
    errors.push('envelope signature failed verification')
  }

  // Step 2: each inner fidelity attestation under the SAME public key.
  const innerFidelitySignaturesValid: boolean[] = fp.fidelity.map((att, i) => {
    let ok = false
    try {
      ok = verifyFidelityAttestation(att, measurerPublicKey)
    } catch {
      ok = false
    }
    if (!ok) {
      errors.push(
        `inner fidelity attestation ${i} (${att.attestationId ?? 'unknown'}) failed verification`,
      )
    }
    return ok
  })

  const allInnerValid = innerFidelitySignaturesValid.every(Boolean)

  return {
    valid: envelopeSignatureValid && allInnerValid,
    envelopeSignatureValid,
    innerFidelitySignaturesValid,
    errors,
  }
}

// ── Compose / Project ──

/** Pure projection helper for a BehavioralFingerprint. Surfaces the top-
 *  level scalar from each axis without combining them into a single number.
 *
 *  The paper's three-axis orthogonality claim (Nanook PDR v2.19 §2.2) is
 *  untested. This SDK deliberately does NOT bake a combinator policy into
 *  the projection: callers that want a composite score must compute it
 *  themselves with their own weighting choices. The function returns the
 *  raw axis scalars and lets the consumer decide.
 *
 *  - fidelityMean: arithmetic mean of fp.fidelity[*].fidelity.score.
 *    A simple mean is the right default because each FidelityAttestation
 *    represents one HBB probe under different conditions (e.g. pre vs
 *    post substrate swap). Confidence-weighting is available inside the
 *    individual SubstrateFidelity scoring path; the envelope projection
 *    treats each attestation as one observation.
 *
 *  - pdrOverall: scoreOverall from the optional PDR reference, or undefined
 *    if no PDR axis is present.
 *
 *  - constraintCompliance: complianceScore from the optional Saebo
 *    reference, or undefined if no constraint axis is present.
 */
export function composeFingerprintAxes(fp: BehavioralFingerprint): {
  fidelityMean: number
  pdrOverall?: number
  constraintCompliance?: number
} {
  if (!fp.fidelity || fp.fidelity.length === 0) {
    throw new Error('composeFingerprintAxes: fingerprint has no fidelity attestations')
  }

  const sum = fp.fidelity.reduce((acc, att) => acc + att.fidelity.score, 0)
  const fidelityMean = sum / fp.fidelity.length

  const result: { fidelityMean: number; pdrOverall?: number; constraintCompliance?: number } = {
    fidelityMean,
  }
  if (fp.pdr_ref) result.pdrOverall = fp.pdr_ref.scoreOverall
  if (fp.constraint_ref) result.constraintCompliance = fp.constraint_ref.complianceScore
  return result
}
