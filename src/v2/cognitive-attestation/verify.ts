// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// ══════════════════════════════════════════════════════════════════
// Cognitive Attestation — three-stage verification
// ══════════════════════════════════════════════════════════════════
// Paper: "Cognitive Attestation" — Zenodo DOI 10.5281/zenodo.19646276, §4
//
// Stage 1 (cryptographic): verifySignature + verifyRequiredSignerRoles — ships.
// Stage 2 (registry):      verifyAgainstRegistry — interface + basic impl;
//                          concrete resolvers injected by integrators/gateway.
// Stage 3 (replay):        verifyByReplay — typed shape only; the SDK does
//                          not bundle a running SAE. Throws "not implemented"
//                          until a ReplayBackend is wired.
// ══════════════════════════════════════════════════════════════════

import { verify as edVerifyHex } from '../../crypto/keys.js'
import { canonicalizeAttestation } from './envelope.js'
import type { CognitiveAttestation, SignerRole } from './types.js'

function bytesToHex(bytes: Uint8Array): string {
  let out = ''
  for (let i = 0; i < bytes.length; i++) out += bytes[i].toString(16).padStart(2, '0')
  return out
}

function base64ToHex(b64: string): string | null {
  try {
    return Buffer.from(b64, 'base64').toString('hex')
  } catch {
    return null
  }
}

// ──────────────────────────────────────────────────────────────────
// Stage 1a — cryptographic single-signer check.
// ──────────────────────────────────────────────────────────────────

/**
 * Verify that at least one signature entry for `signerDid` validates against
 * `publicKey`. Returns false on tamper, wrong DID, malformed signature, or
 * key mismatch.
 */
export function verifySignature(
  att: CognitiveAttestation,
  publicKey: Uint8Array,
  signerDid: string,
): boolean {
  if (!(publicKey instanceof Uint8Array) || publicKey.length !== 32) return false

  const canonicalBytes = canonicalizeAttestation(att)
  const canonicalString = new TextDecoder().decode(canonicalBytes)
  const publicKeyHex = bytesToHex(publicKey)

  const matches = att.signatures.filter((s) => s.signer_did === signerDid)
  if (matches.length === 0) return false

  for (const entry of matches) {
    const sigHex = base64ToHex(entry.signature)
    if (!sigHex) continue
    if (edVerifyHex(canonicalString, sigHex, publicKeyHex)) return true
  }
  return false
}

// ──────────────────────────────────────────────────────────────────
// Stage 1b — required signer role coverage.
// ──────────────────────────────────────────────────────────────────

export interface RequiredRoleCoverage {
  ok: boolean
  missing: SignerRole[]
  present: SignerRole[]
}

/**
 * Confirm every role in `aggregation_policy.required_signer_roles` is
 * represented by at least one signature entry with that role. Structural
 * check only — does NOT verify signature cryptographically. Callers should
 * pair this with `verifySignature` per signer for full Stage 1.
 */
export function verifyRequiredSignerRoles(att: CognitiveAttestation): RequiredRoleCoverage {
  const required = new Set<SignerRole>(att.aggregation_policy.required_signer_roles)
  const presentRoles = new Set<SignerRole>(att.signatures.map((s) => s.signer_role))
  const missing: SignerRole[] = []
  for (const role of required) if (!presentRoles.has(role)) missing.push(role)
  return {
    ok: missing.length === 0,
    missing,
    present: Array.from(presentRoles),
  }
}

// ──────────────────────────────────────────────────────────────────
// Stage 2 — registry verification (model + dictionary version hashes).
// ──────────────────────────────────────────────────────────────────

export interface RegistryResolver {
  /** Return true if the model_version_hash is known to the caller's model registry. */
  isKnownModel(modelId: string, modelVersionHash: string): Promise<boolean>
  /** Return true if the dictionary_version_hash is known to the caller's SAE/feature-dict registry. */
  isKnownDictionary(dictionaryId: string, dictionaryVersionHash: string): Promise<boolean>
}

export interface RegistryVerificationResult {
  ok: boolean
  model_known: boolean
  dictionary_known: boolean
  errors: string[]
}

/**
 * Stage 2. Checks that the referenced model and dictionary versions exist in
 * the resolver's registry view. The SDK ships no registry client — integrators
 * (or the private gateway) implement `RegistryResolver`.
 */
export async function verifyAgainstRegistry(
  att: CognitiveAttestation,
  registryResolver: RegistryResolver,
): Promise<RegistryVerificationResult> {
  const errors: string[] = []
  let model_known = false
  let dictionary_known = false

  try {
    model_known = await registryResolver.isKnownModel(
      att.model_ref.model_id,
      att.model_ref.model_version_hash,
    )
    if (!model_known) {
      errors.push(
        `unknown model_version_hash for model_id="${att.model_ref.model_id}"`,
      )
    }
  } catch (e: unknown) {
    errors.push(`model resolver error: ${e instanceof Error ? e.message : String(e)}`)
  }

  try {
    dictionary_known = await registryResolver.isKnownDictionary(
      att.dictionary_ref.dictionary_id,
      att.dictionary_ref.dictionary_version_hash,
    )
    if (!dictionary_known) {
      errors.push(
        `unknown dictionary_version_hash for dictionary_id="${att.dictionary_ref.dictionary_id}"`,
      )
    }
  } catch (e: unknown) {
    errors.push(`dictionary resolver error: ${e instanceof Error ? e.message : String(e)}`)
  }

  return {
    ok: errors.length === 0 && model_known && dictionary_known,
    model_known,
    dictionary_known,
    errors,
  }
}

// ──────────────────────────────────────────────────────────────────
// Stage 3 — computational replay (typed stub).
// ──────────────────────────────────────────────────────────────────

export interface ReplayBackend {
  /**
   * Replay the attested token range through the referenced model + SAE and
   * compare feature activations against the envelope within the policy's
   * attestation_epsilon. Implementations live outside the SDK.
   */
  replay(att: CognitiveAttestation): Promise<ReplayVerificationResult>
}

export interface ReplayVerificationResult {
  ok: boolean
  /** Per-feature deltas keyed by feature_id. */
  per_feature_delta: Record<number, number>
  /** Features whose |delta| exceeded aggregation_policy.attestation_epsilon. */
  over_epsilon: number[]
  /** Features claimed by the envelope but not observed during replay. */
  missing_from_replay: number[]
  /** Features observed above threshold during replay but absent from the envelope. */
  unexpected_in_replay: number[]
}

/**
 * Stage 3. Requires an injected `ReplayBackend`. Running an SAE live is
 * outside what a pure SDK primitive should bundle — use a private backend
 * or the gateway's replay service.
 *
 * TODO: Once a reference replay backend exists (gateway-side, not SDK),
 *       document its contract here and ship test vectors covering
 *       threshold-delta, missing-feature, and unexpected-feature cases.
 */
export async function verifyByReplay(
  att: CognitiveAttestation,
  replayer: ReplayBackend,
): Promise<ReplayVerificationResult> {
  if (!replayer || typeof replayer.replay !== 'function') {
    throw new Error(
      'verifyByReplay: not implemented in SDK. Inject a ReplayBackend ' +
        'or use a private backend (e.g. gateway replay service).',
    )
  }
  return replayer.replay(att)
}
