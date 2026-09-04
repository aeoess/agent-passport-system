// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0
// ══════════════════════════════════════════════════════════════════
// Module 37: Decision Semantics & Cross-Engine Interop
// ══════════════════════════════════════════════════════════════════
// Content-addressable decisions, evaluation method classification,
// scope interpretation declaration, cross-engine decision artifacts.
//
// Motivated by cross-engine verification (kanoniv/agent-auth#2):
// Four engines, same scenario, divergent trust verdicts over shared
// structural verdicts. These functions formalize that decomposition.
// ══════════════════════════════════════════════════════════════════

import { v4 as uuidv4 } from 'uuid'
import { sign, verify } from '../crypto/keys.js'
import { canonicalize, canonicalizeForWrite } from './canonical.js'
import { parseRfc3339 } from './rfc3339.js'
import { isRecord } from './is-record.js'
import type { ActionIntent, PolicyDecision, PolicyVerdict } from '../types/policy.js'
import type {
  ContentHash, ContentHashAlgorithm, EvaluationMethod,
  ScopeInterpretation, DecisionSemantics, DecisionArtifact,
  DecisionArtifactVerification
} from '../types/decision-semantics.js'

// ══════════════════════════════════════
// CONTENT HASHING
// ══════════════════════════════════════

/**
 * Minimum required identity boundary fields per artifact type.
 * The spec declares these minimums — artifacts can commit to more but not fewer.
 */
export const MINIMUM_IDENTITY_FIELDS: Record<string, string[]> = {
  action_intent: ['agentId', 'agentPublicKey', 'action', 'delegationId', 'intentId'],
  decision_artifact: ['artifactType', 'engine', 'intent', 'evaluation', 'semantics']
}

/**
 * Compute a content hash of an ActionIntent (unsigned fields only).
 * Uses SHA-256 of canonical JSON serialization.
 * Makes the intent content-addressable — reference by hash, not just signature.
 *
 * The identity boundary (sorted field names) is committed into the hash,
 * making the artifact self-describing: any engine can verify which fields
 * define identity without depending on external projection rules.
 */
async function computeContentHashImpl(
  intent: Omit<ActionIntent, 'signature' | 'contentHash'>,
  canon: (v: unknown) => string
): Promise<ContentHash> {
  // Extract sorted top-level field names — this IS the identity boundary
  const identityBoundary = Object.keys(intent).sort()
  // Hash includes both the content AND the boundary declaration
  const hashInput = { _identityBoundary: identityBoundary, ...intent }
  const canonical = canon(hashInput)
  const hash = await sha256Hex(canonical)
  return {
    algorithm: 'sha256' as ContentHashAlgorithm,
    hash,
    canonicalForm: 'canonical_json_sorted_keys',
    identityBoundary
  }
}

export async function computeContentHash(
  intent: Omit<ActionIntent, 'signature' | 'contentHash'>
): Promise<ContentHash> {
  return computeContentHashImpl(intent, canonicalize)
}

/** Write-boundary twin of computeContentHash().
 *
 *  Shares one implementation body with computeContentHash() so the two can never drift apart
 *  on the field list. Emits the same bytes for every value it accepts; the only
 *  difference is that an integer-valued number outside the interoperable IEEE 754
 *  range is refused instead of serialized. Use at signing and new-write boundaries
 *  ONLY: computeContentHash() stays unrestricted so an artifact signed before this rule keeps
 *  verifying. */
export async function computeContentHashForWrite(
  intent: Omit<ActionIntent, 'signature' | 'contentHash'>
): Promise<ContentHash> {
  return computeContentHashImpl(intent, canonicalizeForWrite)
}

/**
 * Verify that a content hash matches the intent it claims to represent.
 * If identityBoundary is present, verifies the boundary was committed into the hash.
 */
export async function verifyContentHash(
  intent: ActionIntent
): Promise<{ valid: boolean; error?: string }> {
  if (!intent.contentHash) {
    return { valid: false, error: 'No content hash present on intent' }
  }
  // Rebuild from unsigned fields (exclude signature and contentHash itself)
  const { signature, contentHash, ...unsigned } = intent
  // Re-include identity boundary in hash input (same as computeContentHash)
  const identityBoundary = contentHash.identityBoundary ?? Object.keys(unsigned).sort()
  const hashInput = { _identityBoundary: identityBoundary, ...unsigned }
  const canonical = canonicalize(hashInput)
  const expected = await sha256Hex(canonical)
  if (expected !== intent.contentHash.hash) {
    return { valid: false, error: `Hash mismatch: expected ${expected}, got ${intent.contentHash.hash}` }
  }
  return { valid: true }
}

/**
 * Validate that an identity boundary meets the spec minimum for its artifact type.
 * The spec declares minimum required fields — the artifact can commit to more but not fewer.
 */
export function validateIdentityBoundary(
  boundary: string[],
  artifactType: string
): { valid: boolean; missing: string[] } {
  const minimum = MINIMUM_IDENTITY_FIELDS[artifactType]
  if (!minimum) return { valid: true, missing: [] }  // unknown type = no minimum
  const missing = minimum.filter(f => !boundary.includes(f))
  return { valid: missing.length === 0, missing }
}

// ══════════════════════════════════════
// CONTENT-ADDRESSABLE INTENT CREATION
// ══════════════════════════════════════

/**
 * Create an ActionIntent with a content hash embedded.
 * The hash is computed over the unsigned, unhashed intent,
 * then included in the object before signing.
 * This means the signature covers the hash — binding content identity to signer identity.
 */
export async function createContentAddressableIntent(opts: {
  agentId: string
  agentPublicKey: string
  delegationId: string
  action: ActionIntent['action']
  context?: string
  privateKey: string
}): Promise<ActionIntent> {
  // Build the unsigned intent (without signature or contentHash)
  const unsigned = {
    intentId: 'intent_' + uuidv4().slice(0, 12),
    agentId: opts.agentId,
    agentPublicKey: opts.agentPublicKey,
    delegationId: opts.delegationId,
    action: opts.action,
    context: opts.context,
    createdAt: new Date().toISOString()
  }

  // Compute content hash over unsigned fields
  const contentHash = await computeContentHashForWrite(unsigned)

  // Now sign the intent INCLUDING the content hash
  const withHash = { ...unsigned, contentHash }
  const signature = sign(canonicalizeForWrite(withHash), opts.privateKey)

  return { ...withHash, signature }
}

// ══════════════════════════════════════
// EVALUATION METHOD CLASSIFICATION
// ══════════════════════════════════════

/**
 * Classify the evaluation method of a PolicyDecision.
 * If the decision already has evaluationMethod set, returns it.
 * Otherwise infers from the principles evaluated.
 */
export function classifyEvaluationMethod(decision: PolicyDecision): EvaluationMethod {
  if (decision.evaluationMethod) return decision.evaluationMethod

  // Principles F-001 through F-005 are deterministic (scope, expiry, registration)
  // Principles F-006 (Non-Deception) and F-007 (Proportionality) require model reasoning
  const hasModelDependent = decision.principlesEvaluated.some(p => {
    const num = parseInt(p.principleId.replace('F-', ''), 10)
    return num >= 6 && p.status !== 'not_applicable'
  })
  const hasDeterministic = decision.principlesEvaluated.some(p => {
    const num = parseInt(p.principleId.replace('F-', ''), 10)
    return num <= 5 && p.status !== 'not_applicable'
  })

  if (hasModelDependent && hasDeterministic) return 'hybrid'
  if (hasModelDependent) return 'model_dependent'
  return 'deterministic'
}

// ══════════════════════════════════════
// DECISION SEMANTICS DECOMPOSITION
// ══════════════════════════════════════

/**
 * Decompose a PolicyDecision into structural vs trust components.
 * Structural: F-001 through F-005 (scope, delegation, registration)
 * Trust: F-006, F-007, and any reputation/behavioral checks
 */
export function decomposeDecision(decision: PolicyDecision): DecisionSemantics {
  // Split principles into structural (F-001..F-005) and trust (F-006+)
  const structural = decision.principlesEvaluated.filter(p => {
    const num = parseInt(p.principleId.replace('F-', ''), 10)
    return num <= 5
  })
  const trust = decision.principlesEvaluated.filter(p => {
    const num = parseInt(p.principleId.replace('F-', ''), 10)
    return num >= 6 && p.status !== 'not_applicable'
  })

  const structuralFailed = structural.some(p => p.status === 'fail')
  const trustFailed = trust.some(p => p.status === 'fail')
  const hasTrustLayer = trust.length > 0

  const structuralVerdict: PolicyVerdict = structuralFailed ? 'deny' : 'permit'
  const trustVerdict: PolicyVerdict | null = hasTrustLayer
    ? (trustFailed ? 'deny' : 'permit')
    : null

  // Detect override pattern: when trust overrides a structural permit
  const hasOverride = structuralVerdict === 'permit' && trustVerdict === 'deny'

  const evaluationMethod = classifyEvaluationMethod(decision)
  const reproducibility = evaluationMethod === 'deterministic'
    ? 'structural_by_any_engine'
    : evaluationMethod === 'model_dependent'
      ? 'trust_by_originating_engine_only'
      : 'structural_by_any_engine, trust_by_originating_engine_only'

  return {
    structuralVerdict,
    trustVerdict,
    override: hasOverride ? {
      active: true,
      phase: 'trust_threshold',
      wouldHaveBeen: 'permit'
    } : undefined,
    finalVerdictRule: hasTrustLayer ? 'structural AND trust' : 'structural only',
    reproducibility
  }
}

// ══════════════════════════════════════
// DECISION ARTIFACT CREATION
// ══════════════════════════════════════

/**
 * Create a cross-engine decision artifact from an intent + decision pair.
 * Bundles the pre-execution decision with its semantic decomposition
 * into a single verifiable, content-addressable object.
 */
export async function createDecisionArtifact(opts: {
  intent: ActionIntent
  decision: PolicyDecision
  engine: string              // engine identifier (e.g. 'aps', 'aip', 'kanoniv')
  version?: string            // artifact format version
  signerPrivateKey: string    // signs the artifact envelope
}): Promise<DecisionArtifact> {
  // Compute or use existing content hash
  let contentHash: ContentHash
  if (opts.intent.contentHash) {
    contentHash = opts.intent.contentHash
  } else {
    const { signature, ...unsigned } = opts.intent
    contentHash = await computeContentHash(unsigned)
  }

  const semantics = decomposeDecision(opts.decision)
  const evaluationMethod = classifyEvaluationMethod(opts.decision)

  const artifact: Omit<DecisionArtifact, 'proof'> & { proof: Omit<DecisionArtifact['proof'], 'artifactSignature'> } = {
    artifactId: 'dart_' + uuidv4().slice(0, 12),
    artifactType: 'decision',
    version: opts.version ?? '1.0.0',
    engine: opts.engine,
    timestamp: new Date().toISOString(),
    intent: {
      intentId: opts.intent.intentId,
      agentId: opts.intent.agentId,
      action: {
        type: opts.intent.action.type,
        target: opts.intent.action.target,
        scopeRequired: opts.intent.action.scopeRequired
      },
      contentHash
    },
    evaluation: {
      verdict: opts.decision.verdict,
      evaluationMethod,
      principlesChecked: opts.decision.principlesEvaluated.map(p => p.principleId),
      evaluatorId: opts.decision.evaluatorId,
      decisionId: opts.decision.decisionId
    },
    semantics,
    proof: {
      intentSignature: opts.intent.signature,
      decisionSignature: opts.decision.signature
    }
  }

  // Sign the entire artifact
  const artifactSignature = sign(canonicalizeForWrite(artifact), opts.signerPrivateKey)

  return {
    ...artifact,
    proof: {
      ...artifact.proof,
      artifactSignature
    }
  } as DecisionArtifact
}

// ══════════════════════════════════════
// DECISION ARTIFACT VERIFICATION
// ══════════════════════════════════════

/**
 * Verify a decision artifact against the trust anchors the caller supplies.
 *
 * SCOPE OF CLAIM.
 *   Establishes, when `valid` is true: the artifact envelope was signed by
 *     `keys.artifactSignerPublicKey`; `originalIntent` was signed by
 *     `keys.intentSignerPublicKey` and `originalDecision` by
 *     `keys.decisionSignerPublicKey`; the decision decides that intent; and
 *     every value the artifact projects from either source equals its source.
 *   Does NOT establish: that those three keys are the right ones — that is
 *     the relying party's allowlist, not this function's; that the evaluator
 *     was entitled to decide this action; that the decision's reasoning is
 *     sound; or that any of the three parties are distinct (see the
 *     same-key note below).
 *
 * The trust anchors are the whole point. An artifact-carried key —
 * `intent.agentPublicKey`, `decision.evaluatorPublicKey` — is a claim the
 * artifact makes about itself, so verifying against it establishes only that
 * whoever wrote the artifact also held one key. Both are now verified against
 * the caller's anchors, and each embedded key must additionally agree with
 * the anchor it was verified under: the signature covers the embedded key, so
 * a mismatch is an artifact whose signed content contradicts its own signer.
 *
 * The projection checks matter as much as the signatures. The artifact copies
 * the verdict, the evaluator, the decision id, the principle list and the two
 * inner signature strings out of objects it does not carry. Signing those
 * copies proves the artifact's author committed to them, not that they are
 * what the evaluator decided; only comparison against the source does that.
 *
 * SAME-KEY ROLES. Nothing here requires the three anchors to be distinct. A
 * caller that passes one key for all three gets a chain in which one party
 * requested, decided and attested. That is a policy question the repo has no
 * field to express (`Office.incompatibleOffices` in src/types/charter.ts is
 * the only role-separation concept, and it does not reach this layer), so it
 * is left to the caller rather than invented here.
 */
export async function verifyDecisionArtifact(
  artifact: DecisionArtifact,
  keys: {
    /** Trust anchor for the intent: the agent this relying party accepts. */
    intentSignerPublicKey: string
    /** Trust anchor for the decision: the evaluator this relying party accepts. */
    decisionSignerPublicKey: string
    /** Trust anchor for the artifact envelope. */
    artifactSignerPublicKey: string
  },
  originalIntent: ActionIntent,
  originalDecision: PolicyDecision
): Promise<DecisionArtifactVerification> {
  const errors: string[] = []

  // 0. Input guard. These are attacker-deliverable objects; a JSON `null`
  //    must reach the reject verdict, not throw past it.
  if (!isRecord(artifact) || !isRecord(originalIntent) || !isRecord(originalDecision)) {
    return {
      valid: false,
      contentHashValid: false,
      intentSignatureValid: false,
      decisionSignatureValid: false,
      artifactSignatureValid: false,
      linkageValid: false,
      projectionValid: false,
      errors: ['Artifact, intent and decision must all be objects']
    }
  }

  // 1. Content hash, recomputed from the source intent. Required: it is the
  //    artifact's only self-contained binding to the intent's full content,
  //    and an artifact that omits it is not verifiable rather than trivially
  //    verified.
  let contentHashValid = false
  if (!artifact.intent?.contentHash) {
    errors.push('Artifact carries no intent content hash')
  } else {
    const { signature: _intentSig, contentHash, ...unsigned } = originalIntent
    const identityBoundary = contentHash?.identityBoundary ?? Object.keys(unsigned).sort()
    const hashInput = { _identityBoundary: identityBoundary, ...unsigned }
    const expectedHash = await sha256Hex(canonicalize(hashInput))
    contentHashValid = expectedHash === artifact.intent.contentHash.hash
    if (!contentHashValid) {
      errors.push('Content hash mismatch')
    }
  }

  // 2. Intent signature, against the caller's anchor.
  const intentCheck = verifyActionIntentAgainst(originalIntent, keys.intentSignerPublicKey)
  const intentSignatureValid = intentCheck.valid
  if (!intentSignatureValid) {
    errors.push(`Intent signature invalid: ${intentCheck.errors.join(', ')}`)
  }

  // 3. Decision signature, against the caller's anchor.
  const decisionCheck = verifyPolicyDecisionAgainst(originalDecision, keys.decisionSignerPublicKey)
  const decisionSignatureValid = decisionCheck.valid
  if (!decisionSignatureValid) {
    errors.push(`Decision signature invalid: ${decisionCheck.errors.join(', ')}`)
  }

  // 4. Chain linkage. A validly signed decision about some other intent is
  //    still a validly signed decision; it just does not decide this one.
  const linkageValid = originalDecision.intentId === originalIntent.intentId
  if (!linkageValid) {
    errors.push('Decision does not decide this intent: intentId mismatch')
  }

  // 5. Projection binding. Every value the artifact restates must equal the
  //    source it claims to restate.
  const projectionErrors = projectionMismatches(artifact, originalIntent, originalDecision)
  const projectionValid = projectionErrors.length === 0
  for (const mismatch of projectionErrors) {
    errors.push(`Artifact projection does not match source: ${mismatch}`)
  }

  // 6. Artifact envelope signature.
  const { proof, ...artifactBody } = artifact
  const bodyWithPartialProof = {
    ...artifactBody,
    proof: {
      intentSignature: proof.intentSignature,
      decisionSignature: proof.decisionSignature
    }
  }
  const artifactSignatureValid = verify(
    canonicalize(bodyWithPartialProof),
    proof.artifactSignature,
    keys.artifactSignerPublicKey
  )
  if (!artifactSignatureValid) {
    errors.push('Artifact envelope signature invalid')
  }

  return {
    valid: errors.length === 0,
    contentHashValid,
    intentSignatureValid,
    decisionSignatureValid,
    artifactSignatureValid,
    linkageValid,
    projectionValid,
    errors
  }
}

/** Verify an intent under a caller-supplied anchor rather than the key the
 *  intent carries. The embedded key must agree with the anchor: it is inside
 *  the signed bytes, so a mismatch is the artifact contradicting its own
 *  signer, not merely an unexpected key. */
function verifyActionIntentAgainst(
  intent: ActionIntent,
  trustedPublicKey: string
): { valid: boolean; errors: string[] } {
  const errors: string[] = []
  const { signature, ...unsigned } = intent
  if (!verify(canonicalize(unsigned), signature, trustedPublicKey)) {
    errors.push('not signed by the supplied intent signer')
  }
  if (intent.agentPublicKey !== trustedPublicKey) {
    errors.push('intent names an agentPublicKey other than the supplied intent signer')
  }
  if (!intent.agentId) errors.push('Missing agentId')
  if (!intent.delegationId) errors.push('Missing delegationId')
  if (!intent.action?.scopeRequired) errors.push('Missing required scope')
  return { valid: errors.length === 0, errors }
}

/** Decision counterpart of {@link verifyActionIntentAgainst}. Expiry is
 *  checked with the strict parse, so an unreadable `expiresAt` rejects. */
function verifyPolicyDecisionAgainst(
  decision: PolicyDecision,
  trustedPublicKey: string
): { valid: boolean; errors: string[] } {
  const errors: string[] = []
  const { signature, ...unsigned } = decision
  if (!verify(canonicalize(unsigned), signature, trustedPublicKey)) {
    errors.push('not signed by the supplied decision signer')
  }
  if (decision.evaluatorPublicKey !== trustedPublicKey) {
    errors.push('decision names an evaluatorPublicKey other than the supplied decision signer')
  }
  const expiry = parseRfc3339(decision.expiresAt)
  if (!expiry.ok) {
    errors.push(`Invalid decision expiresAt (${expiry.reason})`)
  } else if (expiry.ms < Date.now()) {
    errors.push('Policy decision expired')
  }
  if (!decision.intentId) errors.push('Missing intentId')
  return { valid: errors.length === 0, errors }
}

/** Every projected field, compared against the source it is projected from.
 *  Returns one entry per mismatch, named by field path. Comparison of
 *  structured values goes through canonicalize() so it is the same equality
 *  the signatures are taken over. */
function projectionMismatches(
  artifact: DecisionArtifact,
  intent: ActionIntent,
  decision: PolicyDecision
): string[] {
  const out: string[] = []
  const eq = (path: string, got: unknown, want: unknown) => {
    if (canonicalize(got) !== canonicalize(want)) {
      out.push(`${path} (artifact ${canonicalize(got)}, source ${canonicalize(want)})`)
    }
  }

  eq('intent.intentId', artifact.intent?.intentId, intent.intentId)
  eq('intent.agentId', artifact.intent?.agentId, intent.agentId)
  eq('intent.action.type', artifact.intent?.action?.type, intent.action?.type)
  eq('intent.action.target', artifact.intent?.action?.target, intent.action?.target)
  eq('intent.action.scopeRequired', artifact.intent?.action?.scopeRequired, intent.action?.scopeRequired)

  eq('evaluation.verdict', artifact.evaluation?.verdict, decision.verdict)
  eq('evaluation.evaluatorId', artifact.evaluation?.evaluatorId, decision.evaluatorId)
  eq('evaluation.decisionId', artifact.evaluation?.decisionId, decision.decisionId)
  eq(
    'evaluation.principlesChecked',
    artifact.evaluation?.principlesChecked,
    decision.principlesEvaluated?.map(p => p.principleId)
  )
  eq('evaluation.evaluationMethod', artifact.evaluation?.evaluationMethod, classifyEvaluationMethod(decision))

  // The semantic decomposition is derived, not copied, so it is recomputed
  // rather than compared field by field: an artifact may not assert a
  // decomposition the decision does not produce.
  eq('semantics', artifact.semantics, decomposeDecision(decision))

  eq('proof.intentSignature', artifact.proof?.intentSignature, intent.signature)
  eq('proof.decisionSignature', artifact.proof?.decisionSignature, decision.signature)

  return out
}

// ══════════════════════════════════════
// SCOPE INTERPRETATION HELPERS
// ══════════════════════════════════════

/**
 * Get the effective scope interpretation for a delegation.
 * Defaults to 'hierarchical' — APS's native scope matching.
 */
export function getEffectiveScopeInterpretation(
  delegation: { scopeInterpretation?: ScopeInterpretation }
): ScopeInterpretation {
  return delegation.scopeInterpretation ?? 'hierarchical'
}

// ══════════════════════════════════════
// SHA-256 HELPER
// ══════════════════════════════════════

export async function sha256Hex(data: string): Promise<string> {
  // Use Web Crypto API (available in Node.js 18+ and browsers)
  const encoder = new TextEncoder()
  const buffer = encoder.encode(data)
  const hashBuffer = await crypto.subtle.digest('SHA-256', buffer)
  const hashArray = Array.from(new Uint8Array(hashBuffer))
  return hashArray.map(b => b.toString(16).padStart(2, '0')).join('')
}
