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
import { canonicalize } from './canonical.js'
import { createActionIntent, verifyActionIntent, verifyPolicyDecision } from './policy.js'
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
 * Compute a content hash of an ActionIntent (unsigned fields only).
 * Uses SHA-256 of canonical JSON serialization.
 * Makes the intent content-addressable — reference by hash, not just signature.
 */
export async function computeContentHash(
  intent: Omit<ActionIntent, 'signature' | 'contentHash'>
): Promise<ContentHash> {
  const canonical = canonicalize(intent)
  const hash = await sha256Hex(canonical)
  return {
    algorithm: 'sha256' as ContentHashAlgorithm,
    hash,
    canonicalForm: 'canonical_json_sorted_keys'
  }
}

/**
 * Verify that a content hash matches the intent it claims to represent.
 */
export async function verifyContentHash(
  intent: ActionIntent
): Promise<{ valid: boolean; error?: string }> {
  if (!intent.contentHash) {
    return { valid: false, error: 'No content hash present on intent' }
  }
  // Rebuild from unsigned fields (exclude signature and contentHash itself)
  const { signature, contentHash, ...unsigned } = intent
  const canonical = canonicalize(unsigned)
  const expected = await sha256Hex(canonical)
  if (expected !== intent.contentHash.hash) {
    return { valid: false, error: `Hash mismatch: expected ${expected}, got ${intent.contentHash.hash}` }
  }
  return { valid: true }
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
  const contentHash = await computeContentHash(unsigned)

  // Now sign the intent INCLUDING the content hash
  const withHash = { ...unsigned, contentHash }
  const signature = sign(canonicalize(withHash), opts.privateKey)

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
  const artifactSignature = sign(canonicalize(artifact), opts.signerPrivateKey)

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
 * Verify all cryptographic properties of a decision artifact.
 * Checks: content hash, intent signature, decision signature, artifact signature.
 */
export async function verifyDecisionArtifact(
  artifact: DecisionArtifact,
  keys: {
    intentSignerPublicKey: string     // agent who created the intent
    decisionSignerPublicKey: string   // evaluator who made the decision
    artifactSignerPublicKey: string   // entity who created the artifact
  },
  originalIntent: ActionIntent,
  originalDecision: PolicyDecision
): Promise<DecisionArtifactVerification> {
  const errors: string[] = []

  // 1. Verify content hash
  let contentHashValid = false
  if (artifact.intent.contentHash) {
    const { signature, contentHash, ...unsigned } = originalIntent
    const expectedHash = await sha256Hex(canonicalize(unsigned))
    contentHashValid = expectedHash === artifact.intent.contentHash.hash
    if (!contentHashValid) {
      errors.push('Content hash mismatch')
    }
  }

  // 2. Verify intent signature
  const intentCheck = verifyActionIntent(originalIntent)
  const intentSignatureValid = intentCheck.valid
  if (!intentSignatureValid) {
    errors.push(`Intent signature invalid: ${intentCheck.errors.join(', ')}`)
  }

  // 3. Verify decision signature
  const decisionCheck = verifyPolicyDecision(originalDecision)
  const decisionSignatureValid = decisionCheck.valid
  if (!decisionSignatureValid) {
    errors.push(`Decision signature invalid: ${decisionCheck.errors.join(', ')}`)
  }

  // 4. Verify artifact envelope signature
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
    errors
  }
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

async function sha256Hex(data: string): Promise<string> {
  // Use Web Crypto API (available in Node.js 18+ and browsers)
  const encoder = new TextEncoder()
  const buffer = encoder.encode(data)
  const hashBuffer = await crypto.subtle.digest('SHA-256', buffer)
  const hashArray = Array.from(new Uint8Array(hashBuffer))
  return hashArray.map(b => b.toString(16).padStart(2, '0')).join('')
}
