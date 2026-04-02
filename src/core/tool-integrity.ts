// ══════════════════════════════════════════════════════════════════
// Tool Integrity Verification — OWASP Layer 2
// ══════════════════════════════════════════════════════════════════
// Source: OWASP#802 four-layer integrity taxonomy
// Layer 1: Transmission integrity (TLS) ✅
// Layer 2: Tool integrity (THIS MODULE) — tool invoked = tool approved
// Layer 3: Authorization-at-execution (ExecutionAttestation) ✅
// Layer 4: Intent integrity (ActionIntent) ✅
//
// Prevents tool-swap attacks: agent authorized to call `web_search`
// but the tool registry is swapped to a malicious implementation.
// ══════════════════════════════════════════════════════════════════

import { createHash } from 'node:crypto'
import { sign, verify } from '../crypto/keys.js'
import { canonicalize } from './canonical.js'

/** Registry entry for a verified tool */
export interface ToolRegistryEntry {
  /** Tool name (must match the name in delegation scope) */
  toolName: string
  /** SHA-256 hash of the tool implementation (binary, source, or endpoint descriptor) */
  implementationHash: string
  /** Who attested this tool's integrity (runtime, registry, or auditor DID) */
  attestorId: string
  /** When the tool hash was last verified */
  verifiedAt: string
  /** Ed25519 signature over {toolName, implementationHash, attestorId, verifiedAt} */
  signature: string
}

/** Per-invocation trust requirements — tools declare what they need
 *  Source: ymc182/MeshCap on A2A#1628 */
export interface ToolRequirements {
  /** Minimum passport grade required (0-3) */
  minGrade?: number
  /** Required delegation scopes */
  requiredScopes?: string[]
  /** Minimum trust score (0-1) */
  minTrustScore?: number
  /** Whether the tool requires a verified wallet */
  requiresWallet?: boolean
  /** Custom requirements (key-value, tool-specific) */
  custom?: Record<string, unknown>
}

/** Result of tool integrity + requirements check */
export interface ToolIntegrityResult {
  /** Whether the tool passed all checks */
  valid: boolean
  /** Whether the implementation hash matches */
  implementationVerified: boolean
  /** Whether the attestor signature is valid */
  attestorSignatureValid: boolean
  /** Whether the agent meets tool requirements (if any) */
  requirementsMet: boolean
  /** Which requirements failed */
  failedRequirements: string[]
  /** Errors */
  errors: string[]
}

/**
 * Register a tool in the integrity registry.
 * The runtime/attestor signs that this tool implementation is known and approved.
 */
export function createToolRegistryEntry(input: {
  toolName: string
  /** Raw content to hash (source code, binary, or endpoint descriptor JSON) */
  implementation: string | Buffer
  attestorId: string
  attestorPrivateKey: string
}): ToolRegistryEntry {
  const implHash = createHash('sha256')
    .update(typeof input.implementation === 'string' ? input.implementation : input.implementation)
    .digest('hex')

  const now = new Date().toISOString()
  const body = {
    toolName: input.toolName,
    implementationHash: `sha256:${implHash}`,
    attestorId: input.attestorId,
    verifiedAt: now,
  }
  const signature = sign(canonicalize(body), input.attestorPrivateKey)

  return { ...body, signature }
}

/**
 * Verify tool integrity: is this the same tool that was approved?
 * Also checks per-invocation requirements if provided.
 */
export function verifyToolIntegrity(input: {
  /** The registry entry to verify against */
  registryEntry: ToolRegistryEntry
  /** Current implementation to check (will be hashed) */
  currentImplementation: string | Buffer
  /** Attestor's public key for signature verification */
  attestorPublicKey: string
  /** Optional: tool requirements to check against agent capabilities */
  requirements?: ToolRequirements
  /** Optional: agent's current capabilities (for requirements check) */
  agentCapabilities?: {
    grade: number
    scopes: string[]
    trustScore: number
    hasWallet: boolean
  }
}): ToolIntegrityResult {
  const errors: string[] = []
  const failedRequirements: string[] = []

  // 1. Verify attestor signature
  const { signature, ...body } = input.registryEntry
  const attestorSignatureValid = verify(canonicalize(body), signature, input.attestorPublicKey)
  if (!attestorSignatureValid) errors.push('Tool attestor signature invalid')

  // 2. Verify implementation hash matches
  const currentHash = `sha256:${createHash('sha256')
    .update(typeof input.currentImplementation === 'string' ? input.currentImplementation : input.currentImplementation)
    .digest('hex')}`
  const implementationVerified = currentHash === input.registryEntry.implementationHash
  if (!implementationVerified) {
    errors.push(`Tool implementation hash mismatch: expected ${input.registryEntry.implementationHash}, got ${currentHash}`)
  }

  // 3. Check per-invocation requirements (if tool declares them)
  let requirementsMet = true
  if (input.requirements && input.agentCapabilities) {
    const reqs = input.requirements
    const caps = input.agentCapabilities

    if (reqs.minGrade !== undefined && caps.grade < reqs.minGrade) {
      failedRequirements.push(`Grade ${caps.grade} < required ${reqs.minGrade}`)
      requirementsMet = false
    }
    if (reqs.minTrustScore !== undefined && caps.trustScore < reqs.minTrustScore) {
      failedRequirements.push(`Trust score ${caps.trustScore} < required ${reqs.minTrustScore}`)
      requirementsMet = false
    }
    if (reqs.requiredScopes) {
      const missing = reqs.requiredScopes.filter(s => !caps.scopes.includes(s))
      if (missing.length > 0) {
        failedRequirements.push(`Missing scopes: ${missing.join(', ')}`)
        requirementsMet = false
      }
    }
    if (reqs.requiresWallet && !caps.hasWallet) {
      failedRequirements.push('Tool requires wallet but agent has none')
      requirementsMet = false
    }
  }

  if (!requirementsMet) errors.push(`Agent does not meet tool requirements: ${failedRequirements.join('; ')}`)

  return {
    valid: errors.length === 0,
    implementationVerified,
    attestorSignatureValid,
    requirementsMet,
    failedRequirements,
    errors,
  }
}
