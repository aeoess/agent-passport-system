// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
/**
 * Governance Block — Cryptographic governance metadata for HTML embedding.
 *
 * Embeds signed provenance, terms, and revocation primitives directly into
 * web pages so ANY crawler (not just MCP clients) ingests governance metadata
 * alongside content.
 *
 * Two channels, same primitives:
 *   HTML: governance block embedded in page — evidence layer (proof terms were served)
 *   MCP:  full enforcement — terms must be accepted before content is served
 *
 * Compatible with: C2PA (provenance), RSL (licensing), W3C JSON-LD Signatures
 * Novel contribution: revocation propagation + per-artifact-type obligations
 */

import { createHash } from 'node:crypto'
import { sign, verify, canonicalize, createDID } from '../index.js'

// ═══════════════════════════════════════
// Types
// ═══════════════════════════════════════

export type UsagePermission = 'permitted' | 'prohibited' | 'compensation_required' | 'attribution_required'

export interface GovernanceTerms {
  /** Can agents use this for real-time inference/RAG? */
  inference?: UsagePermission
  /** Can agents use this to train/fine-tune models? */
  training?: UsagePermission
  /** Can agents redistribute or republish this content? */
  redistribution?: UsagePermission
  /** Can agents create derivative works? */
  derivative?: UsagePermission
  /** Can agents cache this content locally? */
  caching?: UsagePermission
  /** Custom terms (key-value) */
  custom?: Record<string, UsagePermission>
  /** Human-readable license reference */
  license_url?: string
  /** Terms version (for settlement pinning) */
  version?: string
}

export interface RevocationPolicy {
  /** What happens to cached copies when this content is revoked? */
  cached_copy: 'delete' | 'retain_with_notice' | 'no_obligation'
  /** What happens to RAG chunks derived from this content? */
  rag_chunk: 'delete' | 'quarantine' | 'no_obligation'
  /** What happens to embeddings derived from this content? */
  embedding: 'quarantine' | 'flag_for_review' | 'no_obligation'
  /** What happens to models fine-tuned on this content? */
  fine_tune: 'no_future_use' | 'retraining_required' | 'no_obligation'
  /** What happens to synthetic derivatives? */
  synthetic: 'compensation_only' | 'delete' | 'no_obligation'
}

export interface GovernanceBlock {
  /** APS protocol identifier */
  '@context': 'https://aeoess.com/governance/v1'
  '@type': 'GovernanceBlock'
  /** DID of the content publisher */
  source_did: string
  /** SHA-256 hash of the content body */
  content_hash: string
  /** When the content was published */
  published_at: string
  /** When the governance block was generated */
  governance_generated_at: string
  /** Machine-readable licensing terms */
  terms: GovernanceTerms
  /** What happens when content is revoked */
  revocation_policy: RevocationPolicy
  /** Ed25519 signature over canonical(everything except signature) */
  signature: string
  /** When the governance block expires (AV-3: replay prevention) */
  expires_at?: string
  /** AV-5: SHA-256 hash of the skill implementation this block governs.
   *  Binds the governance declaration to a specific skill, preventing
   *  one skill from presenting another skill's governance block. */
  skill_hash?: string
}

// ═══════════════════════════════════════
// Default revocation policy
// ═══════════════════════════════════════

export const DEFAULT_REVOCATION_POLICY: RevocationPolicy = {
  cached_copy: 'delete',
  rag_chunk: 'delete',
  embedding: 'quarantine',
  fine_tune: 'no_future_use',
  synthetic: 'compensation_only',
}

// ═══════════════════════════════════════
// Generate
// ═══════════════════════════════════════

export interface GenerateGovernanceBlockInput {
  /** Content body to hash (the article text, not the full HTML) */
  content: string
  /** Publisher's public key (hex) */
  publicKey: string
  /** Publisher's private key (hex) for signing */
  privateKey: string
  /** Licensing terms */
  terms: GovernanceTerms
  /** Revocation policy (defaults to strict) */
  revocationPolicy?: RevocationPolicy
  /** Publication timestamp (defaults to now) */
  publishedAt?: string
  /** Expiry timestamp (AV-3: replay prevention). If set, the block is invalid after this time */
  expiresAt?: string
  /** AV-5: Skill implementation content. If provided, SHA-256 hash is computed and included
   *  in the block, binding governance to this specific implementation. */
  skillContent?: string
}

export function generateGovernanceBlock(input: GenerateGovernanceBlockInput): GovernanceBlock {
  const contentHash = createHash('sha256').update(input.content).digest('hex')
  const sourceDid = createDID(input.publicKey)
  const now = new Date().toISOString()

  const block: Omit<GovernanceBlock, 'signature'> = {
    '@context': 'https://aeoess.com/governance/v1',
    '@type': 'GovernanceBlock',
    source_did: sourceDid,
    content_hash: `sha256:${contentHash}`,
    published_at: input.publishedAt || now,
    governance_generated_at: now,
    terms: input.terms,
    revocation_policy: input.revocationPolicy || DEFAULT_REVOCATION_POLICY,
    ...(input.expiresAt ? { expires_at: input.expiresAt } : {}),
    ...(input.skillContent ? { skill_hash: `sha256:${createHash('sha256').update(input.skillContent).digest('hex')}` } : {}),
  }

  const payload = canonicalize(block)
  const signature = sign(payload, input.privateKey)

  return { ...block, signature }
}

// ═══════════════════════════════════════
// Verify
// ═══════════════════════════════════════

export interface GovernanceBlockVerification {
  /** Is the Ed25519 signature valid? */
  signatureValid: boolean
  /** Does the content hash match the provided content? */
  contentHashValid: boolean
  /** Does the DID resolve to the signing key? */
  didConsistent: boolean
  /** Overall: all checks pass */
  valid: boolean
  /** Human-readable errors */
  errors: string[]
}

export function verifyGovernanceBlock(
  block: GovernanceBlock,
  content: string,
  publicKey: string,
  options?: {
    /** AV-5: If provided, verify the block's skill_hash matches this content */
    skillContent?: string
  },
): GovernanceBlockVerification {
  const errors: string[] = []

  // 1. Verify signature
  const { signature, ...rest } = block
  const payload = canonicalize(rest)
  const signatureValid = verify(payload, signature, publicKey)
  if (!signatureValid) errors.push('Signature verification failed')

  // 2. Verify content hash
  const expectedHash = `sha256:${createHash('sha256').update(content).digest('hex')}`
  const contentHashValid = block.content_hash === expectedHash
  if (!contentHashValid) errors.push(`Content hash mismatch: expected ${expectedHash}, got ${block.content_hash}`)

  // 3. Verify DID consistency
  const expectedDid = createDID(publicKey)
  const didConsistent = block.source_did === expectedDid
  if (!didConsistent) errors.push(`DID mismatch: expected ${expectedDid}, got ${block.source_did}`)

  // 4. AV-5: Verify skill hash if skill content provided
  let skillHashValid = true
  if (options?.skillContent) {
    const expectedSkillHash = `sha256:${createHash('sha256').update(options.skillContent).digest('hex')}`
    if (!block.skill_hash) {
      skillHashValid = false
      errors.push('Skill content provided but block has no skill_hash')
    } else if (block.skill_hash !== expectedSkillHash) {
      skillHashValid = false
      errors.push(`Skill hash mismatch: expected ${expectedSkillHash}, got ${block.skill_hash}`)
    }
  }

  return {
    signatureValid,
    contentHashValid,
    didConsistent,
    valid: signatureValid && contentHashValid && didConsistent && skillHashValid,
    errors,
  }
}

// ═══════════════════════════════════════
// HTML rendering
// ═══════════════════════════════════════

/**
 * Render a governance block as an HTML script tag for embedding in any web page.
 *
 * Usage: Insert the returned string anywhere in your HTML <head> or <body>.
 * Every crawler that reads the page ingests this block alongside the content.
 *
 * Example output:
 * <script type="application/aps-governance+json">{"@context":"https://aeoess.com/governance/v1",...}</script>
 */
export function renderGovernanceHTML(block: GovernanceBlock): string {
  const json = JSON.stringify(block, null, 2)
  return `<script type="application/aps-governance+json">\n${json}\n</script>`
}

/**
 * Render as a meta tag alternative (for strict CSP environments).
 * The full block is base64-encoded in the content attribute.
 */
export function renderGovernanceMeta(block: GovernanceBlock): string {
  const b64 = Buffer.from(JSON.stringify(block)).toString('base64')
  return `<meta name="aps-governance" content="${b64}" />`
}

/**
 * Parse a governance block from HTML content.
 * Looks for <script type="application/aps-governance+json"> or
 * <meta name="aps-governance" content="..."> tags.
 */
export function parseGovernanceBlockFromHTML(html: string): GovernanceBlock | null {
  // Try script tag first
  const scriptMatch = html.match(
    /<script\s+type\s*=\s*"application\/aps-governance\+json"\s*>([\s\S]*?)<\/script>/i
  )
  if (scriptMatch) {
    try { return JSON.parse(scriptMatch[1].trim()) as GovernanceBlock } catch { return null }
  }

  // Try meta tag
  const metaMatch = html.match(
    /<meta\s+name\s*=\s*"aps-governance"\s+content\s*=\s*"([^"]+)"\s*\/?>/i
  )
  if (metaMatch) {
    try {
      const decoded = Buffer.from(metaMatch[1], 'base64').toString('utf-8')
      return JSON.parse(decoded) as GovernanceBlock
    } catch { return null }
  }

  return null
}

/**
 * Convenience: generate + render in one call.
 * Returns both the block (for storage/MCP) and the HTML tag (for embedding).
 */
export function embedGovernance(input: GenerateGovernanceBlockInput): {
  block: GovernanceBlock
  html: string
  meta: string
} {
  const block = generateGovernanceBlock(input)
  return {
    block,
    html: renderGovernanceHTML(block),
    meta: renderGovernanceMeta(block),
  }
}

/**
 * Check if a specific usage is permitted under the governance block's terms.
 */
export function isUsagePermitted(
  block: GovernanceBlock,
  usage: keyof Omit<GovernanceTerms, 'custom' | 'license_url' | 'version'>,
): { permitted: boolean; condition: UsagePermission | 'not_specified' } {
  const permission = block.terms[usage]
  if (!permission) return { permitted: true, condition: 'not_specified' }
  return {
    permitted: permission === 'permitted' || permission === 'attribution_required',
    condition: permission,
  }
}


// ══════════════════════════════════════════════════════════════════
// AV-5 Fix: Governance Block ↔ Implementation Binding
// Source: MoltyCel on qntm#7 — a skill can present a governance
// block that mimics another skill's declarations. Without binding
// the block to the implementation, there's no proof they belong
// together.
// ══════════════════════════════════════════════════════════════════

export interface GovernanceBinding {
  /** Hash of the governance block (canonical JSON) */
  governanceBlockHash: string
  /** Hash of the skill implementation (source code or artifact) */
  implementationHash: string
  /** Combined binding hash */
  bindingHash: string
  /** Publisher DID */
  publisherDid: string
  /** Timestamp of binding */
  boundAt: string
  /** Signature over the binding (Ed25519) */
  signature: string
}

/**
 * Bind a governance block to a skill implementation.
 * Creates a cryptographic proof that this governance block
 * belongs to this specific implementation.
 *
 * A verifier checks: governanceBlockHash matches the block,
 * implementationHash matches the code, bindingHash ties them,
 * signature proves the publisher created the binding.
 */
export function bindGovernanceToImplementation(input: {
  /** The governance block to bind */
  governanceBlock: GovernanceBlock
  /** SHA-256 hash of the skill implementation */
  implementationHash: string
  /** Publisher's private key for signing */
  privateKey: string
  /** Publisher's DID */
  publisherDid: string
}): GovernanceBinding {
  const { governanceBlock, implementationHash, privateKey, publisherDid } = input

  // Hash the governance block
  const { signature: _sig, ...blockWithoutSig } = governanceBlock
  const governanceBlockHash = `sha256:${createHash('sha256')
    .update(canonicalize(blockWithoutSig))
    .digest('hex')}`

  // Create the binding hash — ties block to implementation
  const bindingInput = `${governanceBlockHash}:${implementationHash}:${publisherDid}`
  const bindingHash = `sha256:${createHash('sha256')
    .update(bindingInput)
    .digest('hex')}`

  const now = new Date().toISOString()

  // Sign the binding
  const bindingPayload = canonicalize({
    governanceBlockHash,
    implementationHash,
    bindingHash,
    publisherDid,
    boundAt: now,
  })
  const bindingSig = sign(bindingPayload, privateKey)

  return {
    governanceBlockHash,
    implementationHash,
    bindingHash,
    publisherDid,
    boundAt: now,
    signature: bindingSig,
  }
}

/**
 * Verify a governance-to-implementation binding.
 * Confirms: hashes match, binding is correctly computed,
 * signature is valid.
 */
export function verifyGovernanceBinding(
  binding: GovernanceBinding,
  governanceBlock: GovernanceBlock,
  implementationHash: string,
  publicKey: string
): { valid: boolean; errors: string[] } {
  const errors: string[] = []

  // Verify governance block hash
  const { signature: _sig, ...blockWithoutSig } = governanceBlock
  const expectedBlockHash = `sha256:${createHash('sha256')
    .update(canonicalize(blockWithoutSig))
    .digest('hex')}`
  if (binding.governanceBlockHash !== expectedBlockHash) {
    errors.push('Governance block hash mismatch — block may have been modified')
  }

  // Verify implementation hash
  if (binding.implementationHash !== implementationHash) {
    errors.push('Implementation hash mismatch — code may have been modified')
  }

  // Verify binding hash construction
  const expectedBinding = `sha256:${createHash('sha256')
    .update(`${binding.governanceBlockHash}:${binding.implementationHash}:${binding.publisherDid}`)
    .digest('hex')}`
  if (binding.bindingHash !== expectedBinding) {
    errors.push('Binding hash mismatch — binding may have been tampered')
  }

  // Verify signature
  const payload = canonicalize({
    governanceBlockHash: binding.governanceBlockHash,
    implementationHash: binding.implementationHash,
    bindingHash: binding.bindingHash,
    publisherDid: binding.publisherDid,
    boundAt: binding.boundAt,
  })
  const sigValid = verify(payload, binding.signature, publicKey)
  if (!sigValid) errors.push('Binding signature verification failed')

  return { valid: errors.length === 0, errors }
}


// ══════════════════════════════════════════════════════════════════
// AV-3 Fix: Governance Block Expiry Check
// Source: MoltyCel on qntm#7 — expired blocks presented as valid
// ══════════════════════════════════════════════════════════════════

/**
 * Check if a governance block has expired.
 * Returns true if the block has an expires_at field and it's in the past.
 */
export function isGovernanceBlockExpired(block: GovernanceBlock): boolean {
  if (!block.expires_at) return false // no expiry = never expires
  return new Date(block.expires_at) < new Date()
}

// ══════════════════════════════════════════════════════════════════
// AV-1 Fix: Verified Governance Credential (W3C VC wrapper)
// Source: MoltyCel on qntm#7 — governance block spoofing
// ══════════════════════════════════════════════════════════════════

/** W3C Verifiable Credential wrapping a governance block for tamper-evidence */
export interface VerifiedGovernanceCredential {
  '@context': ['https://www.w3.org/2018/credentials/v1', 'https://aeoess.com/governance/v1']
  type: ['VerifiableCredential', 'GovernanceCredential']
  issuer: string  // publisher DID
  issuanceDate: string
  expirationDate?: string
  credentialSubject: {
    /** Hash of the governance block (canonical JSON, SHA-256) */
    governanceBlockHash: string
    /** The source content hash */
    contentHash: string
    /** The publisher DID */
    publisherDid: string
    /** Summary of terms for quick verification */
    termsVersion?: string
  }
  proof: {
    type: 'Ed25519Signature2020'
    created: string
    verificationMethod: string // publisher DID + key reference
    proofPurpose: 'assertionMethod'
    proofValue: string  // Ed25519 signature
  }
}

/**
 * Create a Verified Governance Credential — W3C VC wrapping a governance block.
 * Makes the block tamper-evident: any modification after issuance invalidates the credential.
 * The hash is independently verifiable without trusting the presenter.
 */
export function createVerifiedGovernanceCredential(input: {
  block: GovernanceBlock
  privateKey: string
  publisherDid: string
}): VerifiedGovernanceCredential {
  const { block, privateKey, publisherDid } = input

  // Hash the block (excluding signature for consistency with verification)
  const { signature: _sig, ...blockWithoutSig } = block
  const blockHash = `sha256:${createHash('sha256')
    .update(canonicalize(blockWithoutSig))
    .digest('hex')}`

  const now = new Date().toISOString()

  const credential: Omit<VerifiedGovernanceCredential, 'proof'> = {
    '@context': ['https://www.w3.org/2018/credentials/v1', 'https://aeoess.com/governance/v1'],
    type: ['VerifiableCredential', 'GovernanceCredential'],
    issuer: publisherDid,
    issuanceDate: now,
    ...(block.expires_at ? { expirationDate: block.expires_at } : {}),
    credentialSubject: {
      governanceBlockHash: blockHash,
      contentHash: block.content_hash,
      publisherDid: block.source_did,
      termsVersion: block.terms.version,
    },
  }

  const proofPayload = canonicalize(credential)
  const proofValue = sign(proofPayload, privateKey)

  return {
    ...credential,
    proof: {
      type: 'Ed25519Signature2020',
      created: now,
      verificationMethod: `${publisherDid}#key-1`,
      proofPurpose: 'assertionMethod',
      proofValue,
    },
  }
}

/**
 * Verify a Verified Governance Credential.
 * Checks: signature valid, block hash matches, not expired.
 */
export function verifyGovernanceCredential(
  credential: VerifiedGovernanceCredential,
  block: GovernanceBlock,
  publicKey: string
): { valid: boolean; errors: string[] } {
  const errors: string[] = []

  // 1. Verify the proof signature
  const { proof, ...credentialWithoutProof } = credential
  const proofPayload = canonicalize(credentialWithoutProof)
  if (!verify(proofPayload, proof.proofValue, publicKey)) {
    errors.push('Credential proof signature invalid')
  }

  // 2. Verify block hash matches
  const { signature: _sig, ...blockWithoutSig } = block
  const expectedHash = `sha256:${createHash('sha256')
    .update(canonicalize(blockWithoutSig))
    .digest('hex')}`
  if (credential.credentialSubject.governanceBlockHash !== expectedHash) {
    errors.push('Governance block hash mismatch — block was modified after credential issuance')
  }

  // 3. Check expiry (AV-3)
  if (credential.expirationDate && new Date(credential.expirationDate) < new Date()) {
    errors.push('Governance credential has expired')
  }

  return { valid: errors.length === 0, errors }
}
