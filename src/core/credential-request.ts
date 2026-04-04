// Agent Passport System — Credential Request Protocol
// Selective disclosure: verifier requests specific claims,
// agent presents a VC containing only those claims.

import { canonicalize } from './canonical.js'
import { sign, verify, publicKeyFromPrivate } from '../crypto/keys.js'
import { toDIDKey, fromDIDKey } from './did-interop.js'
import { hexToMultibase } from './did.js'
import type { VerifiableCredential, VerifiablePresentation, LinkedDataProof } from '../types/did.js'
import type { ProviderAttestation } from '../types/attestation.js'

// ── Types ──

export interface CredentialRequest {
  /** Unique request ID */
  id: string
  /** Claims the verifier wants (e.g., ["grade", "capabilities", "delegationScope"]) */
  requestedClaims: string[]
  /** DID of the verifier making the request */
  verifierDID: string
  /** Challenge nonce for replay protection */
  challenge: string
  /** When this request was created */
  createdAt: string
}

export interface CredentialResponseResult {
  valid: boolean
  /** Extracted claims that the verifier requested */
  claims: Record<string, unknown>
  /** Detailed checks */
  checks: string[]
}

export interface SelectivePassport {
  agentId: string
  publicKey: string
  agentName?: string
  mission?: string
  capabilities?: string[]
  grade?: number
  delegationScope?: string[]
  createdAt?: string
  expiresAt?: string
  evidence?: ProviderAttestation[]
}

// ── Constants ──

const VC_CONTEXT = [
  'https://www.w3.org/ns/credentials/v2',
  'https://w3id.org/security/suites/ed25519-2020/v1',
]
const APS_CONTEXT = 'https://aeoess.com/ns/agent-passport/v1'

// ── Credential Request Protocol ──

/**
 * Create a credential request specifying which claims the verifier needs.
 * The challenge provides replay protection: the agent must bind the VP
 * to this specific challenge.
 */
export function createCredentialRequest(
  claims: string[],
  verifierDID: string,
  challenge?: string,
): CredentialRequest {
  if (!claims || claims.length === 0) {
    throw new Error('Credential request must specify at least one claim')
  }
  if (!verifierDID) {
    throw new Error('Verifier DID is required')
  }

  return {
    id: `creq_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`,
    requestedClaims: claims,
    verifierDID,
    challenge: challenge || crypto.randomUUID(),
    createdAt: new Date().toISOString(),
  }
}

/**
 * Fulfill a credential request by creating a VP that contains only
 * the requested claims. This is selective disclosure: the agent
 * reveals only what the verifier asked for.
 *
 * The VC's credentialSubject will contain:
 * - id (always included, the agent's did:key)
 * - agentId (always included for APS correlation)
 * - only the fields listed in request.requestedClaims
 */
export async function fulfillCredentialRequest(
  request: CredentialRequest,
  passport: SelectivePassport,
  privateKey: string,
): Promise<VerifiablePresentation> {
  const publicKey = publicKeyFromPrivate(privateKey)
  const subjectDIDKey = toDIDKey(passport.publicKey)
  const issuerDIDKey = toDIDKey(publicKey)
  const now = new Date().toISOString()

  // Build selective credentialSubject
  const fullSubject: Record<string, unknown> = {
    id: subjectDIDKey,
    agentId: passport.agentId,
    publicKey: subjectDIDKey,
    publicKeyMultibase: hexToMultibase(passport.publicKey),
    agentName: passport.agentName,
    mission: passport.mission,
    capabilities: passport.capabilities,
    grade: passport.grade,
    delegationScope: passport.delegationScope,
  }

  // Filter to only requested claims + mandatory fields
  const selective: Record<string, unknown> = {
    id: fullSubject.id,
    agentId: fullSubject.agentId,
  }
  for (const claim of request.requestedClaims) {
    if (claim in fullSubject && fullSubject[claim] !== undefined) {
      selective[claim] = fullSubject[claim]
    }
  }

  // Build the VC
  const credential: Record<string, unknown> = {
    '@context': [...VC_CONTEXT, APS_CONTEXT],
    id: `urn:aps:credential:selective:${passport.agentId}:${request.id}`,
    type: ['VerifiableCredential', 'AgentPassportCredential'],
    issuer: issuerDIDKey,
    issuanceDate: passport.createdAt || now,
    credentialSubject: selective,
  }

  if (passport.expiresAt) {
    credential.expirationDate = passport.expiresAt
  }

  if (passport.evidence && passport.evidence.length > 0) {
    credential.evidence = passport.evidence.map(att => ({
      type: 'InfrastructureAttestation',
      provider: att.provider,
      subjectClass: att.subjectClass,
      verificationMethod: att.verificationMethod,
      issuedAt: att.issuedAt,
      expiresAt: att.expiresAt,
    }))
  }

  const vcProof = await createProof(credential, privateKey, issuerDIDKey, 'assertionMethod')
  const vc = { ...credential, proof: vcProof } as VerifiableCredential

  // Wrap in VP with the request's challenge
  const holderDIDKey = toDIDKey(passport.publicKey)

  const presentation: Record<string, unknown> = {
    '@context': VC_CONTEXT,
    id: `urn:aps:presentation:${request.id}`,
    type: ['VerifiablePresentation'],
    holder: holderDIDKey,
    verifiableCredential: [vc],
  }

  const vpProof = await createProof(
    presentation,
    privateKey,
    holderDIDKey,
    'authentication',
    { challenge: request.challenge, domain: request.verifierDID },
  )

  return { ...presentation, proof: vpProof } as unknown as VerifiablePresentation
}

/**
 * Verify a credential response VP and extract the requested claims.
 *
 * Checks:
 * 1. VP proof is valid
 * 2. Challenge matches (replay protection)
 * 3. Each contained VC proof is valid
 * 4. Credential is not expired
 * 5. Extracts claims from credentialSubject
 */
export async function verifyCredentialResponse(
  vp: VerifiablePresentation,
  expectedChallenge?: string,
): Promise<CredentialResponseResult> {
  const checks: string[] = []
  let valid = true

  // Check required fields
  if (!vp.holder || !vp.proof || !vp.verifiableCredential) {
    checks.push('FAIL: missing required VP fields')
    return { valid: false, claims: {}, checks }
  }
  checks.push('PASS: required VP fields present')

  // Verify challenge if expected
  const proof = vp.proof as LinkedDataProof & { challenge?: string; domain?: string }
  if (expectedChallenge) {
    if (proof.challenge === expectedChallenge) {
      checks.push('PASS: challenge matches')
    } else {
      checks.push(`FAIL: challenge mismatch — expected "${expectedChallenge}", got "${proof.challenge}"`)
      valid = false
    }
  }

  // Verify VP proof
  try {
    const vmDID = vp.proof.verificationMethod.split('#')[0]
    const publicKey = vmDID.startsWith('did:key:') ? fromDIDKey(vmDID) : vmDID.split(':').pop()!
    const { proof: vpProof, ...vpWithoutProof } = vp
    const canonical = canonicalize(vpWithoutProof as unknown as Record<string, unknown>)
    const sigHex = base64urlToHex(vpProof.proofValue)
    const sigValid = verify(canonical, sigHex, publicKey)

    if (sigValid) {
      checks.push('PASS: presentation signature valid')
    } else {
      checks.push('FAIL: presentation signature invalid')
      valid = false
    }
  } catch (err) {
    checks.push(`FAIL: presentation signature error — ${err instanceof Error ? err.message : String(err)}`)
    valid = false
  }

  // Verify each credential and extract claims
  const claims: Record<string, unknown> = {}

  for (let i = 0; i < vp.verifiableCredential.length; i++) {
    const vc = vp.verifiableCredential[i]

    // Verify VC proof
    try {
      const vmDID = vc.proof.verificationMethod.split('#')[0]
      const publicKey = vmDID.startsWith('did:key:') ? fromDIDKey(vmDID) : vmDID.split(':').pop()!
      const { proof: vcProof, ...vcWithoutProof } = vc
      const canonical = canonicalize(vcWithoutProof as unknown as Record<string, unknown>)
      const sigHex = base64urlToHex(vcProof.proofValue)
      const sigValid = verify(canonical, sigHex, publicKey)

      if (sigValid) {
        checks.push(`PASS: credential[${i}] signature valid`)
      } else {
        checks.push(`FAIL: credential[${i}] signature invalid`)
        valid = false
        continue
      }
    } catch (err) {
      checks.push(`FAIL: credential[${i}] signature error — ${err instanceof Error ? err.message : String(err)}`)
      valid = false
      continue
    }

    // Check expiration
    if (vc.expirationDate) {
      if (new Date(vc.expirationDate) < new Date()) {
        checks.push(`FAIL: credential[${i}] expired`)
        valid = false
      } else {
        checks.push(`PASS: credential[${i}] not expired`)
      }
    }

    // Extract claims
    const subject = vc.credentialSubject as Record<string, unknown>
    for (const [key, value] of Object.entries(subject)) {
      if (key !== 'id' && value !== undefined) {
        claims[key] = value
      }
    }
  }

  return { valid, claims, checks }
}

// ── Proof Helpers ──

import crypto from 'node:crypto'

async function createProof(
  data: Record<string, unknown>,
  privateKey: string,
  did: string,
  purpose: LinkedDataProof['proofPurpose'],
  options?: { challenge?: string; domain?: string },
): Promise<LinkedDataProof> {
  const canonical = canonicalize(data as Record<string, unknown>)
  const sig = sign(canonical, privateKey)

  const proof: LinkedDataProof & { challenge?: string; domain?: string } = {
    type: 'Ed25519Signature2020',
    created: new Date().toISOString(),
    verificationMethod: `${did}#key-1`,
    proofPurpose: purpose,
    proofValue: hexToBase64url(sig),
  }

  if (options?.challenge) proof.challenge = options.challenge
  if (options?.domain) proof.domain = options.domain

  return proof
}

// ── Encoding ──

function hexToBytes(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2)
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.substring(i, i + 2), 16)
  }
  return bytes
}

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('')
}

function hexToBase64url(hex: string): string {
  const bytes = hexToBytes(hex)
  const base64 = Buffer.from(bytes).toString('base64')
  return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

function base64urlToHex(b64url: string): string {
  const base64 = b64url.replace(/-/g, '+').replace(/_/g, '/')
  const buf = Buffer.from(base64, 'base64')
  return bytesToHex(new Uint8Array(buf))
}
