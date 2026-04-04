// Agent Passport System — VC Wrapper (Interop Bridge)
// Thin layer over vc.ts that uses did:key identifiers, includes
// passport grade + delegation scope in credentialSubject, and
// connects SPIFFE attestations as VC evidence.
//
// Bridges: did-interop.ts (did:key) + identity-bridge.ts (SPIFFE/OAuth)
//        → vc.ts (W3C Verifiable Credentials)

import { canonicalize } from './canonical.js'
import { sign, verify, publicKeyFromPrivate } from '../crypto/keys.js'
import { toDIDKey, fromDIDKey } from './did-interop.js'
import { hexToMultibase } from './did.js'
import type { VerifiableCredential, VerifiablePresentation, LinkedDataProof } from '../types/did.js'
import type { ProviderAttestation } from '../types/attestation.js'

// ── Constants ──

const VC_CONTEXT = [
  'https://www.w3.org/ns/credentials/v2',
  'https://w3id.org/security/suites/ed25519-2020/v1',
]
const APS_CONTEXT = 'https://aeoess.com/ns/agent-passport/v1'

// ── Types ──

export interface PassportVCInput {
  agentId: string
  publicKey: string
  agentName?: string
  mission?: string
  capabilities?: string[]
  grade?: number
  delegationScope?: string[]
  createdAt?: string
  expiresAt?: string
  /** SPIFFE or other infrastructure attestation to include as evidence */
  evidence?: ProviderAttestation[]
}

export interface VCVerifyResult {
  valid: boolean
  checks: string[]
}

export interface VPVerifyResult {
  valid: boolean
  credentials: VerifiableCredential[]
  checks: string[]
}

// ── Credential Creation ──

/**
 * Wrap an APS passport as a W3C Verifiable Credential using did:key
 * as the subject identifier.
 *
 * credentialSubject includes grade and delegationScope (the delegation
 * ceiling). If evidence (e.g., from importSPIFFESVID) is provided, it
 * is attached to the VC as W3C evidence, proving the identity claim
 * is backed by infrastructure attestation.
 */
export async function passportToVerifiableCredential(
  passport: PassportVCInput,
  issuerPrivateKey: string,
): Promise<VerifiableCredential> {
  const issuerPublicKey = publicKeyFromPrivate(issuerPrivateKey)
  const subjectDIDKey = toDIDKey(passport.publicKey)
  const issuerDIDKey = toDIDKey(issuerPublicKey)

  const now = new Date().toISOString()

  const credentialSubject: Record<string, unknown> = {
    id: subjectDIDKey,
    agentId: passport.agentId,
    publicKey: subjectDIDKey,
    publicKeyMultibase: hexToMultibase(passport.publicKey),
  }
  if (passport.agentName) credentialSubject.agentName = passport.agentName
  if (passport.mission) credentialSubject.mission = passport.mission
  if (passport.capabilities) credentialSubject.capabilities = passport.capabilities
  if (passport.grade !== undefined) credentialSubject.grade = passport.grade
  if (passport.delegationScope) credentialSubject.delegationScope = passport.delegationScope

  const credential: Record<string, unknown> = {
    '@context': [...VC_CONTEXT, APS_CONTEXT],
    id: `urn:aps:credential:passport:${passport.agentId}`,
    type: ['VerifiableCredential', 'AgentPassportCredential'],
    issuer: issuerDIDKey,
    issuanceDate: passport.createdAt || now,
    credentialSubject,
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

  const proof = await createProof(credential, issuerPrivateKey, issuerDIDKey, 'assertionMethod')
  return { ...credential, proof } as VerifiableCredential
}

// ── Credential Verification ──

/**
 * Verify a Verifiable Credential's Ed25519 proof.
 * Returns a checks array listing each verification step and its result.
 */
export async function verifyVerifiableCredential(vc: VerifiableCredential): Promise<VCVerifyResult> {
  const checks: string[] = []
  let valid = true

  // Check required fields
  if (!vc['@context'] || !vc.type || !vc.issuer || !vc.credentialSubject || !vc.proof) {
    checks.push('FAIL: missing required VC fields')
    return { valid: false, checks }
  }
  checks.push('PASS: required fields present')

  // Check VC type
  if (!vc.type.includes('VerifiableCredential')) {
    checks.push('FAIL: type array must include VerifiableCredential')
    return { valid: false, checks }
  }
  checks.push('PASS: type includes VerifiableCredential')

  // Check expiration
  if (vc.expirationDate) {
    if (new Date(vc.expirationDate) < new Date()) {
      checks.push('FAIL: credential expired')
      valid = false
    } else {
      checks.push('PASS: credential not expired')
    }
  } else {
    checks.push('SKIP: no expirationDate set')
  }

  // Verify Ed25519 signature
  try {
    const vmDID = vc.proof.verificationMethod.split('#')[0]
    let publicKey: string

    if (vmDID.startsWith('did:key:')) {
      publicKey = fromDIDKey(vmDID)
    } else {
      // Fall back to did:aps parsing
      const parts = vmDID.split(':')
      publicKey = parts[parts.length - 1]
    }

    const { proof, ...credentialWithoutProof } = vc
    const canonical = canonicalize(credentialWithoutProof as unknown as Record<string, unknown>)
    const sigHex = base64urlToHex(proof.proofValue)
    const sigValid = verify(canonical, sigHex, publicKey)

    if (sigValid) {
      checks.push('PASS: Ed25519 signature valid')
    } else {
      checks.push('FAIL: Ed25519 signature invalid')
      valid = false
    }
  } catch (err) {
    checks.push(`FAIL: signature verification error — ${err instanceof Error ? err.message : String(err)}`)
    valid = false
  }

  // Check evidence if present
  const cred = vc as unknown as Record<string, unknown>
  if (Array.isArray(cred.evidence) && cred.evidence.length > 0) {
    checks.push(`PASS: ${cred.evidence.length} evidence attachment(s) present`)
  }

  return { valid, checks }
}

// ── Verifiable Presentation ──

/**
 * Wrap one or more VCs into a Verifiable Presentation for a verifier.
 * Uses did:key for the holder identifier.
 * Challenge and domain provide replay protection.
 */
export async function createVerifiablePresentation(
  credentials: VerifiableCredential[],
  holderPrivateKey: string,
  options?: { challenge?: string; domain?: string },
): Promise<VerifiablePresentation> {
  const holderPublicKey = publicKeyFromPrivate(holderPrivateKey)
  const holderDIDKey = toDIDKey(holderPublicKey)

  const presentation: Record<string, unknown> = {
    '@context': VC_CONTEXT,
    id: `urn:aps:presentation:${Date.now()}`,
    type: ['VerifiablePresentation'],
    holder: holderDIDKey,
    verifiableCredential: credentials,
  }

  const proof = await createProof(
    presentation,
    holderPrivateKey,
    holderDIDKey,
    'authentication',
    options,
  )

  return { ...presentation, proof } as unknown as VerifiablePresentation
}

/**
 * Verify a Verifiable Presentation: check the presentation proof,
 * then verify each contained credential.
 */
export async function verifyVerifiablePresentation(
  vp: VerifiablePresentation,
): Promise<VPVerifyResult> {
  const checks: string[] = []
  let valid = true

  // Check required fields
  if (!vp.holder || !vp.proof || !vp.verifiableCredential) {
    checks.push('FAIL: missing required VP fields')
    return { valid: false, credentials: [], checks }
  }
  checks.push('PASS: required VP fields present')

  // Verify presentation proof
  try {
    const vmDID = vp.proof.verificationMethod.split('#')[0]
    let publicKey: string

    if (vmDID.startsWith('did:key:')) {
      publicKey = fromDIDKey(vmDID)
    } else {
      const parts = vmDID.split(':')
      publicKey = parts[parts.length - 1]
    }

    const { proof, ...vpWithoutProof } = vp
    const canonical = canonicalize(vpWithoutProof as unknown as Record<string, unknown>)
    const sigHex = base64urlToHex(proof.proofValue)
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

  // Verify each credential
  for (let i = 0; i < vp.verifiableCredential.length; i++) {
    const vc = vp.verifiableCredential[i]
    const vcResult = await verifyVerifiableCredential(vc)
    if (vcResult.valid) {
      checks.push(`PASS: credential[${i}] (${vc.id}) verified`)
    } else {
      checks.push(`FAIL: credential[${i}] (${vc.id}) — ${vcResult.checks.filter(c => c.startsWith('FAIL')).join('; ')}`)
      valid = false
    }
  }

  return { valid, credentials: vp.verifiableCredential, checks }
}

// ── Proof Helpers ──

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
