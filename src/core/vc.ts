// Agent Passport System — W3C Verifiable Credentials
// Wraps protocol artifacts as W3C VC Data Model 2.0 credentials.
// Pure translation layer: no changes to core protocol.

import { canonicalize } from './canonical.js'
import { sign, verify, publicKeyFromPrivate } from '../crypto/keys.js'
import { createDID, publicKeyFromDID, hexToMultibase } from './did.js'
import type { AgentPassport, Delegation, ActionReceipt } from '../types/passport.js'
import type {
  VerifiableCredential, VerifiablePresentation, LinkedDataProof,
  PassportCredentialSubject, DelegationCredentialSubject,
  FloorAttestationCredentialSubject, PolicyReceiptCredentialSubject
} from '../types/did.js'

// ── Constants ──

const VC_CONTEXT = [
  'https://www.w3.org/ns/credentials/v2',
  'https://w3id.org/security/suites/ed25519-2020/v1'
]

const APS_CONTEXT = 'https://aeoess.com/ns/agent-passport/v1'

// ── Credential Creation ──

/**
 * Create a Verifiable Credential for an Agent Passport.
 * The passport holder proves their identity and capabilities.
 */
export async function passportToVC(
  passport: AgentPassport,
  issuerPrivateKey: string,
  issuerPublicKey: string
): Promise<VerifiableCredential> {
  const agentDID = createDID(passport.publicKey)
  const issuerDID = createDID(issuerPublicKey)

  const subject: PassportCredentialSubject = {
    id: agentDID,
    agentName: passport.agentName,
    ownerAlias: passport.ownerAlias,
    mission: passport.mission,
    capabilities: passport.capabilities,
    runtime: {
      platform: passport.runtime.platform,
      models: passport.runtime.models
    }
  }

  const credential: Omit<VerifiableCredential, 'proof'> = {
    '@context': [...VC_CONTEXT, APS_CONTEXT],
    id: `urn:aps:credential:passport:${passport.agentId}`,
    type: ['VerifiableCredential', 'AgentPassportCredential'],
    issuer: issuerDID,
    issuanceDate: passport.createdAt,
    expirationDate: passport.expiresAt,
    credentialSubject: subject as unknown as Record<string, unknown>
  }

  const proof = await createProof(credential, issuerPrivateKey, issuerDID, 'assertionMethod')
  return { ...credential, proof }
}

/**
 * Create a Verifiable Credential for a Delegation.
 * Proves that authority was granted from delegator to delegate.
 */
export async function delegationToVC(
  delegation: Delegation,
  delegatorPrivateKey: string
): Promise<VerifiableCredential> {
  const delegatorDID = createDID(delegation.delegatedBy)
  const delegateDID = createDID(delegation.delegatedTo)

  const subject: DelegationCredentialSubject = {
    id: delegateDID,
    delegatedBy: delegatorDID,
    scope: delegation.scope,
    spendLimit: delegation.spendLimit,
    maxDepth: delegation.maxDepth,
    currentDepth: delegation.currentDepth,
    expiresAt: delegation.expiresAt
  }

  const credential: Omit<VerifiableCredential, 'proof'> = {
    '@context': [...VC_CONTEXT, APS_CONTEXT],
    id: `urn:aps:credential:delegation:${delegation.delegationId}`,
    type: ['VerifiableCredential', 'AgentDelegationCredential'],
    issuer: delegatorDID,
    issuanceDate: delegation.createdAt,
    expirationDate: delegation.expiresAt,
    credentialSubject: subject as unknown as Record<string, unknown>
  }

  const proof = await createProof(credential, delegatorPrivateKey, delegatorDID, 'capabilityDelegation')
  return { ...credential, proof }
}

/**
 * Create a Verifiable Credential for a Floor Attestation.
 * Proves an agent has attested to the Values Floor.
 */
export async function floorAttestationToVC(
  attestation: { agentId: string; floorVersion: string; principles: string[]; extensions?: string[]; attestedAt: string },
  agentPublicKey: string,
  agentPrivateKey: string
): Promise<VerifiableCredential> {
  const agentDID = createDID(agentPublicKey)

  const subject: FloorAttestationCredentialSubject = {
    id: agentDID,
    floorVersion: attestation.floorVersion,
    principles: attestation.principles,
    extensions: attestation.extensions,
    attestedAt: attestation.attestedAt
  }

  const credential: Omit<VerifiableCredential, 'proof'> = {
    '@context': [...VC_CONTEXT, APS_CONTEXT],
    id: `urn:aps:credential:attestation:${agentPublicKey.slice(0, 16)}:${Date.now()}`,
    type: ['VerifiableCredential', 'FloorAttestationCredential'],
    issuer: agentDID,
    issuanceDate: attestation.attestedAt,
    credentialSubject: subject as unknown as Record<string, unknown>
  }

  const proof = await createProof(credential, agentPrivateKey, agentDID, 'assertionMethod')
  return { ...credential, proof }
}

/**
 * Create a Verifiable Credential for an Action Receipt.
 * Provides non-repudiable proof of agent work.
 */
export async function receiptToVC(
  receipt: ActionReceipt,
  agentPrivateKey: string
): Promise<VerifiableCredential> {
  const agentPublicKey = publicKeyFromPrivate(agentPrivateKey)
  const agentDID = createDID(agentPublicKey)

  const credential: Omit<VerifiableCredential, 'proof'> = {
    '@context': [...VC_CONTEXT, APS_CONTEXT],
    id: `urn:aps:credential:receipt:${receipt.receiptId}`,
    type: ['VerifiableCredential', 'ActionReceiptCredential'],
    issuer: agentDID,
    issuanceDate: receipt.timestamp,
    credentialSubject: {
      id: agentDID,
      receiptId: receipt.receiptId,
      actionType: receipt.action.type,
      target: receipt.action.target,
      scopeUsed: receipt.action.scopeUsed,
      status: receipt.result.status,
      summary: receipt.result.summary,
      delegationChain: receipt.delegationChain
    }
  }

  const proof = await createProof(credential, agentPrivateKey, agentDID, 'assertionMethod')
  return { ...credential, proof }
}

// ── Verifiable Presentations ──

/**
 * Create a Verifiable Presentation from a set of credentials.
 * The holder selectively presents credentials to a verifier.
 */
export async function createPresentation(
  credentials: VerifiableCredential[],
  holderPrivateKey: string,
  holderPublicKey: string,
  options?: { challenge?: string; domain?: string }
): Promise<VerifiablePresentation> {
  const holderDID = createDID(holderPublicKey)

  const presentation: Omit<VerifiablePresentation, 'proof'> = {
    '@context': VC_CONTEXT,
    id: `urn:aps:presentation:${Date.now()}`,
    type: ['VerifiablePresentation'],
    holder: holderDID,
    verifiableCredential: credentials
  }

  const proof = await createProof(
    presentation as unknown as Record<string, unknown>,
    holderPrivateKey,
    holderDID,
    'authentication'
  )

  return { ...presentation, proof }
}

// ── Verification ──

/**
 * Verify a Verifiable Credential's proof.
 * Checks Ed25519 signature against the issuer's public key.
 */
export async function verifyVC(credential: VerifiableCredential): Promise<{
  valid: boolean
  issuerDID: string
  error?: string
}> {
  try {
    const issuerDID = typeof credential.issuer === 'string'
      ? credential.issuer
      : credential.issuer.id

    // Extract public key from the verification method DID
    const vmDID = credential.proof.verificationMethod.split('#')[0]
    const publicKey = publicKeyFromDID(vmDID)

    // Reconstruct the credential without proof for verification
    const { proof, ...credentialWithoutProof } = credential
    const canonical = canonicalize(credentialWithoutProof as unknown as Record<string, unknown>)
    const sigHex = base64urlToHex(proof.proofValue)

    const isValid = await verify(canonical, sigHex, publicKey)

    // Check expiration
    if (credential.expirationDate) {
      const expiry = new Date(credential.expirationDate)
      if (expiry < new Date()) {
        return { valid: false, issuerDID, error: 'Credential has expired' }
      }
    }

    return { valid: isValid, issuerDID, error: isValid ? undefined : 'Invalid signature' }
  } catch (err) {
    return {
      valid: false,
      issuerDID: '',
      error: `Verification failed: ${err instanceof Error ? err.message : String(err)}`
    }
  }
}

/**
 * Verify a Verifiable Presentation and all contained credentials.
 */
export async function verifyPresentation(presentation: VerifiablePresentation): Promise<{
  valid: boolean
  holderDID: string
  credentialResults: Array<{ id: string; valid: boolean; error?: string }>
  error?: string
}> {
  // Verify presentation proof
  const vmDID = presentation.proof.verificationMethod.split('#')[0]
  const publicKey = publicKeyFromDID(vmDID)
  const { proof, ...presentationWithoutProof } = presentation
  const canonical = canonicalize(presentationWithoutProof as unknown as Record<string, unknown>)
  const sigHex = base64urlToHex(proof.proofValue)

  const presentationValid = await verify(canonical, sigHex, publicKey)
  if (!presentationValid) {
    return {
      valid: false,
      holderDID: presentation.holder,
      credentialResults: [],
      error: 'Presentation signature invalid'
    }
  }

  // Verify each credential
  const credentialResults = await Promise.all(
    presentation.verifiableCredential.map(async (vc) => {
      const result = await verifyVC(vc)
      return { id: vc.id, valid: result.valid, error: result.error }
    })
  )

  const allValid = credentialResults.every(r => r.valid)

  return {
    valid: allValid,
    holderDID: presentation.holder,
    credentialResults,
    error: allValid ? undefined : 'One or more credentials failed verification'
  }
}

// ── Proof Helpers ──

async function createProof(
  data: Record<string, unknown> | Omit<VerifiableCredential, 'proof'>,
  privateKey: string,
  did: string,
  purpose: LinkedDataProof['proofPurpose']
): Promise<LinkedDataProof> {
  const canonical = canonicalize(data as Record<string, unknown>)
  const sig = await sign(canonical, privateKey)

  return {
    type: 'Ed25519Signature2020',
    created: new Date().toISOString(),
    verificationMethod: `${did}#key-1`,
    proofPurpose: purpose,
    proofValue: hexToBase64url(sig)
  }
}

// ── Encoding (shared with did.ts but kept local to avoid circular deps) ──

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
