// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0
// Agent Passport System — W3C Verifiable Credentials
// Wraps protocol artifacts as W3C VC Data Model 2.0 credentials.
// Pure translation layer: no changes to core protocol.

import { canonicalize, canonicalizeForWrite } from './canonical.js'
import { parseRfc3339 } from './rfc3339.js'
import { sign, verify, publicKeyFromPrivate } from '../crypto/keys.js'
import { createDID } from './did.js'
import { bindVerificationMethod, proofSigningInput, type KeyAuthority } from './vc-proof.js'
import type { AgentPassport, Delegation, ActionReceipt } from '../types/passport.js'
import type {
  VerifiableCredential, VerifiablePresentation, LinkedDataProof,
  PassportCredentialSubject, DelegationCredentialSubject,
  FloorAttestationCredentialSubject
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
    'authentication',
    options
  )

  return { ...presentation, proof }
}

// ── Verification ──

/** Proof purposes a credential may carry. `capabilityDelegation` is here
 *  because delegationToVC() emits it; anything else is a proof made for a
 *  different job and is refused rather than repurposed. */
const CREDENTIAL_PURPOSES: ReadonlySet<string> = new Set(['assertionMethod', 'capabilityDelegation'])

export interface VerifyVCResult {
  /** Integrity AND identity binding: the credential's bytes verify under a key
   *  the claimed issuer DID commits to. NOT an authorization decision — see
   *  the note on issuerDID. */
  valid: boolean
  /** The issuer the credential claims, echoed back so the relying party can
   *  allowlist it. Meaningful only when `valid` is true; before the binding
   *  check this field named an issuer nobody had shown had signed anything. */
  issuerDID: string
  /** The proof verifies under the key its own verificationMethod names. True
   *  on some rejected results: a forged credential can be internally
   *  consistent and still not be the issuer's. */
  proofOfPossession: boolean
  /** Whether that key was shown to belong to the claimed issuer. */
  keyAuthority: KeyAuthority
  error?: string
}

/**
 * Verify a Verifiable Credential.
 *
 * SCOPE OF CLAIM.
 *   Establishes, when `valid` is true: the credential's bytes and its proof
 *     configuration are unaltered since signing, and the signing key is the
 *     one the DID in `issuer` commits to; the proof was made for a credential
 *     purpose; and the credential has not expired.
 *   Does NOT establish: that the issuer is one this relying party trusts —
 *     that is an allowlist decision, and `issuerDID` is returned so the caller
 *     can make it; that the claims inside are true; or that the credential has
 *     not been revoked.
 *
 * The key is no longer taken from `proof.verificationMethod` on its own. That
 * field is part of the document the presenter wrote, so verifying under it
 * established only that whoever assembled the credential held some key. A
 * credential naming a trusted issuer and carrying an attacker's proof
 * verified, and returned the trusted issuer's DID.
 *
 * Only self-certifying DID methods can be bound without resolving a DID
 * document, and this surface resolves none. A credential whose issuer uses any
 * other method now returns keyAuthority 'unresolved' and `valid: false`.
 */
export async function verifyVC(
  credential: VerifiableCredential,
  opts?: {
    /** Refuse unless the credential claims this exact issuer. Optional: the
     *  binding is checked either way, and `issuerDID` is returned for callers
     *  that allowlist after the fact. */
    expectedIssuer?: string
  }
): Promise<VerifyVCResult> {
  const fail = (error: string, over: Partial<VerifyVCResult> = {}): VerifyVCResult => ({
    valid: false, issuerDID: '', proofOfPossession: false, keyAuthority: 'rejected', error, ...over
  })

  try {
    const claimedIssuer = typeof credential.issuer === 'string'
      ? credential.issuer
      : credential.issuer?.id
    const proof = credential.proof

    if (!proof || typeof proof !== 'object') return fail('Credential carries no proof')
    if (proof.type !== 'Ed25519Signature2020') {
      return fail(`Unsupported proof type ${String(proof.type)}`)
    }
    if (!CREDENTIAL_PURPOSES.has(proof.proofPurpose)) {
      return fail(`Proof purpose ${String(proof.proofPurpose)} is not a credential purpose`)
    }
    if (opts?.expectedIssuer !== undefined && claimedIssuer !== opts.expectedIssuer) {
      return fail(`Credential issuer ${String(claimedIssuer)} is not the expected ${opts.expectedIssuer}`)
    }

    const binding = bindVerificationMethod(claimedIssuer, proof.verificationMethod)
    if (binding.keyAuthority !== 'verified') {
      return fail(`Issuer binding failed: ${binding.reason}`, { keyAuthority: binding.keyAuthority })
    }

    const canonical = proofSigningInput(
      credential as unknown as Record<string, unknown>,
      proof as unknown as Record<string, unknown>,
      canonicalize
    )
    const proofOfPossession = verify(canonical, base64urlToHex(proof.proofValue), binding.publicKey)
    if (!proofOfPossession) {
      return fail('Invalid signature', { keyAuthority: 'rejected' })
    }

    const issuerDID = claimedIssuer as string

    // Check expiration. An expirationDate this verifier cannot read is not an
    // expiry it can honour, so it fails the credential instead of passing it.
    if (credential.expirationDate) {
      const expiry = parseRfc3339(credential.expirationDate)
      if (!expiry.ok) {
        return {
          valid: false, issuerDID, proofOfPossession: true, keyAuthority: 'verified',
          error: `Credential has an invalid expirationDate (${expiry.reason})`
        }
      }
      if (expiry.ms < Date.now()) {
        return {
          valid: false, issuerDID, proofOfPossession: true, keyAuthority: 'verified',
          error: 'Credential has expired'
        }
      }
    }

    return { valid: true, issuerDID, proofOfPossession: true, keyAuthority: 'verified' }
  } catch (err) {
    return fail(`Verification failed: ${err instanceof Error ? err.message : String(err)}`)
  }
}

export interface VerifyPresentationResult {
  valid: boolean
  /** The holder the presentation claims, returned for allowlisting on the
   *  same terms as issuerDID above. */
  holderDID: string
  proofOfPossession: boolean
  keyAuthority: KeyAuthority
  /** The challenge carried in the verified proof, when the proof was accepted.
   *  Consuming it — refusing a nonce already spent — is relying-party state
   *  and does not belong in a stateless verifier, so it is handed back rather
   *  than enforced here. */
  challenge?: string
  /** The domain carried in the verified proof, on the same terms. */
  domain?: string
  credentialResults: Array<{ id: string; valid: boolean; error?: string }>
  error?: string
}

/**
 * Verify a Verifiable Presentation and every credential it carries.
 *
 * SCOPE OF CLAIM.
 *   Establishes, when `valid` is true: the presentation and its proof
 *     configuration are unaltered since signing; the signing key is the one
 *     the DID in `holder` commits to; the proof was made for authentication;
 *     it carries the challenge and domain the caller expected, when the caller
 *     expected any; and every contained credential passes verifyVC.
 *   Does NOT establish: that the holder is entitled to present these
 *     credentials — a presentation binds the presenter to the bytes, not the
 *     credentials to the presenter; that the challenge has not already been
 *     spent, which is the caller's to track; or that the holder is trusted.
 *
 * The challenge and domain are now inside the signed bytes. They used to be
 * attached to the proof after signing, so a presentation minted for one
 * verifier could be readdressed to another without invalidating it.
 */
export async function verifyPresentation(
  presentation: VerifiablePresentation,
  opts?: {
    /** Refuse unless the presentation claims this exact holder. */
    expectedHolder?: string
    /** The nonce this verifier issued. When supplied, the proof must carry it;
     *  a proof carrying none is refused, because a presentation that answers
     *  no challenge answers any challenge. */
    expectedChallenge?: string
    /** The domain this verifier expects to be addressed as, on the same terms. */
    expectedDomain?: string
  }
): Promise<VerifyPresentationResult> {
  const claimedHolder = presentation?.holder ?? ''
  // The holder is echoed only once the binding establishes it. Handing back a
  // trusted DID from a failed verification is how a caller allowlists an
  // attacker, which is exactly what the unbound verifier did.
  const fail = (error: string, over: Partial<VerifyPresentationResult> = {}): VerifyPresentationResult => ({
    valid: false, holderDID: '', proofOfPossession: false, keyAuthority: 'rejected',
    credentialResults: [], error, ...over
  })

  const proof = presentation?.proof
  if (!proof || typeof proof !== 'object') return fail('Presentation carries no proof')
  if (proof.type !== 'Ed25519Signature2020') {
    return fail(`Unsupported proof type ${String(proof.type)}`)
  }
  if (proof.proofPurpose !== 'authentication') {
    return fail(`Proof purpose ${String(proof.proofPurpose)} is not authentication`)
  }
  if (opts?.expectedHolder !== undefined && claimedHolder !== opts.expectedHolder) {
    return fail(`Presentation holder ${claimedHolder} is not the expected ${opts.expectedHolder}`)
  }

  const binding = bindVerificationMethod(claimedHolder, proof.verificationMethod)
  if (binding.keyAuthority !== 'verified') {
    return fail(`Holder binding failed: ${binding.reason}`, { keyAuthority: binding.keyAuthority })
  }

  let proofOfPossession: boolean
  try {
    const canonical = proofSigningInput(
      presentation as unknown as Record<string, unknown>,
      proof as unknown as Record<string, unknown>,
      canonicalize
    )
    proofOfPossession = verify(canonical, base64urlToHex(proof.proofValue), binding.publicKey)
  } catch (err) {
    return fail(`Presentation signature error: ${err instanceof Error ? err.message : String(err)}`)
  }
  if (!proofOfPossession) {
    return fail('Presentation signature invalid', { keyAuthority: 'rejected' })
  }

  // Replay context. Compared only after the signature is verified, so the
  // values compared are the signed ones.
  const bound = { proofOfPossession: true, keyAuthority: 'verified' as const, holderDID: claimedHolder }
  if (opts?.expectedChallenge !== undefined) {
    if (proof.challenge === undefined) {
      return fail('Presentation carries no challenge but one was expected', bound)
    }
    if (proof.challenge !== opts.expectedChallenge) {
      return fail('Presentation challenge does not match the expected challenge', bound)
    }
  }
  if (opts?.expectedDomain !== undefined) {
    if (proof.domain === undefined) {
      return fail('Presentation carries no domain but one was expected', bound)
    }
    if (proof.domain !== opts.expectedDomain) {
      return fail('Presentation domain does not match the expected domain', bound)
    }
  }

  const credentialResults = await Promise.all(
    (presentation.verifiableCredential ?? []).map(async (vc) => {
      const result = await verifyVC(vc)
      return { id: vc.id, valid: result.valid, error: result.error }
    })
  )
  const allValid = credentialResults.every(r => r.valid)

  return {
    valid: allValid,
    holderDID: claimedHolder,
    proofOfPossession: true,
    keyAuthority: 'verified',
    challenge: proof.challenge,
    domain: proof.domain,
    credentialResults,
    error: allValid ? undefined : 'One or more credentials failed verification'
  }
}

// ── Proof Helpers ──

/** Build a proof whose configuration is inside the bytes it signs.
 *
 *  The signed input is the document with its `proof` member set to this
 *  proof's configuration, which is everything except `proofValue`. So
 *  `created`, `proofPurpose`, `verificationMethod`, `challenge` and `domain`
 *  are all covered. Previously only the document body was signed and the proof
 *  was attached afterwards, which left every one of those fields rewritable
 *  without invalidating the signature. verifyVC and verifyPresentation rebuild
 *  exactly this input; the two must change together or nothing verifies. */
async function createProof(
  data: Record<string, unknown> | Omit<VerifiableCredential, 'proof'>,
  privateKey: string,
  did: string,
  purpose: LinkedDataProof['proofPurpose'],
  options?: { challenge?: string; domain?: string }
): Promise<LinkedDataProof> {
  const proofConfig: Omit<LinkedDataProof, 'proofValue'> = {
    type: 'Ed25519Signature2020',
    created: new Date().toISOString(),
    verificationMethod: `${did}#key-1`,
    proofPurpose: purpose,
    ...(options?.challenge !== undefined ? { challenge: options.challenge } : {}),
    ...(options?.domain !== undefined ? { domain: options.domain } : {})
  }

  const canonical = proofSigningInput(
    data as Record<string, unknown>,
    proofConfig as unknown as Record<string, unknown>,
    canonicalizeForWrite
  )
  const sig = await sign(canonical, privateKey)

  return { ...proofConfig, proofValue: hexToBase64url(sig) }
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
