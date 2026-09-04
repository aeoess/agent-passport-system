// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0
// Agent Passport System — VC Wrapper (Interop Bridge)
// Thin layer over vc.ts that uses did:key identifiers, includes
// passport grade + delegation scope in credentialSubject, and
// connects SPIFFE attestations as VC evidence.
//
// Bridges: did-interop.ts (did:key) + identity-bridge.ts (SPIFFE/OAuth)
//        → vc.ts (W3C Verifiable Credentials)

import { canonicalize, canonicalizeForWrite } from './canonical.js'
import { parseRfc3339 } from './rfc3339.js'
import { sign, verify, publicKeyFromPrivate } from '../crypto/keys.js'
import { toDIDKey } from './did-interop.js'
import { bindVerificationMethod, proofSigningInput, type KeyAuthority } from './vc-proof.js'
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
  /** Integrity AND issuer binding, plus expiry. Not an authorization decision:
   *  the caller allowlists on `issuerDID`. */
  valid: boolean
  /** The issuer the credential claims, returned so the caller can allowlist
   *  it. Empty when the binding failed, because an unbound issuer field names
   *  nobody who has been shown to have signed anything. */
  issuerDID: string
  /** The proof verifies under the key its own verificationMethod names. */
  proofOfPossession: boolean
  /** Whether that key was shown to belong to the claimed issuer. */
  keyAuthority: KeyAuthority
  checks: string[]
}

export interface VPVerifyResult {
  valid: boolean
  /** The holder the presentation claims, on the same terms as issuerDID. */
  holderDID: string
  proofOfPossession: boolean
  keyAuthority: KeyAuthority
  /** The challenge and domain carried in the verified proof. Consuming a
   *  challenge is relying-party state, so the verified value is returned
   *  rather than enforced here. */
  challenge?: string
  domain?: string
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

/** See the note in vc.ts: delegation credentials are emitted with
 *  capabilityDelegation, so both purposes are credential purposes here. */
const CREDENTIAL_PURPOSES: ReadonlySet<string> = new Set(['assertionMethod', 'capabilityDelegation'])

/**
 * Verify a Verifiable Credential's Ed25519 proof.
 *
 * SCOPE OF CLAIM.
 *   Establishes, when `valid` is true: the credential and its proof
 *     configuration are unaltered since signing, the signing key is the one
 *     the DID in `issuer` commits to, the proof was made for a credential
 *     purpose, and the credential has not expired.
 *   Does NOT establish: that the issuer is trusted (allowlist on `issuerDID`),
 *     that the claims are true, that attached evidence was checked — the
 *     `checks` array reports evidence PRESENCE and says so — or that the
 *     credential has not been revoked.
 *
 * The verification key used to come from `proof.verificationMethod` with no
 * relation to `issuer`, and the non-did:key branch took the last colon-
 * separated segment of the identifier as raw key material, so a credential
 * naming a trusted did:key issuer and carrying a did:aps proof over the
 * attacker's own key verified. Both are closed: the method DID must be the
 * issuer DID, and the key must derive from it.
 */
export async function verifyVerifiableCredential(vc: VerifiableCredential): Promise<VCVerifyResult> {
  const checks: string[] = []
  const fail = (over: Partial<VCVerifyResult> = {}): VCVerifyResult => ({
    valid: false, issuerDID: '', proofOfPossession: false, keyAuthority: 'rejected', checks, ...over
  })

  // Check required fields
  if (!vc || !vc['@context'] || !vc.type || !vc.issuer || !vc.credentialSubject || !vc.proof) {
    checks.push('FAIL: missing required VC fields')
    return fail()
  }
  checks.push('PASS: required fields present')

  // Check VC type
  if (!vc.type.includes('VerifiableCredential')) {
    checks.push('FAIL: type array must include VerifiableCredential')
    return fail()
  }
  checks.push('PASS: type includes VerifiableCredential')

  if (vc.proof.type !== 'Ed25519Signature2020') {
    checks.push(`FAIL: unsupported proof type ${String(vc.proof.type)}`)
    return fail()
  }
  if (!CREDENTIAL_PURPOSES.has(vc.proof.proofPurpose)) {
    checks.push(`FAIL: proof purpose ${String(vc.proof.proofPurpose)} is not a credential purpose`)
    return fail()
  }
  checks.push('PASS: proof type and purpose are credential-shaped')

  const issuerDID = typeof vc.issuer === 'string' ? vc.issuer : (vc.issuer as { id: string }).id
  const binding = bindVerificationMethod(issuerDID, vc.proof.verificationMethod)
  if (binding.keyAuthority !== 'verified') {
    checks.push(`FAIL: issuer binding — ${binding.reason}`)
    return fail({ keyAuthority: binding.keyAuthority })
  }
  checks.push('PASS: proof key is the one the issuer DID commits to')

  let valid = true

  // Verify Ed25519 signature over the body plus the proof configuration.
  try {
    const canonical = proofSigningInput(
      vc as unknown as Record<string, unknown>,
      vc.proof as unknown as Record<string, unknown>,
      canonicalize,
    )
    const sigValid = verify(canonical, base64urlToHex(vc.proof.proofValue), binding.publicKey)
    if (sigValid) {
      checks.push('PASS: Ed25519 signature valid')
    } else {
      checks.push('FAIL: Ed25519 signature invalid')
      return fail({ keyAuthority: 'rejected' })
    }
  } catch (err) {
    checks.push(`FAIL: signature verification error — ${err instanceof Error ? err.message : String(err)}`)
    return fail()
  }

  // Check expiration. An expirationDate this verifier cannot read is not an
  // expiry it can honour, so it fails rather than reporting "not expired".
  if (vc.expirationDate) {
    const expiry = parseRfc3339(vc.expirationDate)
    if (!expiry.ok) {
      checks.push(`FAIL: credential has an invalid expirationDate (${expiry.reason})`)
      valid = false
    } else if (expiry.ms < Date.now()) {
      checks.push('FAIL: credential expired')
      valid = false
    } else {
      checks.push('PASS: credential not expired')
    }
  } else {
    checks.push('SKIP: no expirationDate set')
  }

  // Evidence is reported as PRESENT, never as checked. Verifying an
  // infrastructure attestation is the attestation provider's protocol, not
  // this one's, and saying "PASS" about a thing nobody verified is the habit
  // this repair exists to remove.
  const cred = vc as unknown as Record<string, unknown>
  if (Array.isArray(cred.evidence) && cred.evidence.length > 0) {
    checks.push(`PRESENT: ${cred.evidence.length} evidence attachment(s), not verified here`)
  }

  return { valid, issuerDID, proofOfPossession: true, keyAuthority: 'verified', checks }
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
 * Verify a Verifiable Presentation: the presentation proof, then each
 * contained credential.
 *
 * SCOPE OF CLAIM.
 *   Establishes, when `valid` is true: the presentation and its proof
 *     configuration are unaltered since signing; the signing key is the one
 *     the DID in `holder` commits to; the proof was made for authentication;
 *     it carries the challenge and domain the caller expected, when the caller
 *     expected any; and every contained credential passes
 *     verifyVerifiableCredential.
 *   Does NOT establish: that the holder is entitled to present these
 *     credentials. A presentation binds the presenter to the bytes, not the
 *     credentials to the presenter; a holder presenting somebody else's
 *     credential produces a valid presentation of a valid credential, and the
 *     relying party has to compare the credential subject to the holder itself.
 *
 * `challenge` and `domain` are inside the signed bytes as of this change.
 * They used to be attached after signing, so a presentation minted for one
 * verifier could be readdressed to another without invalidating it.
 */
export async function verifyVerifiablePresentation(
  vp: VerifiablePresentation,
  opts?: {
    /** Refuse unless the presentation claims this exact holder. */
    expectedHolder?: string
    /** The nonce this verifier issued. A proof carrying none is refused when
     *  one is expected: a presentation that answers no challenge answers any. */
    expectedChallenge?: string
    /** The domain this verifier expects to be addressed as. */
    expectedDomain?: string
  },
): Promise<VPVerifyResult> {
  const checks: string[] = []
  const holderDID = vp?.holder ?? ''
  const fail = (over: Partial<VPVerifyResult> = {}): VPVerifyResult => ({
    valid: false, holderDID, proofOfPossession: false, keyAuthority: 'rejected',
    credentials: [], checks, ...over
  })

  // Check required fields
  if (!vp || !vp.holder || !vp.proof || !vp.verifiableCredential) {
    checks.push('FAIL: missing required VP fields')
    return fail()
  }
  checks.push('PASS: required VP fields present')

  if (vp.proof.type !== 'Ed25519Signature2020') {
    checks.push(`FAIL: unsupported proof type ${String(vp.proof.type)}`)
    return fail()
  }
  if (vp.proof.proofPurpose !== 'authentication') {
    checks.push(`FAIL: proof purpose ${String(vp.proof.proofPurpose)} is not authentication`)
    return fail()
  }
  if (opts?.expectedHolder !== undefined && holderDID !== opts.expectedHolder) {
    checks.push(`FAIL: holder ${holderDID} is not the expected ${opts.expectedHolder}`)
    return fail()
  }

  const binding = bindVerificationMethod(holderDID, vp.proof.verificationMethod)
  if (binding.keyAuthority !== 'verified') {
    checks.push(`FAIL: holder binding — ${binding.reason}`)
    return fail({ keyAuthority: binding.keyAuthority })
  }
  checks.push('PASS: proof key is the one the holder DID commits to')

  try {
    const canonical = proofSigningInput(
      vp as unknown as Record<string, unknown>,
      vp.proof as unknown as Record<string, unknown>,
      canonicalize,
    )
    const sigValid = verify(canonical, base64urlToHex(vp.proof.proofValue), binding.publicKey)
    if (!sigValid) {
      checks.push('FAIL: presentation signature invalid')
      return fail({ keyAuthority: 'rejected' })
    }
    checks.push('PASS: presentation signature valid')
  } catch (err) {
    checks.push(`FAIL: presentation signature error — ${err instanceof Error ? err.message : String(err)}`)
    return fail()
  }

  // Replay context, compared only after the signature verified, so the values
  // compared are the signed ones.
  const bound = { proofOfPossession: true, keyAuthority: 'verified' as const }
  if (opts?.expectedChallenge !== undefined) {
    if (vp.proof.challenge === undefined) {
      checks.push('FAIL: presentation carries no challenge but one was expected')
      return fail(bound)
    }
    if (vp.proof.challenge !== opts.expectedChallenge) {
      checks.push('FAIL: presentation challenge does not match the expected challenge')
      return fail(bound)
    }
    checks.push('PASS: challenge matches')
  }
  if (opts?.expectedDomain !== undefined) {
    if (vp.proof.domain === undefined) {
      checks.push('FAIL: presentation carries no domain but one was expected')
      return fail(bound)
    }
    if (vp.proof.domain !== opts.expectedDomain) {
      checks.push('FAIL: presentation domain does not match the expected domain')
      return fail(bound)
    }
    checks.push('PASS: domain matches')
  }

  let valid = true
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

  return {
    valid,
    holderDID,
    proofOfPossession: true,
    keyAuthority: 'verified',
    challenge: vp.proof.challenge,
    domain: vp.proof.domain,
    credentials: vp.verifiableCredential,
    checks,
  }
}

// ── Proof Helpers ──

/** Build a proof whose configuration is inside the bytes it signs. See the
 *  twin in vc.ts: challenge and domain used to be attached AFTER signing, so
 *  they could be rewritten to readdress a presentation without invalidating
 *  it. Signer and verifier rebuild the same input and must change together. */
async function createProof(
  data: Record<string, unknown>,
  privateKey: string,
  did: string,
  purpose: LinkedDataProof['proofPurpose'],
  options?: { challenge?: string; domain?: string },
): Promise<LinkedDataProof> {
  const proofConfig: Omit<LinkedDataProof, 'proofValue'> = {
    type: 'Ed25519Signature2020',
    created: new Date().toISOString(),
    verificationMethod: `${did}#key-1`,
    proofPurpose: purpose,
    ...(options?.challenge !== undefined ? { challenge: options.challenge } : {}),
    ...(options?.domain !== undefined ? { domain: options.domain } : {}),
  }

  const canonical = proofSigningInput(
    data,
    proofConfig as unknown as Record<string, unknown>,
    canonicalizeForWrite,
  )
  return { ...proofConfig, proofValue: hexToBase64url(sign(canonical, privateKey)) }
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
