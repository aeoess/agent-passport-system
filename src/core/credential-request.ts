// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0
// Agent Passport System — Credential Request Protocol
// Selective disclosure: verifier requests specific claims,
// agent presents a VC containing only those claims.

import { canonicalizeForWrite } from './canonical.js'
import { proofSigningInput } from './vc-proof.js'
import { verifyVerifiablePresentation } from './vc-wrapper.js'
import { sign, publicKeyFromPrivate } from '../crypto/keys.js'
import { toDIDKey } from './did-interop.js'
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
 * Verify a credential response and extract the requested claims.
 *
 * SCOPE OF CLAIM.
 *   Establishes, when `valid` is true: everything
 *     {@link verifyVerifiablePresentation} establishes — presentation and
 *     credential integrity, holder and issuer binding, proof purpose, expiry,
 *     and that the response answers the challenge and domain the caller
 *     expected.
 *   Does NOT establish: that the challenge has not already been spent, which
 *     is the verifier's own state to keep; that the holder is entitled to
 *     present these credentials; or that the extracted claims are true.
 *
 * The verification is delegated rather than repeated. This module carried its
 * own copy of the presentation and credential checks, with the same two
 * defects: the verification key came from the proof rather than from the
 * claimed issuer or holder, and the challenge it compared was outside the
 * signed bytes, so the replay protection this function's own header advertised
 * was defeated by rewriting the field it compared. One implementation cannot
 * drift from itself.
 *
 * `expectedChallenge` stays optional in the signature and is required in
 * effect for replay protection: omitting it verifies the response but compares
 * no nonce, and the result says so in `checks`.
 */
export async function verifyCredentialResponse(
  vp: VerifiablePresentation,
  expectedChallenge?: string,
  expectedDomain?: string,
): Promise<CredentialResponseResult> {
  const presentation = await verifyVerifiablePresentation(vp, {
    expectedChallenge,
    expectedDomain,
  })
  const checks = [...presentation.checks]
  if (expectedChallenge === undefined) {
    checks.push('SKIP: no expected challenge supplied, so no replay check was made')
  }

  if (!presentation.valid) {
    return { valid: false, claims: {}, checks }
  }

  // Claims are extracted only from a response that verified end to end.
  const claims: Record<string, unknown> = {}
  for (const vc of presentation.credentials) {
    const subject = vc.credentialSubject as Record<string, unknown>
    for (const [key, value] of Object.entries(subject)) {
      if (key !== 'id' && value !== undefined) {
        claims[key] = value
      }
    }
  }

  return { valid: true, claims, checks }
}

// ── Proof Helpers ──

import crypto from 'node:crypto'

/** Build a proof whose configuration is inside the bytes it signs, matching
 *  the twins in vc.ts and vc-wrapper.ts. The challenge this module puts on a
 *  response used to be attached after signing, which is what made the replay
 *  check in verifyCredentialResponse defeatable by rewriting it. */
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


function hexToBase64url(hex: string): string {
  const bytes = hexToBytes(hex)
  const base64 = Buffer.from(bytes).toString('base64')
  return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

