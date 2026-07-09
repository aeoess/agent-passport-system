// Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
/**
 * @fileoverview EXPERIMENTAL, ISOLATED. BBS selective-disclosure scope
 * credentials over BLS12-381.
 *
 * ============================ PROOF BOX ============================
 * Specified, tested, validated against the library's draft-05 behavior.
 * This is NOT core-reviewed cryptography this round; the crypto-review
 * burden is outstanding.
 *
 * PROVES: A derived disclosure proof shows the holder possesses a credential,
 *   signed by the named public key, that asserts the disclosed scope subset,
 *   WITHOUT revealing the undisclosed scopes or the original signature. The
 *   proof is bound to a verifier-supplied presentation header to resist replay.
 *
 * DOES NOT PROVE:
 *   - That the undisclosed scopes are narrow or harmless. Hidden scopes could
 *     be broad. Absence of disclosure is not evidence of limited authority.
 *   - That the signer was entitled to assert any of these scopes. This is a
 *     possession proof over a signature, not an authorization decision.
 *   - Anything about freshness or revocation. The credential carries no
 *     validity window here; bind those out of band.
 *   - Truth of the scope strings. The credential asserts a signed claim, not a
 *     fact about the world (verbal confession, not a brain scan).
 *   - Production-grade security. Constants track an IETF draft, not an RFC, and
 *     this module has not had an independent cryptographic review.
 * ==================================================================
 */

import {
  API_ID_BBS_SHA,
  API_ID_BBS_SHAKE,
  keyGen,
  messages_to_scalars,
  prepareGenerators,
  proofGen,
  proofVerify,
  publicFromPrivate,
  sign,
  verify,
} from '@grottonetworking/bbs-signatures'

import type {
  BbsKeyPair,
  Ciphersuite,
  ScopeCredential,
  ScopeDisclosureProof,
  ScopeOfClaim,
} from './types.js'

/** Default domain-separation header bound into issued credentials. */
const DEFAULT_HEADER = new TextEncoder().encode('aps:bbs-scope-credential:v0')

const enc = new TextEncoder()

function apiIdFor(ciphersuite: Ciphersuite): string {
  return ciphersuite === 'SHA-256' ? API_ID_BBS_SHA : API_ID_BBS_SHAKE
}

function scopesToOctets(scopes: string[]): Uint8Array[] {
  return scopes.map((s) => enc.encode(s))
}

/** Default honest scope-of-claim for an issued scope credential. */
export function defaultCredentialScope(): ScopeOfClaim {
  return {
    asserts:
      'The signer asserts this ordered set of scope strings under a single BBS signature.',
    does_not_assert: [
      'That the signer was authorized to grant these scopes.',
      'That the scope strings are true statements about the world.',
      'Any freshness, expiry, or revocation status.',
      'Independent review of the underlying cryptography.',
    ],
    capture_mode: 'self_attested',
    completeness: 'complete',
    self_attested: true,
  }
}

/** Default honest scope-of-claim for a derived disclosure proof. */
export function defaultDisclosureScope(): ScopeOfClaim {
  return {
    asserts:
      'The holder possesses a credential, signed by the named key, asserting the disclosed scope subset.',
    does_not_assert: [
      'That the undisclosed scopes are narrow or harmless.',
      'That the signer was authorized to grant any scope.',
      'Freshness, expiry, or revocation of the underlying credential.',
      'Independent review of the underlying cryptography.',
    ],
    capture_mode: 'self_attested',
    completeness: 'partial',
    self_attested: true,
  }
}

/**
 * Generate a BBS key pair over BLS12-381.
 *
 * @param keyMaterial - At least 32 bytes of entropy. In production this MUST
 *   come from a CSPRNG. Callers may pass fixed material for test reproduction.
 * @param ciphersuite - SHA-256 (default) or SHAKE-256.
 */
export async function generateKeyPair(
  keyMaterial: Uint8Array,
  ciphersuite: Ciphersuite = 'SHA-256',
  keyInfo: Uint8Array = new Uint8Array()
): Promise<BbsKeyPair> {
  if (keyMaterial.length < 32) {
    throw new RangeError(
      'generateKeyPair: keyMaterial must be at least 32 bytes'
    )
  }
  const api_id = apiIdFor(ciphersuite)
  const secretKey = await keyGen(keyMaterial, keyInfo, '', api_id)
  const publicKey = publicFromPrivate(secretKey)
  return { secretKey, publicKey }
}

/**
 * Issue a scope credential: sign an ordered list of scope strings into one
 * fixed-size (80-byte) BBS signature.
 *
 * @param keyPair - Issuer BBS key pair.
 * @param scopes - Ordered scope strings. Order is load-bearing for disclosure.
 * @param ciphersuite - Must match the key pair's ciphersuite.
 * @param header - Optional domain-separation header. A default is used if
 *   omitted; the same header is required at disclosure and verification.
 */
export async function issueScopeCredential(
  keyPair: BbsKeyPair,
  scopes: string[],
  ciphersuite: Ciphersuite = 'SHA-256',
  header: Uint8Array = DEFAULT_HEADER
): Promise<ScopeCredential> {
  if (scopes.length === 0) {
    throw new RangeError('issueScopeCredential: scopes must be non-empty')
  }
  const api_id = apiIdFor(ciphersuite)
  const msgScalars = await messages_to_scalars(scopesToOctets(scopes), api_id)
  const generators = await prepareGenerators(msgScalars.length, api_id)
  const signature = await sign(
    keyPair.secretKey,
    keyPair.publicKey,
    header,
    msgScalars,
    generators,
    api_id
  )
  return {
    publicKey: keyPair.publicKey,
    header,
    scopes: [...scopes],
    signature,
    ciphersuite,
    scopeOfClaim: defaultCredentialScope(),
  }
}

/**
 * Validate that a scope credential's signature covers its scope vector.
 * Returns true when the signature is valid for the full ordered vector.
 */
export async function verifyScopeCredential(
  credential: ScopeCredential
): Promise<boolean> {
  const api_id = apiIdFor(credential.ciphersuite)
  const msgScalars = await messages_to_scalars(
    scopesToOctets(credential.scopes),
    api_id
  )
  const generators = await prepareGenerators(msgScalars.length, api_id)
  return verify(
    credential.publicKey,
    credential.signature,
    credential.header,
    msgScalars,
    generators,
    api_id
  )
}

/**
 * Derive a selective-disclosure proof that reveals only the named subset of
 * scopes. The undisclosed scopes and the original signature stay hidden.
 *
 * @param credential - The issued credential to present from.
 * @param disclosedScopes - The subset of scope strings to reveal. Each MUST
 *   appear in the credential. Revealing none or all are both permitted.
 * @param presentationHeader - Verifier-supplied challenge bound into the proof
 *   to prevent replay. Use a fresh value per presentation.
 * @param randScalars - Optional deterministic scalar source. FOR TEST VECTOR
 *   REPRODUCTION ONLY. Never supply fixed randomness in production; omit it so
 *   a CSPRNG is used.
 */
export async function deriveDisclosureProof(
  credential: ScopeCredential,
  disclosedScopes: string[],
  presentationHeader: Uint8Array,
  randScalars?: (count: number) => Promise<bigint[]> | bigint[]
): Promise<ScopeDisclosureProof> {
  const api_id = apiIdFor(credential.ciphersuite)

  // Resolve each disclosed scope to its index in the original ordered vector.
  // Reject any scope that is not present, and reject duplicate disclosures.
  const remaining = credential.scopes.map((s, i) => ({ s, i }))
  const disclosedIndexes: number[] = []
  for (const wanted of disclosedScopes) {
    const hit = remaining.findIndex((entry) => entry.s === wanted)
    if (hit === -1) {
      throw new RangeError(
        'deriveDisclosureProof: disclosed scope not present in credential (or already used): ' +
          wanted
      )
    }
    disclosedIndexes.push(remaining[hit].i)
    remaining.splice(hit, 1)
  }
  disclosedIndexes.sort((a, b) => a - b)

  const allScalars = await messages_to_scalars(
    scopesToOctets(credential.scopes),
    api_id
  )
  const generators = await prepareGenerators(allScalars.length, api_id)

  const proof = await proofGen(
    credential.publicKey,
    credential.signature,
    credential.header,
    presentationHeader,
    allScalars,
    disclosedIndexes,
    generators,
    api_id,
    randScalars
  )

  return {
    publicKey: credential.publicKey,
    header: credential.header,
    presentationHeader,
    disclosedScopes: disclosedIndexes.map((i) => credential.scopes[i]),
    disclosedIndexes,
    proof,
    totalScopes: credential.scopes.length,
    ciphersuite: credential.ciphersuite,
    scopeOfClaim: defaultDisclosureScope(),
  }
}

/**
 * Verify a selective-disclosure proof against the signer public key and the
 * presentation context. Returns true when the proof is valid for the disclosed
 * subset. A tampered proof, a mismatched presentation header, or a wrong
 * disclosed value all return false.
 */
export async function verifyDisclosureProof(
  proof: ScopeDisclosureProof
): Promise<boolean> {
  const api_id = apiIdFor(proof.ciphersuite)
  if (proof.disclosedScopes.length !== proof.disclosedIndexes.length) {
    return false
  }
  const disclosedScalars = await messages_to_scalars(
    scopesToOctets(proof.disclosedScopes),
    api_id
  )
  // Generators must be sized to the FULL original vector, not the subset.
  const generators = await prepareGenerators(proof.totalScopes, api_id)
  try {
    return await proofVerify(
      proof.publicKey,
      proof.proof,
      proof.header,
      proof.presentationHeader,
      disclosedScalars,
      proof.disclosedIndexes,
      generators,
      api_id
    )
  } catch {
    // Malformed proof bytes are treated as a verification failure, not a throw.
    return false
  }
}
