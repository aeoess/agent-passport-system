// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0
// Ed25519 Cryptographic Operations for Agent Passport System
// Uses Node.js crypto for Ed25519 key generation, signing, and verification

import crypto from 'node:crypto'
import type { KeyPair } from '../types/passport.js'
import { isAdmissibleKeyMaterial } from './ed25519-admissibility.js'

function hexToBytes(hex: string): Uint8Array {
  if (!hex || hex.length % 2 !== 0 || !/^[0-9a-fA-F]+$/.test(hex)) {
    throw new Error(`Invalid hex string (length=${hex?.length || 0})`)
  }
  const bytes = new Uint8Array(hex.length / 2)
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.slice(i, i + 2), 16)
  }
  return bytes
}

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('')
}

export function generateKeyPair(): KeyPair {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519', {
    publicKeyEncoding: { type: 'spki', format: 'der' },
    privateKeyEncoding: { type: 'pkcs8', format: 'der' }
  })
  // Extract raw 32-byte keys from DER encoding
  const privHex = bytesToHex(new Uint8Array(privateKey.slice(-32)))
  const pubHex = bytesToHex(new Uint8Array(publicKey.slice(-32)))
  return { privateKey: privHex, publicKey: pubHex }
}

export function sign(message: string, privateKeyHex: string): string {
  // Reconstruct DER-encoded private key
  const privBytes = hexToBytes(privateKeyHex)
  const derPrefix = Buffer.from('302e020100300506032b657004220420', 'hex')
  const derKey = Buffer.concat([derPrefix, Buffer.from(privBytes)])

  const keyObj = crypto.createPrivateKey({ key: derKey, format: 'der', type: 'pkcs8' })
  const sig = crypto.sign(null, Buffer.from(message, 'utf8'), keyObj)
  return bytesToHex(new Uint8Array(sig))
}

/**
 * Verify an Ed25519 signature over the UTF-8 bytes of `message`.
 *
 * The public key and the signature's R must be admissible: the canonical
 * encoding of a point that is not of small order. That is the behaviour on
 * which the two strict implementations in the APS family agree, libsodium in
 * agent-passport-python and ed25519-dalek verify_strict in
 * crates/aps-verifier-core, checked over a 2534 vector corpus that includes
 * the Wycheproof Ed25519 suite. Inadmissible key material is refused here so
 * no artifact verifier downstream can accept it.
 */
export function verify(message: string, signatureHex: string, publicKeyHex: string): boolean {
  // Ed25519 public keys are exactly 32 bytes (64 hex chars) and signatures are
  // exactly 64 bytes (128 hex chars). Reject any other length up front. This
  // closes a key-equivocation gap (a longer public key whose leading 32 bytes
  // are valid must NOT verify, because the fixed DER prefix declares a 32-byte
  // key and trailing bytes would otherwise be ignored), enforces signature
  // length, and bounds work on attacker-supplied input before any hex parsing.
  if (typeof publicKeyHex !== 'string' || publicKeyHex.length !== 64) return false
  if (typeof signatureHex !== 'string' || signatureHex.length !== 128) return false
  try {
    const pubBytes = hexToBytes(publicKeyHex)
    const sigBytes = hexToBytes(signatureHex)

    // Ed25519 admissibility. Node's crypto.verify implements the RFC 8032
    // equation and nothing more, so it accepts a public key or an R that
    // decodes to a small-order point. With the Edwards identity as the public
    // key and R = the identity with S = 0 the equation degenerates and one
    // signature verifies under every message, which proves nothing about the
    // artifact carrying it. See ./ed25519-admissibility.ts.
    if (!isAdmissibleKeyMaterial(pubBytes, sigBytes)) return false

    const derPrefix = Buffer.from('302a300506032b6570032100', 'hex')
    const derKey = Buffer.concat([derPrefix, Buffer.from(pubBytes)])

    const keyObj = crypto.createPublicKey({ key: derKey, format: 'der', type: 'spki' })
    return crypto.verify(null, Buffer.from(message, 'utf8'), keyObj, Buffer.from(sigBytes))
  } catch (err: unknown) {
    // Distinguish input errors from verification failures (F-PX2-003)
    const msg = err instanceof Error ? err.message : String(err)
    if (msg.includes('Invalid key') || msg.includes('asn1') || msg.includes('key length')) {
      console.warn(`[agent-passport] verify(): malformed input — ${JSON.stringify(msg.slice(0, 200))}`)
    }
    return false
  }
}

export function publicKeyFromPrivate(privateKeyHex: string): string {
  const privBytes = hexToBytes(privateKeyHex)
  const derPrefix = Buffer.from('302e020100300506032b657004220420', 'hex')
  const derKey = Buffer.concat([derPrefix, Buffer.from(privBytes)])

  const keyObj = crypto.createPrivateKey({ key: derKey, format: 'der', type: 'pkcs8' })
  const pubKey = crypto.createPublicKey(keyObj)
  const pubDer = pubKey.export({ type: 'spki', format: 'der' })
  return bytesToHex(new Uint8Array(pubDer.slice(-32)))
}
