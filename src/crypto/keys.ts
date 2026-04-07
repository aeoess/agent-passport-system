// Ed25519 Cryptographic Operations for Agent Passport System
// Uses Node.js crypto for Ed25519 key generation, signing, and verification

import crypto from 'node:crypto'
import type { KeyPair } from '../types/passport.js'

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

export function verify(message: string, signatureHex: string, publicKeyHex: string): boolean {
  try {
    const pubBytes = hexToBytes(publicKeyHex)
    const derPrefix = Buffer.from('302a300506032b6570032100', 'hex')
    const derKey = Buffer.concat([derPrefix, Buffer.from(pubBytes)])

    const keyObj = crypto.createPublicKey({ key: derKey, format: 'der', type: 'spki' })
    const sigBytes = hexToBytes(signatureHex)
    return crypto.verify(null, Buffer.from(message, 'utf8'), keyObj, Buffer.from(sigBytes))
  } catch (err: unknown) {
    // Distinguish input errors from verification failures (F-PX2-003)
    const msg = err instanceof Error ? err.message : String(err)
    if (msg.includes('Invalid key') || msg.includes('asn1') || msg.includes('key length')) {
      console.warn(`[agent-passport] verify(): malformed input — ${msg}`)
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
