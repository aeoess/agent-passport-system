// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// ══════════════════════════════════════════════════════════════════
// IPR — envelope construction (createInstructionProvenanceReceipt)
// ══════════════════════════════════════════════════════════════════
// Tier-locked to 'self-asserted' in v0.2 per spec §4.1. Throws on attempts
// to construct 'witnessed' or 'verified' envelopes (reserved for v0.3+).
// ══════════════════════════════════════════════════════════════════

import { createPrivateKey, sign as cryptoSign } from 'node:crypto'
import {
  canonicalizeEnvelope,
  canonicalizePath,
  computeContextRoot,
  sha256Hex,
  sortInstructionFiles,
} from './canonicalize.js'
import type {
  CreateIPRInput,
  InstructionFile,
  InstructionProvenanceReceipt,
} from './types.js'

const PKCS8_ED25519_PREFIX = Buffer.from('302e020100300506032b657004220420', 'hex')

/** Typed error for IPR construction failures. */
export class IPRConstructionError extends Error {
  constructor(public readonly code: string, message: string) {
    super(`${code}: ${message}`)
    this.name = 'IPRConstructionError'
  }
}

/**
 * Build, sign, and return a complete InstructionProvenanceReceipt envelope.
 * Performs all v0.2 invariants:
 *   - tier locked to 'self-asserted'
 *   - discovery_patterns non-empty
 *   - every instruction_files[].path canonicalized
 *   - instruction_files sorted in canonical order
 *   - context_root derived from sorted files
 *   - receipt_id = sha256(canonical envelope bytes)
 *   - signature = Ed25519 over canonical envelope bytes
 */
export function createInstructionProvenanceReceipt(
  input: CreateIPRInput,
): InstructionProvenanceReceipt {
  // Tier lock — v0.2 only emits 'self-asserted'.
  if (input.attestation_tier !== undefined && input.attestation_tier !== 'self-asserted') {
    throw new IPRConstructionError(
      'TIER_RESERVED',
      `attestation_tier '${String(input.attestation_tier)}' reserved for v0.3+; v0.2 only emits 'self-asserted'`,
    )
  }

  if (!Array.isArray(input.discovery_patterns) || input.discovery_patterns.length === 0) {
    throw new IPRConstructionError('EMPTY_PATTERNS', 'discovery_patterns must be a non-empty array')
  }

  if (!input.working_root.startsWith('/')) {
    throw new IPRConstructionError('WORKING_ROOT_NOT_ABSOLUTE', `working_root must be absolute POSIX: ${input.working_root}`)
  }

  if (!/^[0-9a-f]{64}$/.test(input.delegation_chain_root)) {
    throw new IPRConstructionError('BAD_DELEGATION_ROOT', 'delegation_chain_root must be 64-char lowercase hex')
  }
  if (!/^[0-9a-f]{64}$/.test(input.publicKeyHex)) {
    throw new IPRConstructionError('BAD_PUBLIC_KEY', 'publicKeyHex must be 64-char lowercase hex')
  }
  if (!/^[0-9a-f]{64}$/.test(input.privateKeyHex)) {
    throw new IPRConstructionError('BAD_PRIVATE_KEY', 'privateKeyHex must be 64-char lowercase hex (Ed25519 seed)')
  }

  // Canonicalize each path; rejects symlink dereferencing, traversal, etc.
  const canonicalFiles: InstructionFile[] = input.instruction_files.map(f => ({
    ...f,
    path: canonicalizePath(f.path, {
      workingRoot: input.working_root,
      filesystemMode: input.filesystem_mode,
    }),
  }))

  // Validate digest format on every file.
  for (const f of canonicalFiles) {
    if (!/^[0-9a-f]{64}$/.test(f.digest)) {
      throw new IPRConstructionError('BAD_DIGEST', `instruction_files entry has malformed digest: ${f.path}`)
    }
    if (f.is_symlink && !f.symlink_target) {
      throw new IPRConstructionError(
        'SYMLINK_MISSING_TARGET',
        `instruction_files entry is_symlink=true but symlink_target is missing: ${f.path}`,
      )
    }
  }

  const sortedFiles = sortInstructionFiles(canonicalFiles)
  const contextRoot = computeContextRoot(sortedFiles)
  const issuedAt = input.issued_at ?? new Date().toISOString()
  const signingKeyId = `ed25519:${input.publicKeyHex.slice(0, 16)}`

  // Build the unsigned envelope (signature + receipt_id absent).
  const unsigned: Omit<InstructionProvenanceReceipt, 'signature' | 'receipt_id'> = {
    delegation_chain_root: input.delegation_chain_root,
    agent_did: input.agent_did,
    discovery_patterns: input.discovery_patterns,
    working_root: input.working_root,
    filesystem_mode: input.filesystem_mode,
    instruction_files: sortedFiles,
    context_root: contextRoot,
    attestation_tier: 'self-asserted',
    recompute_at_action: input.recompute_at_action ?? false,
    issued_at: issuedAt,
    ...(input.expires_at !== undefined ? { expires_at: input.expires_at } : {}),
    bound_to: input.bound_to,
    signing_key_id: signingKeyId,
  }

  const canonicalBytes = canonicalizeEnvelope(unsigned)
  const receiptId = sha256Hex(canonicalBytes)
  const signatureHex = signEd25519(canonicalBytes, input.privateKeyHex)

  return {
    receipt_id: receiptId,
    ...unsigned,
    signature: signatureHex,
  }
}

/** Ed25519 sign using the same PKCS8-prefix construction as the bilateral
 *  fixture generator. Returns hex (128 chars). */
export function signEd25519(message: string | Uint8Array, privateKeyHex: string): string {
  const seed = Buffer.from(privateKeyHex, 'hex')
  const derKey = Buffer.concat([PKCS8_ED25519_PREFIX, seed])
  const keyObj = createPrivateKey({ key: derKey, format: 'der', type: 'pkcs8' })
  const msg = typeof message === 'string' ? Buffer.from(message, 'utf8') : Buffer.from(message)
  const sig = cryptoSign(null, msg, keyObj)
  return Buffer.from(sig).toString('hex')
}
