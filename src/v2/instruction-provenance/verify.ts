// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// ══════════════════════════════════════════════════════════════════
// IPR — verification end-to-end (§6)
// ══════════════════════════════════════════════════════════════════
// Pipeline order matches spec §6.1 → §6.5. Hard reject early; do not
// silently downgrade. Returns aggregate { valid, errors[], tier, contextRoot }.
//
// §6.5 action-time recompute (verifyActionTimeContextRoot) is a separate
// helper because it needs the action-receipt's freshly recomputed root,
// which is not part of the IPR envelope itself.
// ══════════════════════════════════════════════════════════════════

import { createPublicKey, verify as cryptoVerify } from 'node:crypto'
import { existsSync, readdirSync, statSync } from 'node:fs'
import { join, relative, resolve } from 'node:path'
import {
  IPRPathError,
  canonicalizeEnvelope,
  canonicalizePath,
  computeContextRoot,
  sha256Hex,
} from './canonicalize.js'
import type {
  ActionTimeContextRootInput,
  AttestationTier,
  InstructionFile,
  VerificationResult,
  VerifyIPRInput,
} from './types.js'

const SPKI_ED25519_PREFIX = Buffer.from('302a300506032b6570032100', 'hex')

const VALID_TIERS: ReadonlySet<AttestationTier> = new Set(['self-asserted', 'witnessed', 'verified'])
const V0_2_PERMITTED_TIER: AttestationTier = 'self-asserted'

/**
 * Verify an InstructionProvenanceReceipt envelope per spec §6.
 *
 * Pipeline:
 *   §6.1 schema + signature
 *   §6.2 delegation linkage (signature key matches signing_key_id)
 *   §6.3 path canonicalization, sort order, context_root, exhaustiveness
 *   §6.4 issued_at + expires_at + bound_to consistency
 *
 * Filesystem-side checks (§6.3 step 10/11 cross-walk vs disk) only run
 * when `filesystemCheck: true` AND `working_root` exists on this host.
 */
export function verifyInstructionProvenanceReceipt(input: VerifyIPRInput): VerificationResult {
  const errors: string[] = []
  const env = input.envelope
  const tier = env.attestation_tier

  // §6.1 — schema-level checks (subset; full schema is in spec §4.2)
  if (!env || typeof env !== 'object') {
    errors.push('envelope is not an object')
    return { valid: false, errors }
  }
  if (!VALID_TIERS.has(tier)) {
    errors.push(`attestation_tier must be one of self-asserted | witnessed | verified, got '${tier}'`)
  }
  if (tier !== V0_2_PERMITTED_TIER) {
    errors.push(`attestation_tier reserved for v0.3+, v0.2 only accepts self-asserted (got '${tier}')`)
  }
  if (typeof env.signing_key_id !== 'string' || !/^ed25519:[0-9a-f]{16}$/.test(env.signing_key_id)) {
    errors.push(`signing_key_id must match ^ed25519:[0-9a-f]{16}$ (got '${env.signing_key_id}')`)
  }
  if (typeof env.signature !== 'string' || !/^[0-9a-f]{128}$/.test(env.signature)) {
    errors.push('signature must be 128-char lowercase hex')
  }
  if (typeof env.receipt_id !== 'string' || !/^[0-9a-f]{64}$/.test(env.receipt_id)) {
    errors.push('receipt_id must be 64-char lowercase hex')
  }
  if (typeof env.context_root !== 'string' || !/^[0-9a-f]{64}$/.test(env.context_root)) {
    errors.push('context_root must be 64-char lowercase hex')
  }
  if (typeof env.delegation_chain_root !== 'string' || !/^[0-9a-f]{64}$/.test(env.delegation_chain_root)) {
    errors.push('delegation_chain_root must be 64-char lowercase hex')
  }
  if (!Array.isArray(env.discovery_patterns) || env.discovery_patterns.length === 0) {
    errors.push('discovery_patterns must be a non-empty array')
  }
  if (typeof env.working_root !== 'string' || !env.working_root.startsWith('/')) {
    errors.push('working_root must be absolute POSIX')
  }

  if (errors.length > 0) return { valid: false, errors, tier }

  // §6.1 step 3 — recompute receipt_id from canonical bytes
  const canonical = canonicalizeEnvelope(env)
  const expectedReceiptId = sha256Hex(canonical)
  if (env.receipt_id !== expectedReceiptId) {
    errors.push(`receipt_id mismatch (expected ${expectedReceiptId}, got ${env.receipt_id})`)
    return { valid: false, errors, tier }
  }

  // §6.1 step 4 — Ed25519 signature
  const sigOk = verifyEd25519(canonical, env.signature, input.publicKeyHex)
  if (!sigOk) {
    errors.push('Ed25519 signature verification failed')
    return { valid: false, errors, tier }
  }

  // §6.2 step 6 — signing_key_id must match the public key fingerprint
  const expectedKid = `ed25519:${input.publicKeyHex.slice(0, 16)}`
  if (env.signing_key_id !== expectedKid) {
    errors.push(`signing_key_id ${env.signing_key_id} does not match provided publicKeyHex fingerprint ${expectedKid}`)
    return { valid: false, errors, tier }
  }

  // §6.3 step 7-9 — path canonicalization + sort order + context_root
  for (const f of env.instruction_files) {
    let canon: string
    try {
      canon = canonicalizePath(f.path, {
        workingRoot: env.working_root,
        filesystemMode: env.filesystem_mode,
      })
    } catch (e) {
      const msg = e instanceof IPRPathError ? e.message : (e as Error).message
      errors.push(`instruction_files[${f.path}] path canonicalization failed: ${msg}`)
      continue
    }
    if (canon !== f.path) {
      errors.push(`instruction_files[${f.path}] path is not in canonical form (expected ${canon})`)
    }
  }

  if (!isSortedByPath(env.instruction_files)) {
    errors.push('instruction_files is not sorted by path (canonical lexicographic)')
  }

  const expectedContextRoot = computeContextRoot(env.instruction_files)
  if (env.context_root !== expectedContextRoot) {
    errors.push(`context_root mismatch (expected ${expectedContextRoot}, got ${env.context_root})`)
  }

  // §6.3 step 10/11 — exhaustiveness + smuggling checks
  const declaredPaths = new Set(env.instruction_files.map(f => f.path))
  for (const f of env.instruction_files) {
    if (!matchesAnyPattern(f.path, env.discovery_patterns)) {
      errors.push(`path smuggling: instruction_files[${f.path}] matches no discovery_pattern`)
    }
  }

  if (input.filesystemCheck && existsSync(env.working_root)) {
    const discovered = walkPatterns(env.working_root, env.discovery_patterns, env.filesystem_mode)
    for (const p of discovered) {
      if (!declaredPaths.has(p)) {
        errors.push(`omission detected: filesystem matches discovery_pattern but instruction_files omits '${p}'`)
      }
    }
  }

  // §6.4 step 12 — issued_at not in the future
  const now = input.now ?? new Date()
  const skew = input.clockSkewMs ?? 5 * 60 * 1000
  const issuedAtMs = Date.parse(env.issued_at)
  if (Number.isNaN(issuedAtMs)) {
    errors.push('issued_at is not a parseable ISO-8601 timestamp')
  } else if (issuedAtMs > now.getTime() + skew) {
    errors.push(`issued_at is in the future beyond clock skew (${env.issued_at})`)
  }

  // §6.4 step 13 — expires_at not in the past
  if (env.expires_at !== undefined) {
    const expMs = Date.parse(env.expires_at)
    if (Number.isNaN(expMs)) {
      errors.push('expires_at is not a parseable ISO-8601 timestamp')
    } else if (expMs < now.getTime()) {
      errors.push(`IPR expired at ${env.expires_at}`)
    }
  }

  // §6.4 step 14 — bound_to.ref shape per type
  if (env.bound_to.type === 'action' && !/^[0-9a-f]{64}$/.test(env.bound_to.ref)) {
    errors.push(`bound_to.type='action' requires ref to be 64-char hex sha256, got '${env.bound_to.ref}'`)
  }
  if (env.bound_to.type === 'window' && !/^[^/]+\/[^/]+$/.test(env.bound_to.ref)) {
    errors.push(`bound_to.type='window' requires ref of form '<iso8601>/<iso8601>'`)
  }

  return {
    valid: errors.length === 0,
    errors,
    tier,
    contextRoot: expectedContextRoot,
  }
}

/**
 * §6.5 — when an IPR carries `recompute_at_action: true`, every action
 * receipt under its binding scope MUST include `context_root_at_action_time`
 * computed by re-walking discovery_patterns. This helper compares.
 */
export function verifyActionTimeContextRoot(input: ActionTimeContextRootInput): VerificationResult {
  const errors: string[] = []
  if (!input.envelope.recompute_at_action) {
    errors.push('IPR did not declare recompute_at_action: true; action-time check not applicable')
    return { valid: false, errors }
  }
  if (!/^[0-9a-f]{64}$/.test(input.context_root_at_action_time)) {
    errors.push('context_root_at_action_time must be 64-char lowercase hex')
    return { valid: false, errors }
  }
  if (input.context_root_at_action_time !== input.envelope.context_root) {
    errors.push(
      `context_drift: action-time root ${input.context_root_at_action_time} differs from IPR root ${input.envelope.context_root}`,
    )
    return { valid: false, errors }
  }
  return { valid: true, errors: [], contextRoot: input.envelope.context_root }
}

// ─── helpers ────────────────────────────────────────────────────────

function verifyEd25519(message: string | Uint8Array, sigHex: string, publicKeyHex: string): boolean {
  try {
    const pub = Buffer.from(publicKeyHex, 'hex')
    if (pub.length !== 32) return false
    const derKey = Buffer.concat([SPKI_ED25519_PREFIX, pub])
    const keyObj = createPublicKey({ key: derKey, format: 'der', type: 'spki' })
    const msg = typeof message === 'string' ? Buffer.from(message, 'utf8') : Buffer.from(message)
    return cryptoVerify(null, msg, keyObj, Buffer.from(sigHex, 'hex'))
  } catch {
    return false
  }
}

function isSortedByPath(files: readonly InstructionFile[]): boolean {
  for (let i = 1; i < files.length; i++) {
    if (files[i - 1]!.path > files[i]!.path) return false
  }
  return true
}

/**
 * Tiny POSIX-glob matcher. Supports `*`, `?`, `**`, character literals.
 * Patterns are matched against canonical relative paths (no leading `/`,
 * forward-slash separators). Patterns may start with `./` (stripped) or
 * `**` for recursive match.
 */
export function matchesAnyPattern(path: string, patterns: readonly string[]): boolean {
  for (const raw of patterns) {
    const pat = raw.startsWith('./') ? raw.slice(2) : raw
    if (matchGlob(path, pat)) return true
  }
  return false
}

function matchGlob(path: string, pattern: string): boolean {
  const re = globToRegex(pattern)
  return re.test(path)
}

/** Compile a POSIX glob to a JS regex. `**` matches any number of segments
 *  including zero; `*` matches anything except `/`; `?` matches one non-`/`. */
function globToRegex(pattern: string): RegExp {
  let i = 0
  let out = '^'
  while (i < pattern.length) {
    const c = pattern[i]!
    if (c === '*') {
      if (pattern[i + 1] === '*') {
        // `**` consumes path segments. Handle leading `**/` and trailing `/**`.
        i += 2
        if (pattern[i] === '/') {
          out += '(?:.*/)?'
          i += 1
        } else {
          out += '.*'
        }
      } else {
        out += '[^/]*'
        i += 1
      }
    } else if (c === '?') {
      out += '[^/]'
      i += 1
    } else if ('.+()|{}[]^$\\'.includes(c)) {
      out += `\\${c}`
      i += 1
    } else {
      out += c
      i += 1
    }
  }
  out += '$'
  return new RegExp(out)
}

/** Walk the working root and return canonical relative paths matching any
 *  discovery pattern. Symlinks are returned as relative paths in their own
 *  right (we don't dereference). */
function walkPatterns(
  workingRoot: string,
  patterns: readonly string[],
  filesystemMode: 'case-sensitive' | 'case-insensitive',
): string[] {
  const out: string[] = []
  const root = resolve(workingRoot)

  const visit = (dir: string): void => {
    let entries: import('node:fs').Dirent[]
    try {
      entries = readdirSync(dir, { withFileTypes: true }) as unknown as import('node:fs').Dirent[]
    } catch {
      return
    }
    for (const ent of entries) {
      const name = String(ent.name)
      const abs = join(dir, name)
      const rel = canonicalizePathSafe(workingRoot, abs, filesystemMode)
      if (rel === null) continue
      if (ent.isDirectory()) {
        visit(abs)
      } else if (ent.isFile() || ent.isSymbolicLink()) {
        if (matchesAnyPattern(rel, patterns)) out.push(rel)
      }
    }
  }

  if (!existsSync(root)) return out
  const stat = statSync(root)
  if (!stat.isDirectory()) return out
  visit(root)
  return out.sort()
}

function canonicalizePathSafe(
  workingRoot: string,
  absPath: string,
  filesystemMode: 'case-sensitive' | 'case-insensitive',
): string | null {
  try {
    const rel = relative(workingRoot, absPath)
    if (rel.length === 0 || rel.startsWith('..')) return null
    return canonicalizePath(rel, { workingRoot, filesystemMode })
  } catch {
    return null
  }
}

