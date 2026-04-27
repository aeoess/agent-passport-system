// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// ══════════════════════════════════════════════════════════════════
// IPR — path canonicalization (§5.1) + envelope canonicalization (§5.2)
// ══════════════════════════════════════════════════════════════════
// Pure functions, no I/O. Cross-language byte-parity contract: every
// `canonicalizePath` result must match the future Python port byte-for-byte
// against the same fixture inputs. JCS canonicalization for envelopes
// reuses the existing src/core/canonical-jcs.ts implementation (RFC 8785).
// ══════════════════════════════════════════════════════════════════

import { createHash } from 'node:crypto'
import { canonicalizeJCS } from '../../core/canonical-jcs.js'
import type { FilesystemMode, InstructionFile, InstructionProvenanceReceipt } from './types.js'

/** Typed error for path-canonicalization rejections (spec §5.1). */
export class IPRPathError extends Error {
  constructor(public readonly code: string, message: string) {
    super(`${code}: ${message}`)
    this.name = 'IPRPathError'
  }
}

export interface CanonicalizePathOptions {
  /** Absolute POSIX path to the working root. The input path must resolve
   *  inside this root. */
  workingRoot: string
  /** Filesystem case mode for the working root. Affects normalization. */
  filesystemMode: FilesystemMode
}

/**
 * Canonicalize a raw path per spec §5.1. Returns a relative POSIX path.
 *
 * Steps (must match the spec algorithm exactly for cross-language parity):
 *   1. Reject empty path.
 *   2. Reject percent-encoded paths (paths are POSIX, not URIs).
 *   3. Compute absolute form of `raw` relative to `workingRoot` (without
 *      filesystem access — pure string math).
 *   4. Reject if the absolute form does not start with `workingRoot`.
 *   5. Strip the working-root prefix to get a relative form.
 *   6. Reject leading `./`.
 *   7. Reject any `..` segment.
 *   8. Reject trailing slash.
 *   9. Normalize Unicode to NFC.
 *  10. Apply case mode (lowercase if case-insensitive).
 *  11. Replace OS-specific separators with `/`.
 */
export function canonicalizePath(raw: string, options: CanonicalizePathOptions): string {
  if (raw.length === 0) throw new IPRPathError('EMPTY', 'path is empty')
  if (raw.includes('%')) {
    throw new IPRPathError('PERCENT_ENCODING', 'paths are POSIX, not URIs; percent-encoding rejected')
  }

  const root = stripTrailingSlash(options.workingRoot)
  if (!root.startsWith('/')) {
    throw new IPRPathError('WORKING_ROOT_NOT_ABSOLUTE', `working_root must be absolute POSIX: ${root}`)
  }

  // Compute absolute form. Treat raw as relative-to-root if not already absolute.
  let abs: string
  if (raw.startsWith('/')) {
    abs = raw
  } else {
    const cleaned = raw.startsWith('./') ? raw.slice(2) : raw
    abs = `${root}/${cleaned}`
  }

  // Reject ".." anywhere (segment-level check).
  for (const seg of abs.split('/')) {
    if (seg === '..') throw new IPRPathError('TRAVERSAL', 'parent traversal `..` not permitted')
  }

  // Reject if absolute form is not under root.
  const rootWithSlash = `${root}/`
  if (abs !== root && !abs.startsWith(rootWithSlash)) {
    throw new IPRPathError('OUTSIDE_ROOT', `path resolves outside working_root: ${abs}`)
  }

  let rel = abs === root ? '' : abs.slice(rootWithSlash.length)
  if (rel.length === 0) {
    throw new IPRPathError('EMPTY', 'path canonicalizes to empty (working_root itself, not a file)')
  }
  if (rel.endsWith('/')) {
    throw new IPRPathError('TRAILING_SLASH', `trailing slash not permitted: ${rel}`)
  }
  if (rel.startsWith('./')) {
    throw new IPRPathError('LEADING_DOT_SLASH', `leading "./" not permitted in canonical form: ${rel}`)
  }

  rel = rel.normalize('NFC')
  if (options.filesystemMode === 'case-insensitive') rel = rel.toLowerCase()

  // Replace any backslashes (OS separators on non-POSIX platforms emitting
  // path strings via Node's path.join). Spec mandates POSIX `/`.
  rel = rel.replace(/\\/g, '/')

  return rel
}

/** Strip trailing slash from a path while preserving the root `/`. */
function stripTrailingSlash(p: string): string {
  if (p.length > 1 && p.endsWith('/')) return p.slice(0, -1)
  return p
}

/** sha256 hex of a UTF-8 string. */
export function sha256Hex(input: string | Uint8Array): string {
  return createHash('sha256').update(input).digest('hex')
}

/**
 * Compute `context_root` per spec §4.1: sha256 of the JCS canonicalization
 * of the `instruction_files` array. Must be byte-identical across languages.
 */
export function computeContextRoot(files: InstructionFile[]): string {
  const sorted = sortInstructionFiles(files)
  return sha256Hex(canonicalizeJCS(sorted))
}

/**
 * Canonical sort order for `instruction_files`: lexicographic by `path`
 * (canonical bytes). Spec §6.3 step 8.
 */
export function sortInstructionFiles(files: InstructionFile[]): InstructionFile[] {
  return [...files].sort((a, b) => (a.path < b.path ? -1 : a.path > b.path ? 1 : 0))
}

/**
 * Strip `signature` and `receipt_id` from the envelope and return the JCS
 * canonical bytes used for both `receipt_id` derivation and Ed25519 signing.
 * Spec §5.2.
 */
export function canonicalizeEnvelope(
  envelope: Omit<InstructionProvenanceReceipt, 'signature' | 'receipt_id'>,
): string {
  // Defensive shallow clone that strips signature/receipt_id even when the
  // caller passes a fully-formed envelope at runtime (TS narrows on Omit at
  // compile time, but JS objects can carry extras).
  const clone: Record<string, unknown> = {}
  const src = envelope as Record<string, unknown>
  for (const k of Object.keys(src)) {
    if (k === 'signature' || k === 'receipt_id') continue
    clone[k] = src[k]
  }
  return canonicalizeJCS(clone)
}
