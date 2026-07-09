// Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
/**
 * Signed, content-addressed policy-bundle FORMAT and VERIFIER.
 *
 * A policy-bundle is a deterministic tar of policy files plus a JCS-canonical
 * manifest plus an Ed25519 detached signature over that manifest. The manifest
 * pins every file by sha256 and pins the whole tar by sha256, so the bundle is
 * content-addressed: its identity is sha256(canonicalizeJCS(manifest)).
 *
 * What this module is:
 *   - a way to BUILD a bundle from in-memory files (createPolicyBundle)
 *   - a way to VERIFY a bundle's integrity, signature, governance class, and
 *     revocation status against an aps.txt fixture (verifyPolicyBundle)
 *
 * What this module is NOT (these are gateway product, out of scope here):
 *   - a registry, a resolver protocol, a lockfile service, a transparency log.
 * It reuses existing protocol primitives and builds no service.
 *
 * Reuse map:
 *   - JCS canonical hashing: src/core/canonical-jcs.ts
 *   - Ed25519 sign/verify:   src/crypto/keys.ts
 *   - did:aps derivation:    src/core/did.ts (createDID)
 *   - changeType vocabulary: src/types/governance.ts (GovernanceChangeType)
 *   - aps.txt revocation:    src/core/aps-txt.ts (resolveTermsForPath)
 *   - ScopeOfClaim:          src/v2/accountability/types/base.ts
 *
 * ─────────────────────────────────────────────────────────────────────────
 * PROOF BOX
 * ─────────────────────────────────────────────────────────────────────────
 * Proves: a valid policy-bundle proves the bundle contents match the signed
 *   manifest hash and that the signer authorized this exact bundle. The tar
 *   bytes hash to manifest.tarSha256, every file inside hashes to its manifest
 *   pin, and the Ed25519 signature over the canonical manifest verifies under
 *   the declared signer key.
 * Does NOT prove: that the policy inside the bundle is correct, sound, or
 *   safe; that the signer is currently authorized beyond the supplied aps.txt
 *   revocation check; or anything about who wrote the policy versus who signed
 *   it. Tested and validated, not proved-as-truth.
 * ─────────────────────────────────────────────────────────────────────────
 */

import { createHash } from 'node:crypto'
import { sign, verify } from '../../crypto/keys.js'
import { createDID } from '../../core/did.js'
import { canonicalizeJCS, canonicalHashJCS } from '../../core/canonical-jcs.js'
import { resolveTermsForPath } from '../../core/aps-txt.js'
import type { ApsTxt } from '../../core/aps-txt.js'
import type { GovernanceTerms } from '../../core/governance-block.js'
import type { GovernanceChangeType } from '../../types/governance.js'
import type { ScopeOfClaim } from '../accountability/types/base.js'
import { packTar, unpackTar } from './tar.js'
import type { TarEntry } from './tar.js'
import type {
  PolicyBundleManifest,
  PolicyBundleEnvelope,
  PolicyBundleVerification,
  PolicyBundleFileEntry,
  PolicyBundleGovernance,
  ManifestHash,
} from './types.js'

// ── encoding helpers ──

function sha256hex(bytes: Uint8Array): string {
  return createHash('sha256').update(bytes).digest('hex')
}

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('')
}

function hexToBytes(hex: string): Uint8Array {
  if (hex.length % 2 !== 0 || !/^[0-9a-f]*$/i.test(hex)) {
    throw new Error('policy-bundle: invalid hex string')
  }
  const out = new Uint8Array(hex.length / 2)
  for (let i = 0; i < hex.length; i += 2) out[i / 2] = parseInt(hex.slice(i, i + 2), 16)
  return out
}

/** A file to place in a bundle. */
export interface PolicyBundleFileInput {
  /** POSIX path inside the bundle (forward slashes, no leading slash). */
  path: string
  /** File contents as bytes or UTF-8 string. */
  content: Uint8Array | string
}

export interface CreatePolicyBundleInput {
  bundleId: string
  files: PolicyBundleFileInput[]
  signerPrivateKey: string
  signerPublicKey: string
  /** Governance classification versus the previous version. Defaults to initial. */
  governance?: Partial<PolicyBundleGovernance>
  /** Honest scope declaration. A sensible default is supplied if omitted. */
  scopeOfClaim?: ScopeOfClaim
  /** ISO timestamp override (testing/determinism). Defaults to now. */
  createdAt?: string
}

/** Default ScopeOfClaim for a policy-bundle. Dogfoods the honest-scope shape. */
export function defaultPolicyBundleScope(): ScopeOfClaim {
  return {
    asserts:
      'The bundle contents match the signed manifest hash and the signer authorized this exact bundle.',
    does_not_assert: [
      'That the policy inside the bundle is correct, sound, or safe.',
      'That the signer is currently authorized beyond the supplied aps.txt revocation check.',
      'Any claim about who authored the policy versus who signed the bundle.',
    ],
    capture_mode: 'self_attested',
    completeness: 'complete',
    self_attested: true,
  }
}

function normalizeContent(content: Uint8Array | string): Uint8Array {
  return typeof content === 'string' ? new TextEncoder().encode(content) : content
}

function buildGovernance(input?: Partial<PolicyBundleGovernance>): PolicyBundleGovernance {
  const previousManifestHash = input?.previousManifestHash ?? null
  const additions = input?.additions ?? []
  const modifications = input?.modifications ?? []
  const removals = input?.removals ?? []
  let changeType: GovernanceChangeType
  if (input?.changeType) {
    changeType = input.changeType
  } else if (previousManifestHash === null) {
    changeType = 'initial'
  } else {
    const hasAdditions = additions.length > 0
    const hasRemovals = removals.length > 0
    if (hasAdditions && hasRemovals) changeType = 'mixed'
    else if (hasRemovals) changeType = 'weakening'
    else if (hasAdditions) changeType = 'strengthening'
    else changeType = 'neutral'
  }
  return { changeType, previousManifestHash, additions, modifications, removals }
}

/**
 * Build a signed, content-addressed policy-bundle from in-memory files.
 * The tar is deterministic, so the same files always yield the same bytes
 * and the same manifest hash.
 */
export function createPolicyBundle(input: CreatePolicyBundleInput): PolicyBundleEnvelope {
  if (input.files.length === 0) {
    throw new Error('policy-bundle: at least one file is required')
  }

  const entries: TarEntry[] = input.files.map(f => ({
    name: f.path,
    data: normalizeContent(f.content),
  }))

  // Deterministic tar bytes.
  const tarBytes = packTar(entries)
  const tarSha256 = sha256hex(tarBytes)

  // Per-file pins, sorted by path for a canonical manifest.
  const fileEntries: PolicyBundleFileEntry[] = entries
    .map(e => ({ path: e.name, size: e.data.length, sha256: sha256hex(e.data) }))
    .sort((a, b) => (a.path < b.path ? -1 : a.path > b.path ? 1 : 0))

  const signerDid = createDID(input.signerPublicKey)
  const createdAt = input.createdAt ?? new Date().toISOString()

  const manifest: PolicyBundleManifest = {
    format: 'aps-policy-bundle',
    version: '1',
    bundleId: input.bundleId,
    tarSha256,
    files: fileEntries,
    signerPublicKey: input.signerPublicKey,
    signerDid,
    createdAt,
    governance: buildGovernance(input.governance),
    scopeOfClaim: input.scopeOfClaim ?? defaultPolicyBundleScope(),
  }

  // Detached signature over the JCS-canonical manifest.
  const canonical = canonicalizeJCS(manifest as unknown as Record<string, unknown>)
  const signature = sign(canonical, input.signerPrivateKey)

  return { manifest, signature, tarHex: bytesToHex(tarBytes) }
}

/** Content-addressed identity of a manifest: sha256(canonicalizeJCS(manifest)). */
export function manifestHash(manifest: PolicyBundleManifest): ManifestHash {
  return canonicalHashJCS(manifest as unknown as Record<string, unknown>)
}

export interface VerifyPolicyBundleOptions {
  /**
   * Optional aps.txt revocation anchor. When provided, the verifier resolves
   * terms for `revocationPath` (defaults to `/<bundleId>`) and treats a
   * fully-prohibited result as a revoked bundle. This reuses the existing
   * aps.txt path-override mechanism. It builds no registry or resolver service.
   */
  apsTxt?: ApsTxt
  /**
   * Path the bundle is anchored at inside the publisher's aps.txt namespace.
   * Defaults to `/<bundleId>`.
   */
  revocationPath?: string
  /**
   * Raw tar bytes. If omitted, the verifier decodes envelope.tarHex.
   * Passing bytes directly avoids a hex round-trip.
   */
  tarBytes?: Uint8Array
}

/** Returns true when every governance/revocation term denies all usage. */
function isAllDenied(terms: GovernanceTerms): boolean {
  const fields = ['inference', 'training', 'redistribution', 'derivative', 'caching'] as const
  return fields.every(f => terms[f] === 'prohibited')
}

/**
 * Verify a policy-bundle.
 *
 * Required checks (all must pass for valid=true):
 *   - signature over canonicalizeJCS(manifest) verifies under signerPublicKey
 *   - signerDid is consistent with signerPublicKey
 *   - tar bytes hash to manifest.tarSha256
 *   - every file inside the tar matches its manifest pin (path, size, sha256),
 *     and the tar contains exactly the manifest's file set
 *   - the bundle is not revoked by the supplied aps.txt anchor
 *
 * Advisory (does NOT fail the bundle, but is reported):
 *   - weakeningFlagged when governance.changeType is 'weakening' or 'mixed'.
 *     A weakening change is surfaced for caller policy, not silently accepted.
 */
export function verifyPolicyBundle(
  envelope: PolicyBundleEnvelope,
  options: VerifyPolicyBundleOptions = {},
): PolicyBundleVerification {
  const reasons: string[] = []
  const { manifest, signature } = envelope

  const mHash = manifestHash(manifest)

  // 1. Signature over canonical manifest.
  const canonical = canonicalizeJCS(manifest as unknown as Record<string, unknown>)
  let signatureValid = false
  try {
    signatureValid = verify(canonical, signature, manifest.signerPublicKey)
  } catch {
    signatureValid = false
  }
  if (!signatureValid) reasons.push('SIGNATURE_INVALID')

  // 2. signerDid consistency.
  let signerDidConsistent = false
  try {
    signerDidConsistent = createDID(manifest.signerPublicKey) === manifest.signerDid
  } catch {
    signerDidConsistent = false
  }
  if (!signerDidConsistent) reasons.push('SIGNER_DID_MISMATCH')

  // 3. Tar bytes and content integrity.
  let tarBytes: Uint8Array | null = null
  let tarHashMatches = false
  let fileHashesMatch = false
  try {
    tarBytes = options.tarBytes ?? hexToBytes(envelope.tarHex)
    tarHashMatches = sha256hex(tarBytes) === manifest.tarSha256
    if (!tarHashMatches) reasons.push('TAR_HASH_MISMATCH')

    const entries = unpackTar(tarBytes)
    fileHashesMatch = verifyFileSet(entries, manifest.files, reasons)
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err)
    reasons.push(`TAR_PARSE_ERROR:${msg}`)
    tarHashMatches = false
    fileHashesMatch = false
  }

  // 4. Governance weakening flag (advisory).
  const weakeningFlagged =
    manifest.governance.changeType === 'weakening' ||
    manifest.governance.changeType === 'mixed'
  if (weakeningFlagged) reasons.push('GOVERNANCE_WEAKENING')

  // 5. Revocation via aps.txt anchor.
  let revoked = false
  if (options.apsTxt) {
    const path = options.revocationPath ?? `/${manifest.bundleId}`
    const terms = resolveTermsForPath(options.apsTxt, path, manifest.signerDid)
    if (isAllDenied(terms)) {
      revoked = true
      reasons.push('REVOKED')
    }
  }

  const valid =
    signatureValid &&
    signerDidConsistent &&
    tarHashMatches &&
    fileHashesMatch &&
    !revoked

  return {
    valid,
    manifestHash: mHash,
    signatureValid,
    tarHashMatches,
    fileHashesMatch,
    signerDidConsistent,
    weakeningFlagged,
    revoked,
    reasons,
  }
}

/** Confirm the tar's actual entries match the manifest's pinned file set exactly. */
function verifyFileSet(
  entries: TarEntry[],
  pins: PolicyBundleFileEntry[],
  reasons: string[],
): boolean {
  if (entries.length !== pins.length) {
    reasons.push('FILE_COUNT_MISMATCH')
    return false
  }
  const pinByPath = new Map<string, PolicyBundleFileEntry>()
  for (const p of pins) pinByPath.set(p.path, p)

  let ok = true
  for (const entry of entries) {
    const pin = pinByPath.get(entry.name)
    if (!pin) {
      reasons.push(`FILE_NOT_IN_MANIFEST:${entry.name}`)
      ok = false
      continue
    }
    if (entry.data.length !== pin.size) {
      reasons.push(`FILE_SIZE_MISMATCH:${entry.name}`)
      ok = false
    }
    if (sha256hex(entry.data) !== pin.sha256) {
      reasons.push(`FILE_HASH_MISMATCH:${entry.name}`)
      ok = false
    }
  }
  return ok
}

/**
 * Serialize an envelope to a JSON string ready to store next to the tar.
 * The manifest and signature travel together; the tar travels as hex inside.
 */
export function serializePolicyBundle(envelope: PolicyBundleEnvelope): string {
  return JSON.stringify(envelope, null, 2)
}

/** Parse a serialized envelope back to an object, or null if malformed. */
export function parsePolicyBundle(content: string): PolicyBundleEnvelope | null {
  try {
    const parsed = JSON.parse(content)
    if (parsed?.manifest?.format !== 'aps-policy-bundle') return null
    return parsed as PolicyBundleEnvelope
  } catch {
    return null
  }
}

/** Decode the raw tar bytes carried by an envelope. */
export function bundleTarBytes(envelope: PolicyBundleEnvelope): Uint8Array {
  return hexToBytes(envelope.tarHex)
}
