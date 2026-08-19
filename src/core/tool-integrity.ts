// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0
// ══════════════════════════════════════════════════════════════════
// Tool Integrity Verification — OWASP Layer 2
// ══════════════════════════════════════════════════════════════════
// Source: OWASP#802 four-layer integrity taxonomy
// Layer 1: Transmission integrity (TLS) ✅
// Layer 2: Tool integrity (THIS MODULE) — tool invoked = tool approved
// Layer 3: Authorization-at-execution (ExecutionAttestation) ✅
// Layer 4: Intent integrity (ActionIntent) ✅
//
// Prevents tool-swap attacks: agent authorized to call `web_search`
// but the tool registry is swapped to a malicious implementation.
// ══════════════════════════════════════════════════════════════════

import { createHash } from 'node:crypto'
import { sign, verify } from '../crypto/keys.js'
import { canonicalize, canonicalizeForWrite } from './canonical.js'

/** Registry entry for a verified tool */
export interface ToolRegistryEntry {
  /** Tool name (must match the name in delegation scope) */
  toolName: string
  /** SHA-256 hash of the tool implementation (binary, source, or endpoint descriptor) */
  implementationHash: string
  /** Who attested this tool's integrity (runtime, registry, or auditor DID) */
  attestorId: string
  /** When the tool hash was last verified */
  verifiedAt: string
  /** Ed25519 signature over {toolName, implementationHash, attestorId, verifiedAt} */
  signature: string
}

/** Per-invocation trust requirements — tools declare what they need
 *  Source: ymc182/MeshCap on A2A#1628 */
export interface ToolRequirements {
  /** Minimum passport grade required (0-3) */
  minGrade?: number
  /** Required delegation scopes */
  requiredScopes?: string[]
  /** Minimum trust score (0-1) */
  minTrustScore?: number
  /** Whether the tool requires a verified wallet */
  requiresWallet?: boolean
  /** Custom requirements (key-value, tool-specific) */
  custom?: Record<string, unknown>
}

/** Result of tool integrity + requirements check */
export interface ToolIntegrityResult {
  /** Whether the tool passed all checks */
  valid: boolean
  /** Whether the implementation hash matches */
  implementationVerified: boolean
  /** Whether the attestor signature is valid */
  attestorSignatureValid: boolean
  /** Whether the agent meets tool requirements (if any) */
  requirementsMet: boolean
  /** Which requirements failed */
  failedRequirements: string[]
  /** Errors */
  errors: string[]
}

/**
 * Register a tool in the integrity registry.
 * The runtime/attestor signs that this tool implementation is known and approved.
 */
export function createToolRegistryEntry(input: {
  toolName: string
  /** Raw content to hash (source code, binary, or endpoint descriptor JSON) */
  implementation: string | Buffer
  attestorId: string
  attestorPrivateKey: string
}): ToolRegistryEntry {
  const implHash = createHash('sha256')
    .update(input.implementation)
    .digest('hex')

  const now = new Date().toISOString()
  const body = {
    toolName: input.toolName,
    implementationHash: `sha256:${implHash}`,
    attestorId: input.attestorId,
    verifiedAt: now,
  }
  const signature = sign(canonicalizeForWrite(body), input.attestorPrivateKey)

  return { ...body, signature }
}

/**
 * Verify tool integrity: is this the same tool that was approved?
 * Also checks per-invocation requirements if provided.
 */
export function verifyToolIntegrity(input: {
  /** The registry entry to verify against */
  registryEntry: ToolRegistryEntry
  /** Current implementation to check (will be hashed) */
  currentImplementation: string | Buffer
  /** Attestor's public key for signature verification */
  attestorPublicKey: string
  /** Optional: tool requirements to check against agent capabilities */
  requirements?: ToolRequirements
  /** Optional: agent's current capabilities (for requirements check) */
  agentCapabilities?: {
    grade: number
    scopes: string[]
    trustScore: number
    hasWallet: boolean
  }
}): ToolIntegrityResult {
  const errors: string[] = []
  const failedRequirements: string[] = []

  // 1. Verify attestor signature
  const { signature, ...body } = input.registryEntry
  const attestorSignatureValid = verify(canonicalize(body), signature, input.attestorPublicKey)
  if (!attestorSignatureValid) errors.push('Tool attestor signature invalid')

  // 2. Verify implementation hash matches
  const currentHash = `sha256:${createHash('sha256')
    .update(input.currentImplementation)
    .digest('hex')}`
  const implementationVerified = currentHash === input.registryEntry.implementationHash
  if (!implementationVerified) {
    errors.push(`Tool implementation hash mismatch: expected ${input.registryEntry.implementationHash}, got ${currentHash}`)
  }

  // 3. Check per-invocation requirements (if tool declares them)
  let requirementsMet = true
  if (input.requirements && input.agentCapabilities) {
    const reqs = input.requirements
    const caps = input.agentCapabilities

    if (reqs.minGrade !== undefined && caps.grade < reqs.minGrade) {
      failedRequirements.push(`Grade ${caps.grade} < required ${reqs.minGrade}`)
      requirementsMet = false
    }
    if (reqs.minTrustScore !== undefined && caps.trustScore < reqs.minTrustScore) {
      failedRequirements.push(`Trust score ${caps.trustScore} < required ${reqs.minTrustScore}`)
      requirementsMet = false
    }
    if (reqs.requiredScopes) {
      const missing = reqs.requiredScopes.filter(s => !caps.scopes.includes(s))
      if (missing.length > 0) {
        failedRequirements.push(`Missing scopes: ${missing.join(', ')}`)
        requirementsMet = false
      }
    }
    if (reqs.requiresWallet && !caps.hasWallet) {
      failedRequirements.push('Tool requires wallet but agent has none')
      requirementsMet = false
    }
  }

  if (!requirementsMet) errors.push(`Agent does not meet tool requirements: ${failedRequirements.join('; ')}`)

  return {
    valid: errors.length === 0,
    implementationVerified,
    attestorSignatureValid,
    requirementsMet,
    failedRequirements,
    errors,
  }
}

// ══════════════════════════════════════════════════════════════════
// Tool Registry & Discovery Integrity — signed manifests, publisher
// identity verification, namespace governance, metadata-change reapproval.
//
// Maps to CoSAI control `controlToolRegistryandDiscoveryIntegrity`
// (cosai-oasis/secure-ai-tooling#162).
//
// `ToolManifest` is the single canonical surface for this work. The
// `ToolRegistryEntry` above is frozen legacy — kept backward-compatible,
// no new fields, no new behaviour. Every new check (publisher, namespace,
// re-approval) lives on the manifest path.
// ══════════════════════════════════════════════════════════════════

import { fromDIDKey, resolveDIDWeb } from './did-interop.js'

/**
 * Trust roots (D1). The APS-native DID is the default and needs zero
 * external dependency — the Ed25519 key is embedded in the did:key /
 * did:aps identifier itself. `did:web` (domain-anchored) and `raw-key`
 * are accepted external roots so the integrity claim holds for
 * real-world registries.
 */
export type ToolTrustRoot =
  | { type: 'aps'; ref: string }
  | { type: 'did:web'; ref: string }
  | { type: 'raw-key'; ref: string }

/** Metadata block — description, declared schema, declared permissions. */
export interface ToolMetadata {
  description?: string
  schema?: unknown
  permissions?: string[]
}

/**
 * Signed tool manifest — the artifact a publisher/registry publishes.
 * Canonical surface for publisher identity, namespace and re-approval.
 */
export interface ToolManifest {
  /** Tool name (matches the name in delegation scope) */
  toolName: string
  /** Optional declared namespace, e.g. `acme/*` */
  namespace?: string
  /** `sha256:` of the implementation (existing semantics) */
  implementationHash: string
  /** `sha256:` of the canonicalized metadata block — DISTINCT from
   *  implementationHash so a description/schema/permissions change is
   *  detectable even when the implementation is byte-identical. */
  metadataHash: string
  /** Asserted publisher identity (DID). When present, a publisher check runs. */
  publisherDid?: string
  /** How the publisher key is resolved (D1). Default when absent: APS-native. */
  trustRoot?: ToolTrustRoot
  /** Asserted attestor identity (DID). When present, the manifest signature
   *  is verified against the RESOLVED attestor key — a caller-supplied
   *  `attestorPublicKey` cannot override or substitute for it. */
  attestorDid?: string
  /** How the attestor key is resolved (D1). Default when absent: APS-native. */
  attestorTrustRoot?: ToolTrustRoot
  /** Monotonic integer; bumped on every substantive revision. */
  metadataVersion: number
  /** Approval state — `pending-reapproval` blocks verification. */
  approvalState?: 'approved' | 'pending-reapproval'
  /** When this manifest was attested */
  verifiedAt: string
  /** Ed25519 attestor signature over the canonical manifest body */
  signature: string
  /** Ed25519 publisher signature over the SAME canonical body, when a
   *  publisher identity is asserted */
  publisherSignature?: string
}

/** A signed claim of ownership over a tool-name namespace (anti-typosquat). */
export interface NamespaceClaim {
  /** Claimed namespace, e.g. `acme/*` */
  namespace: string
  /** DID of the namespace owner */
  ownerDid: string
  /** How the owner key resolves (D1) */
  trustRoot: ToolTrustRoot
  /** Ed25519 signature by the owner over canonical `{namespace, ownerDid}` */
  signature: string
}

/** Result of `verifyToolManifest`. */
export interface ToolManifestResult {
  /** All checks passed */
  valid: boolean
  /** Attestor signature over the manifest body is valid (against the
   *  authoritative key — resolved when attestorDid is set, else the
   *  caller-supplied attestorPublicKey) */
  attestorSignatureValid: boolean
  /** Manifest signature verified against a RESOLVED attestor identity.
   *  True only when `attestorDid` is asserted, resolves, and the signature
   *  checks out. False when no attestorDid is asserted (no DID binding). */
  attestorVerified: boolean
  /** How the attestor key was resolved, or `caller-supplied-key` when no
   *  attestorDid is asserted */
  attestorResolutionMethod: string
  /** Implementation hash matched (true if no current implementation supplied) */
  implementationVerified: boolean
  /** Metadata hash matched (true if no current metadata supplied) */
  metadataVerified: boolean
  /** Publisher signature verified (false when no publisher identity asserted) */
  publisherVerified: boolean
  /** How the publisher key was resolved, or why it was not */
  publisherResolutionMethod: string
  /** Namespace governance passed (true when no claims supplied or no match) */
  namespaceVerified: boolean
  /** Tool name collides with a namespace owned by a different DID */
  namespaceViolation: boolean
  /** Manifest is pending re-approval after a metadata change */
  reapprovalRequired: boolean
  /** Errors */
  errors: string[]
}

/** Optional injected did:web resolver — lets callers (and tests) resolve a
 *  did:web document without live network access. Defaults to `resolveDIDWeb`. */
export interface ToolResolveOpts {
  didWebResolver?: (didWeb: string) => Promise<object>
}

const SHA256 = (data: string | Buffer): string =>
  'sha256:' + createHash('sha256').update(data).digest('hex')

/** Hash a tool implementation — string as utf-8 bytes, Buffer as raw bytes. */
function hashImplementation(impl: string | Buffer): string {
  return SHA256(impl)
}

/** Hash the canonicalized metadata block. */
function hashMetadata(meta: ToolMetadata): string {
  return SHA256(canonicalize(meta))
}
/** Write-boundary twin of hashMetadata().
 *
 *  Emits the same bytes as hashMetadata() for every value it accepts. The only difference
 *  is that an integer-valued number outside the interoperable IEEE 754 range is
 *  refused instead of serialized. Use at signing and new-write boundaries ONLY:
 *  hashMetadata() stays unrestricted so an artifact signed before this rule keeps
 *  verifying. */
function hashMetadataForWrite(meta: ToolMetadata): string {
  return SHA256(canonicalizeForWrite(meta))
}

/** Canonical signing body — the manifest minus BOTH signatures. The attestor
 *  and the publisher sign exactly this string. */
function canonicalManifestBody(
  m: ToolManifest | Omit<ToolManifest, 'signature' | 'publisherSignature'>,
): string {
  const { signature: _s, publisherSignature: _p, ...body } = m as ToolManifest
  return canonicalize(body)
}

/**
 * Resolve a publisher/owner DID to an Ed25519 public key (hex) via its
 * trust root (D1). Never throws — failures return `publicKey: null` with a
 * reason so the caller can record `publisherVerified: false`.
 */
async function resolveTrustRootKey(
  did: string,
  trustRoot: ToolTrustRoot | undefined,
  opts?: ToolResolveOpts,
): Promise<{ publicKey: string | null; method: string; error?: string }> {
  // Default: APS-native DID — self-certifying, zero external dependency.
  const root: ToolTrustRoot = trustRoot ?? { type: 'aps', ref: did }

  if (root.type === 'aps') {
    // did:key / did:aps carry the Ed25519 key in the identifier itself.
    try {
      const asKey = did.startsWith('did:aps:')
        ? 'did:key:' + did.slice('did:aps:'.length)
        : did
      return { publicKey: fromDIDKey(asKey), method: 'aps-native-did' }
    } catch (e) {
      return { publicKey: null, method: 'aps-native-did', error: e instanceof Error ? e.message : String(e) }
    }
  }

  if (root.type === 'raw-key') {
    // TRUST ASSUMPTION (external root): the caller asserts that `root.ref` is
    // the publisher's Ed25519 public key. APS verifies the signature against
    // this key but does NOT verify any chain proving the key belongs to the
    // named DID — that binding is the caller's to vouch for. The raw key
    // resolves a publisher identity, nothing more.
    const key = root.ref.trim().toLowerCase()
    if (!/^[0-9a-f]{64}$/.test(key)) {
      return { publicKey: null, method: 'raw-key', error: 'raw-key trust root is not a 32-byte hex Ed25519 key' }
    }
    return { publicKey: key, method: 'raw-key' }
  }

  // did:web — external root anchored on domain control. Native fetch only;
  // no fetch polyfill is ever added (D4).
  const resolver = opts?.didWebResolver
  if (!resolver && typeof fetch !== 'function') {
    return { publicKey: null, method: 'did:web', error: 'did_web_resolution_unavailable' }
  }
  try {
    const doc = await (resolver ? resolver(root.ref) : resolveDIDWeb(root.ref))
    const key = firstEd25519Key(doc)
    if (!key) return { publicKey: null, method: 'did:web', error: 'no Ed25519 verification method in did:web document' }
    return { publicKey: key, method: 'did:web' }
  } catch (e) {
    return { publicKey: null, method: 'did:web', error: e instanceof Error ? e.message : String(e) }
  }
}

/** Minimal extractor — the first Ed25519 verification method in a DID doc. */
function firstEd25519Key(doc: unknown): string | null {
  const vms = (doc as { verificationMethod?: unknown[] })?.verificationMethod
  if (!Array.isArray(vms)) return null
  for (const vm of vms) {
    if (!vm || typeof vm !== 'object') continue
    const v = vm as Record<string, unknown>
    const type = String(v.type ?? '')
    const mb = typeof v.publicKeyMultibase === 'string' ? v.publicKeyMultibase : ''
    const isEd25519 = type.includes('Ed25519') || mb.startsWith('z6Mk')
    if (!isEd25519) continue
    if (typeof v.publicKeyHex === 'string' && /^[0-9a-fA-F]{64}$/.test(v.publicKeyHex)) {
      return v.publicKeyHex.toLowerCase()
    }
    if (mb.startsWith('z')) {
      try { return fromDIDKey('did:key:' + mb) } catch { /* try next */ }
    }
  }
  return null
}

/** Namespace match. `acme/*` covers `acme/<anything>`; a bare `acme` covers
 *  `acme` and `acme/<anything>`. Mechanical prefix rule — no globbing beyond
 *  a trailing `/*`. */
function toolNameUnderNamespace(toolName: string, namespace: string): boolean {
  if (namespace.endsWith('/*')) {
    return toolName.startsWith(namespace.slice(0, -1))
  }
  return toolName === namespace || toolName.startsWith(namespace + '/')
}

/**
 * Create a signed tool manifest. The attestor signs the canonical body; if a
 * publisher private key is supplied, the publisher co-signs the same body.
 */
export function createToolManifest(input: {
  toolName: string
  namespace?: string
  /** Raw implementation content to hash */
  implementation: string | Buffer
  /** Metadata block to hash (distinct from the implementation) */
  metadata: ToolMetadata
  attestorPrivateKey: string
  /** Asserted attestor identity (DID) — when set, the manifest carries it and
   *  verification binds the signature to the resolved attestor key */
  attestorDid?: string
  /** Trust root for resolving the attestor key, optional */
  attestorTrustRoot?: ToolTrustRoot
  /** Asserted publisher identity, optional */
  publisherDid?: string
  /** Trust root for resolving the publisher key, optional */
  trustRoot?: ToolTrustRoot
  /** Publisher private key — when present, the manifest is publisher co-signed */
  publisherPrivateKey?: string
  /** Monotonic metadata version (default 1) */
  metadataVersion?: number
  /** Approval state (default 'approved') */
  approvalState?: 'approved' | 'pending-reapproval'
  /** Override timestamp — for deterministic conformance fixtures */
  verifiedAt?: string
}): ToolManifest {
  const body: Omit<ToolManifest, 'signature' | 'publisherSignature'> = {
    toolName: input.toolName,
    namespace: input.namespace,
    implementationHash: hashImplementation(input.implementation),
    metadataHash: hashMetadataForWrite(input.metadata),
    publisherDid: input.publisherDid,
    trustRoot: input.trustRoot,
    attestorDid: input.attestorDid,
    attestorTrustRoot: input.attestorTrustRoot,
    metadataVersion: input.metadataVersion ?? 1,
    approvalState: input.approvalState ?? 'approved',
    verifiedAt: input.verifiedAt ?? new Date().toISOString(),
  }
  const canon = canonicalizeForWrite(body)
  const signature = sign(canon, input.attestorPrivateKey)
  const publisherSignature = input.publisherPrivateKey
    ? sign(canon, input.publisherPrivateKey)
    : undefined
  return { ...body, signature, publisherSignature }
}

/**
 * Verify a tool manifest — attestor signature, optional implementation and
 * metadata hashes, publisher identity (Part 1b), namespace governance
 * (Part 2) and re-approval state (Part 3). Async because did:web resolution
 * is async; the APS-native and raw-key paths resolve synchronously.
 */
export async function verifyToolManifest(input: {
  manifest: ToolManifest
  /** Attestor public key — used ONLY when the manifest asserts no
   *  `attestorDid`. When `attestorDid` is set the resolved key is
   *  authoritative and this key cannot override or substitute for it (G1). */
  attestorPublicKey?: string
  /** Current implementation to hash-check, optional */
  currentImplementation?: string | Buffer
  /** Current metadata to hash-check, optional */
  currentMetadata?: ToolMetadata
  /** Known namespace claims — namespace check runs only when supplied */
  namespaceClaims?: NamespaceClaim[]
  /** Optional injected did:web resolver (offline use / tests) */
  didWebResolver?: (didWeb: string) => Promise<object>
}): Promise<ToolManifestResult> {
  const m = input.manifest
  const errors: string[] = []
  const canon = canonicalManifestBody(m)

  // 1. Attestor signature. When the manifest asserts an `attestorDid`, the
  //    RESOLVED attestor key is authoritative (G1) — a caller-supplied
  //    `attestorPublicKey` cannot override or substitute for it, which is the
  //    whole point of binding. Without an `attestorDid`, the pass-1 behaviour
  //    holds: verify against the caller-supplied key.
  let attestorSignatureValid = false
  let attestorVerified = false
  let attestorResolutionMethod = 'caller-supplied-key'
  if (m.attestorDid !== undefined) {
    const resolved = await resolveTrustRootKey(m.attestorDid, m.attestorTrustRoot, {
      didWebResolver: input.didWebResolver,
    })
    attestorResolutionMethod = resolved.method
    if (!resolved.publicKey) {
      // External trust roots can fail to resolve — a clean fail, never a throw.
      errors.push(`Attestor key resolution failed: ${resolved.error ?? 'unknown'}`)
    } else {
      attestorSignatureValid = verify(canon, m.signature, resolved.publicKey)
      attestorVerified = attestorSignatureValid
      if (!attestorSignatureValid) {
        errors.push('Tool manifest attestor signature invalid (resolved attestor key)')
      }
    }
  } else if (input.attestorPublicKey !== undefined) {
    attestorSignatureValid = verify(canon, m.signature, input.attestorPublicKey)
    if (!attestorSignatureValid) errors.push('Tool manifest attestor signature invalid')
  } else {
    errors.push('No attestorDid on manifest and no attestorPublicKey supplied')
  }

  // 2. Implementation hash — only when a current implementation is supplied.
  let implementationVerified = true
  if (input.currentImplementation !== undefined) {
    implementationVerified = hashImplementation(input.currentImplementation) === m.implementationHash
    if (!implementationVerified) {
      errors.push(`Tool implementation hash mismatch: expected ${m.implementationHash}`)
    }
  }

  // 3. Metadata hash — only when current metadata is supplied.
  let metadataVerified = true
  if (input.currentMetadata !== undefined) {
    metadataVerified = hashMetadata(input.currentMetadata) === m.metadataHash
    if (!metadataVerified) {
      errors.push(`Tool metadata hash mismatch: expected ${m.metadataHash}`)
    }
  }

  // 4. Publisher identity (Part 1b) — runs only when a publisherDid is asserted.
  let publisherVerified = false
  let publisherResolutionMethod = 'not-asserted'
  if (m.publisherDid !== undefined) {
    if (!m.publisherSignature) {
      publisherResolutionMethod = 'no-publisher-signature'
      errors.push('Publisher DID asserted but no publisherSignature present')
    } else {
      const resolved = await resolveTrustRootKey(m.publisherDid, m.trustRoot, {
        didWebResolver: input.didWebResolver,
      })
      publisherResolutionMethod = resolved.method
      if (!resolved.publicKey) {
        errors.push(`Publisher key resolution failed: ${resolved.error ?? 'unknown'}`)
      } else {
        publisherVerified = verify(canon, m.publisherSignature, resolved.publicKey)
        if (!publisherVerified) errors.push('Publisher signature invalid')
      }
    }
  }

  // 5. Namespace governance (Part 2) — anti-typosquat / anti-shadowing.
  //    Open by default: claims are opt-in, a name under no claim passes.
  let namespaceVerified = true
  let namespaceViolation = false
  for (const claim of input.namespaceClaims ?? []) {
    if (!toolNameUnderNamespace(m.toolName, claim.namespace)) continue
    if (m.publisherDid !== claim.ownerDid) {
      namespaceViolation = true
      namespaceVerified = false
      errors.push(
        `Namespace violation: tool "${m.toolName}" falls under claimed namespace ` +
        `"${claim.namespace}" owned by ${claim.ownerDid}, but manifest publisherDid ` +
        `is ${m.publisherDid ?? '(none)'}`,
      )
    }
  }

  // 6. Re-approval (Part 3) — a manifest pending re-approval is not valid.
  const reapprovalRequired = m.approvalState === 'pending-reapproval'
  if (reapprovalRequired) errors.push('tool metadata changed, awaiting re-approval')

  return {
    valid: errors.length === 0,
    attestorSignatureValid,
    attestorVerified,
    attestorResolutionMethod,
    implementationVerified,
    metadataVerified,
    publisherVerified,
    publisherResolutionMethod,
    namespaceVerified,
    namespaceViolation,
    reapprovalRequired,
    errors,
  }
}

/** Create a signed namespace ownership claim. */
export function createNamespaceClaim(input: {
  namespace: string
  ownerDid: string
  trustRoot: ToolTrustRoot
  ownerPrivateKey: string
}): NamespaceClaim {
  const canon = canonicalizeForWrite({ namespace: input.namespace, ownerDid: input.ownerDid })
  return {
    namespace: input.namespace,
    ownerDid: input.ownerDid,
    trustRoot: input.trustRoot,
    signature: sign(canon, input.ownerPrivateKey),
  }
}

/**
 * Verify a namespace claim — resolve the owner key via the claim's own trust
 * root and check the owner signature over canonical `{namespace, ownerDid}`.
 * `resolveOpts` carries an optional injected did:web resolver.
 */
export async function verifyNamespaceClaim(
  claim: NamespaceClaim,
  resolveOpts?: ToolResolveOpts,
): Promise<{ valid: boolean; ownerVerified: boolean; resolutionMethod: string; errors: string[] }> {
  const errors: string[] = []
  const canon = canonicalize({ namespace: claim.namespace, ownerDid: claim.ownerDid })
  const resolved = await resolveTrustRootKey(claim.ownerDid, claim.trustRoot, resolveOpts)
  let ownerVerified = false
  if (!resolved.publicKey) {
    errors.push(`Namespace owner key resolution failed: ${resolved.error ?? 'unknown'}`)
  } else {
    ownerVerified = verify(canon, claim.signature, resolved.publicKey)
    if (!ownerVerified) errors.push('Namespace claim owner signature invalid')
  }
  return { valid: errors.length === 0, ownerVerified, resolutionMethod: resolved.method, errors }
}

/**
 * Revise a tool manifest (Part 3). Produces a new manifest re-signed by the
 * attestor. Hash-delta rule — the concrete link between Part 1a and Part 3:
 * the revision moves to `pending-reapproval` with `metadataVersion + 1` IFF
 * the implementation hash OR the metadata hash differs from the previous
 * manifest. If neither hash changed it is not a substantive revision and the
 * version / approval state are unchanged.
 *
 * The attestor identity (`attestorDid` / `attestorTrustRoot`) is carried
 * forward. If the previous manifest asserts a `publisherDid`, a
 * `publisherPrivateKey` MUST be supplied so the publisher field is re-signed
 * over the revised body — revising a publisher-bearing manifest without it
 * throws rather than emit a manifest with a stale publisher signature.
 */
export function reviseToolManifest(
  prevManifest: ToolManifest,
  changes: { implementation?: string | Buffer; metadata?: ToolMetadata },
  attestorPrivateKey: string,
  opts?: { verifiedAt?: string; publisherPrivateKey?: string },
): ToolManifest {
  if (prevManifest.publisherDid !== undefined && !opts?.publisherPrivateKey) {
    throw new Error(
      'reviseToolManifest: this manifest asserts a publisherDid; a ' +
      'publisherPrivateKey is required to re-sign the publisher field over ' +
      'the revised body',
    )
  }
  const implementationHash = changes.implementation !== undefined
    ? hashImplementation(changes.implementation)
    : prevManifest.implementationHash
  const metadataHash = changes.metadata !== undefined
    ? hashMetadataForWrite(changes.metadata)
    : prevManifest.metadataHash

  const substantive =
    implementationHash !== prevManifest.implementationHash ||
    metadataHash !== prevManifest.metadataHash

  const body: Omit<ToolManifest, 'signature' | 'publisherSignature'> = {
    toolName: prevManifest.toolName,
    namespace: prevManifest.namespace,
    implementationHash,
    metadataHash,
    publisherDid: prevManifest.publisherDid,
    trustRoot: prevManifest.trustRoot,
    attestorDid: prevManifest.attestorDid,
    attestorTrustRoot: prevManifest.attestorTrustRoot,
    metadataVersion: substantive ? prevManifest.metadataVersion + 1 : prevManifest.metadataVersion,
    approvalState: substantive ? 'pending-reapproval' : prevManifest.approvalState,
    verifiedAt: opts?.verifiedAt ?? new Date().toISOString(),
  }
  const canon = canonicalizeForWrite(body)
  const publisherSignature = prevManifest.publisherDid !== undefined
    ? sign(canon, opts!.publisherPrivateKey!)
    : undefined
  return { ...body, signature: sign(canon, attestorPrivateKey), publisherSignature }
}

/**
 * Re-approve a manifest pending re-approval (Part 3). Only an attestor can move
 * `pending-reapproval` -> `approved`.
 *
 * The approval is bound to a resolved attestor identity, not merely any
 * caller-provided keypair: the returned manifest carries `attestorDid` /
 * `attestorTrustRoot`, and its signature then verifies against the resolved
 * attestor key in `verifyToolManifest`. If `opts.attestorDid` is omitted the
 * attestor identity already on the manifest is carried forward.
 *
 * If the manifest asserts a `publisherDid`, a `publisherPrivateKey` is required
 * so the publisher field is re-signed over the approved body. Throws if the
 * manifest is not pending re-approval, or on a missing required publisher key.
 */
export function reapproveToolManifest(
  manifest: ToolManifest,
  opts: {
    attestorPrivateKey: string
    attestorDid?: string
    attestorTrustRoot?: ToolTrustRoot
    publisherPrivateKey?: string
    verifiedAt?: string
  },
): ToolManifest {
  if (manifest.approvalState !== 'pending-reapproval') {
    throw new Error('reapproveToolManifest: manifest is not pending re-approval')
  }
  if (manifest.publisherDid !== undefined && !opts.publisherPrivateKey) {
    throw new Error(
      'reapproveToolManifest: this manifest asserts a publisherDid; a ' +
      'publisherPrivateKey is required to re-sign the publisher field over ' +
      'the approved body',
    )
  }
  const { signature: _s, publisherSignature: _p, ...rest } = manifest
  const body: Omit<ToolManifest, 'signature' | 'publisherSignature'> = {
    ...rest,
    attestorDid: opts.attestorDid ?? manifest.attestorDid,
    attestorTrustRoot: opts.attestorTrustRoot ?? manifest.attestorTrustRoot,
    approvalState: 'approved',
    verifiedAt: opts.verifiedAt ?? new Date().toISOString(),
  }
  const canon = canonicalizeForWrite(body)
  const publisherSignature = manifest.publisherDid !== undefined
    ? sign(canon, opts.publisherPrivateKey!)
    : undefined
  return { ...body, signature: sign(canon, opts.attestorPrivateKey), publisherSignature }
}
