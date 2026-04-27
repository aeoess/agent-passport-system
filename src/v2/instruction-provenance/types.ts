// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// ══════════════════════════════════════════════════════════════════
// InstructionProvenanceReceipt — types
// ══════════════════════════════════════════════════════════════════
// Spec: ~/aeoess_web/specs/INSTRUCTION-PROVENANCE-RECEIPT-DRAFT-v0.2.md
// Tier scope this version: 'self-asserted' only. 'witnessed' and 'verified'
// are reserved schema values; verifiers MUST reject envelopes carrying them
// per ENFORCEMENT-TRUST-ANCHOR Component 4 (§§141-149).
// ══════════════════════════════════════════════════════════════════

/** v0.2 envelopes ship 'self-asserted'. v0.3 unlocks 'witnessed' and 'verified'. */
export type AttestationTier = 'self-asserted' | 'witnessed' | 'verified'

export type FilesystemMode = 'case-sensitive' | 'case-insensitive'

export type InstructionRole =
  | 'system_prompt'
  | 'agent_md'
  | 'user_md'
  | 'memory'
  | 'rules'
  | 'other'

export interface InstructionFile {
  /** Canonicalized relative POSIX path, per spec §5.1. Symlinks are separate
   *  entries with `is_symlink: true`; the link target appears as a distinct
   *  file. */
  path: string
  /** Hex sha256 of file contents. Lowercase, 64 chars. */
  digest: string
  /** Byte length of the file at issuance time. */
  bytes: number
  /** Role classification. `'other'` for files matched by patterns but not
   *  fitting a named role. */
  role: InstructionRole
  /** True iff this entry represents a symlink, not a regular file. The
   *  symlink's target file appears as its own entry. */
  is_symlink?: boolean
  /** Target path of the symlink (only present when is_symlink=true). */
  symlink_target?: string
}

export interface InstructionProvenanceReceiptBoundTo {
  type: 'session' | 'action' | 'window'
  /** Reference to the bound entity. Format depends on `type`:
   *  - session: session_id
   *  - action: action_ref hex sha256 (Module 37 / A2A#1672)
   *  - window: ISO 8601 timestamp interval `<start>/<end>` */
  ref: string
}

export interface InstructionProvenanceReceipt {
  /** sha256 of the canonical-JCS serialization of this object minus
   *  `signature` and `receipt_id`. */
  receipt_id: string

  /** Existing APS field. Links IPR to its delegation root.
   *  Format: hex sha256 of canonical delegation chain. */
  delegation_chain_root: string

  /** Acting agent DID. */
  agent_did: string

  /** Glob patterns the agent claims to have walked, in arbitrary order.
   *  Must be non-empty. POSIX globs relative to `working_root`. */
  discovery_patterns: string[]

  /** Working root for path resolution. Absolute POSIX path. The agent's
   *  `instruction_files[].path` values are relative to this root. */
  working_root: string

  /** Filesystem case mode for the working_root. Affects path comparison. */
  filesystem_mode: FilesystemMode

  /** Files matched by `discovery_patterns`. Exhaustiveness contract: this
   *  array MUST contain every regular file matched by any pattern in
   *  `discovery_patterns`, in canonical sorted order by `path`. */
  instruction_files: InstructionFile[]

  /** sha256 of the canonical-JCS serialization of `instruction_files` only.
   *  The hash that changes when any file content or path changes. */
  context_root: string

  /** Attestation tier per ENFORCEMENT-TRUST-ANCHOR Component 4. v0.2
   *  envelopes MUST carry `'self-asserted'`. */
  attestation_tier: AttestationTier

  /** When true, action receipts emitted under this IPR MUST re-hash the
   *  files matching `discovery_patterns` immediately before action
   *  execution and inline the fresh `context_root` into the action receipt.
   *  Default false. Mandatory true at tier >= 2 in v2.4. */
  recompute_at_action: boolean

  /** Issuance timestamp, ISO 8601 with millisecond precision and Z suffix. */
  issued_at: string

  /** Optional expiry. Verifiers SHOULD treat absent as session-bound. */
  expires_at?: string

  /** Binding scope. */
  bound_to: InstructionProvenanceReceiptBoundTo

  /** Ed25519 signing key fingerprint: `ed25519:<first-16-hex-of-public-key>`. */
  signing_key_id: string

  /** Ed25519 over the JCS canonicalization of this object minus
   *  `signature` and `receipt_id`. Hex, 128 chars. */
  signature: string
}

/** Result of `canonicalizePath`. Either a canonical relative POSIX string or
 *  a typed error explaining the rejection (callers throw `IPRPathError`). */
export interface CanonicalizationResult {
  canonical: string
}

/** Verification outcome from `verifyInstructionProvenanceReceipt`. */
export interface VerificationResult {
  valid: boolean
  errors: string[]
  /** Surfaced for callers that want to gate on tier even when valid=true. */
  tier?: AttestationTier
  /** Surfaced for caller convenience; equals envelope.context_root when
   *  recomputation matched, otherwise the recomputed value. */
  contextRoot?: string
}

/** Inputs for createInstructionProvenanceReceipt. */
export interface CreateIPRInput {
  delegation_chain_root: string
  agent_did: string
  discovery_patterns: string[]
  working_root: string
  filesystem_mode: FilesystemMode
  instruction_files: InstructionFile[]
  recompute_at_action?: boolean
  issued_at?: string
  expires_at?: string
  bound_to: InstructionProvenanceReceiptBoundTo
  /** Ed25519 private key (hex seed, 64 chars). */
  privateKeyHex: string
  /** Ed25519 public key (hex, 64 chars) used to derive `signing_key_id`. */
  publicKeyHex: string
  /** Tier override is not allowed in v0.2; envelope is always 'self-asserted'.
   *  Future-flagged here so v0.3 can wire 'witnessed' / 'verified'. */
  attestation_tier?: 'self-asserted'
}

/** Verification options. */
export interface VerifyIPRInput {
  envelope: InstructionProvenanceReceipt
  /** Ed25519 public key (hex, 64 chars) used to verify `signature`. */
  publicKeyHex: string
  /** When provided, performs §6.3 step 10/11 exhaustiveness check by
   *  re-walking the working root with `discovery_patterns`. When omitted,
   *  the verifier skips filesystem checks (signature + schema only). */
  filesystemCheck?: boolean
  /** Verifier clock for §6.4 step 12/13 (default: Date.now()). */
  now?: Date
  /** Allowable clock skew in milliseconds for `issued_at` future check
   *  (default: 5 minutes). */
  clockSkewMs?: number
}

/** Action-receipt context-root verification input. */
export interface ActionTimeContextRootInput {
  /** The IPR the action receipt is bound to. */
  envelope: InstructionProvenanceReceipt
  /** Action-receipt-side fresh `context_root` computed immediately before
   *  action execution. Hex sha256, 64 chars. */
  context_root_at_action_time: string
}
