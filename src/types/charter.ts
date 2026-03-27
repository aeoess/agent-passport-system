// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// ══════════════════════════════════════════════════════════════════
// Charter — Institutional Root Object
// ══════════════════════════════════════════════════════════════════
// A Charter is the constitutional root of an institution. It defines:
//   1. CharterCore — the institutional identity and governance rules
//   2. Offices — named roles with typed authority bounds
//   3. GovernanceRules — amendment, dissolution, succession triggers
//
// Charter sits ABOVE PrincipalIdentity in the trust hierarchy:
//   Charter → Office → Principal → Agent → Delegation
//
// Consilium resolutions embedded:
//   Q5: Multi-class M-of-N Ed25519 counting (not FROST/Shamir for v1)
//   GPT #8:  OfficeHolderMode (single, co_holders, threshold, vacant, interim, suspended)
//   GPT #10: Term expiry on OfficeHolder
//   GPT #16: Dissolution policy with grace period
//   GPT #17: Quorum failure handling
//   GPT #20: Office incompatibility constraints
//   GPT #21: Delegation survivability on office/charter changes
//   GPT #22: Dispute venue binding
// ══════════════════════════════════════════════════════════════════

import type { MultiClassThresholdPolicy } from './approval.js'


// ══════════════════════════════════════════════════════════════════
// Charter Status
// ══════════════════════════════════════════════════════════════════

/** Lifecycle states for a charter. Transitions:
 *  active → amending → active (amendment succeeds)
 *  active → amending → active (amendment rejected, reverts)
 *  active → suspended → active (suspension lifted)
 *  active → dissolved (terminal — grace period, then final)
 */
export type CharterStatus = 'active' | 'suspended' | 'dissolved' | 'amending'

// ══════════════════════════════════════════════════════════════════
// Office Holder Modes (GPT correction #8)
// ══════════════════════════════════════════════════════════════════

/** How an office is held. Determines signature collection semantics:
 *  - single: exactly one holder, their signature suffices
 *  - co_holders: multiple simultaneous holders, all sign
 *  - threshold: M-of-N threshold — uses MultiClassThresholdPolicy
 *  - vacant: no current holder, succession rules apply
 *  - interim: temporary holder pending formal appointment
 *  - suspended: holder suspended pending challenge resolution
 */
export type OfficeHolderMode =
  | 'single'
  | 'co_holders'
  | 'threshold'
  | 'vacant'
  | 'interim'
  | 'suspended'

/** Office lifecycle. An office can be abolished by charter amendment. */
export type OfficeStatus = 'active' | 'vacant' | 'suspended' | 'abolished'

// ══════════════════════════════════════════════════════════════════
// Office Holder
// ══════════════════════════════════════════════════════════════════

/** An individual holding an office. GPT #10: term expiry support. */
export interface OfficeHolder {
  /** Ed25519 public key (hex) of the holder */
  publicKey: string
  /** ISO timestamp — when this holder was appointed */
  appointedAt: string
  /** Office ID or 'charter_founding' that appointed this holder */
  appointedBy: string
  /** ISO timestamp — term expiry. Undefined = no fixed term (GPT #10) */
  expiresAt?: string
  /** True if this is a temporary holder pending formal appointment */
  isInterim: boolean
}

// ══════════════════════════════════════════════════════════════════
// Office Delegation Policy
// ══════════════════════════════════════════════════════════════════

/** What this office can delegate. Typed policy ref, NOT freeform string.
 *  Every delegation issued by this office is bounded by these constraints.
 *  Monotonic narrowing: sub-delegations can only narrow, never widen. */
export interface OfficeDelegationPolicy {
  /** Allowed scope strings this office can delegate */
  allowedScopes: string[]
  /** Maximum spend per single action (currency implied by charter) */
  maxSpendPerAction: number
  /** Maximum delegation chain depth from this office */
  maxDelegationDepth: number
  /** If set, delegations from this office require approval from this policy */
  requiresApproval?: string   // approvalPolicyId
}

// ══════════════════════════════════════════════════════════════════
// Office
// ══════════════════════════════════════════════════════════════════

/** A named role within an institution. E.g. "Treasury", "Operations", "Counsel".
 *  Offices are the bridge between institutional governance (charter) and
 *  operational authority (delegation chains). An office holder can issue
 *  delegations bounded by the office's delegation policy. */
export interface Office {
  /** Unique identifier for this office (e.g. 'office_treasury') */
  officeId: string
  /** Human-readable name (e.g. "Treasury", "Operations", "Counsel") */
  name: string
  /** How this office is held — determines signature semantics */
  holderMode: OfficeHolderMode
  /** Current holder(s). Array supports co-holders and threshold modes */
  holderSet: OfficeHolder[]
  /** What this office can delegate (typed, bounded) */
  delegationPolicy: OfficeDelegationPolicy
  /** Succession order — which offices inherit if this one vacates.
   *  Ordered list of office IDs. First non-vacant office in list takes over. */
  successionOrder: string[]
  /** Office lifecycle status */
  status: OfficeStatus
  /** ISO timestamp — when this office configuration became effective */
  effectiveAt: string
  /** Offices this holder CANNOT simultaneously hold (GPT #20).
   *  Enforces separation of powers — e.g. Treasury cannot also hold Counsel. */
  incompatibleOffices?: string[]
}

// ══════════════════════════════════════════════════════════════════
// Charter Signature
// ══════════════════════════════════════════════════════════════════

/** A founding signature on a charter. Each signer declares their key class
 *  (role in the institution), enabling multi-class threshold verification. */
export interface CharterSignature {
  /** Ed25519 public key (hex) of the signer */
  publicKey: string
  /** Key class role: 'board', 'recovery', 'counsel', etc. */
  role: string
  /** ISO timestamp */
  signedAt: string
  /** Ed25519 signature over canonical charter content */
  signature: string
}

// ══════════════════════════════════════════════════════════════════
// Delegation Survivability (GPT #21)
// ══════════════════════════════════════════════════════════════════

/** What happens to existing delegations when governance changes.
 *  This is critical for institutional continuity — agent operations
 *  should not silently break when an office changes hands. */
export interface DelegationSurvival {
  /** What happens to delegations when the office holder changes */
  onOfficeChange: 'survive' | 'require_reconfirmation' | 'revoke'
  /** What happens to delegations when the charter is amended */
  onCharterAmendment: 'survive_if_compatible' | 'require_reconfirmation' | 'revoke'
}

// ══════════════════════════════════════════════════════════════════
// Dissolution Policy (GPT #16)
// ══════════════════════════════════════════════════════════════════

/** Rules for dissolving an institution. Dissolution is a terminal
 *  state — the charter cannot be reactivated after dissolution.
 *  Grace period ensures active escrows are handled before shutdown. */
export interface DissolutionPolicy {
  /** Threshold required to approve dissolution */
  requiresThreshold: MultiClassThresholdPolicy
  /** Seconds between dissolution vote passing and taking effect.
   *  During grace period: no new delegations, existing escrows resolve. */
  gracePeriodSeconds: number
  /** How to handle active escrows at dissolution time */
  activeEscrowHandling: 'settle_first' | 'force_refund' | 'transfer_to_successor'
}

// ══════════════════════════════════════════════════════════════════
// Dispute Venue (GPT #22)
// ══════════════════════════════════════════════════════════════════

/** Where disputes involving this institution are resolved.
 *  Binds the charter to a specific gateway's dispute resolution. */
export interface DisputeVenue {
  /** Gateway that handles disputes for this institution */
  gatewayId: string
  /** Legal jurisdiction (e.g. "US", "EU", "SG") */
  jurisdiction?: string
}

// ══════════════════════════════════════════════════════════════════
// Charter Core — Constitutional Root Object
// ══════════════════════════════════════════════════════════════════

/** The constitutional root of an institution. A CharterCore binds together:
 *  - Institutional identity (name, version, status)
 *  - Offices (named roles with typed authority bounds)
 *  - Amendment rules (multi-class threshold)
 *  - Dissolution rules (grace period, escrow handling)
 *  - Delegation survivability (what happens on governance changes)
 *
 *  The charter is the ROOT of the trust hierarchy. Every delegation
 *  chain ultimately traces back to a charter (or a bare principal
 *  for non-institutional agents). */
export interface CharterCore {
  /** Unique charter identifier (e.g. 'charter_<uuid>') */
  charterId: string
  /** Semantic version of this charter (e.g. '1.0.0') */
  version: string
  /** Previous version string, or null for founding charter */
  previousVersion: string | null
  /** Institution name (e.g. "AEOESS Foundation") */
  name: string
  /** Charter lifecycle status */
  status: CharterStatus
  /** Offices defined by this charter */
  offices: Office[]
  /** Multi-class threshold policy for amending this charter */
  amendmentPolicy: MultiClassThresholdPolicy
  /** Rules for dissolving the institution (GPT #16) */
  dissolutionPolicy: DissolutionPolicy
  /** What happens to delegations on governance changes (GPT #21) */
  delegationSurvival: DelegationSurvival
  /** Where disputes involving this institution are resolved (GPT #22) */
  disputeVenue?: DisputeVenue
  /** ISO timestamp — when this charter was created */
  createdAt: string
  /** Founding signatures — multi-class quorum that ratified this charter */
  foundingSignatures: CharterSignature[]
  /** SHA-256 hash of canonical charter content (excludes signature field) */
  contentHash: string
  /** Ed25519 signature over contentHash by quorum of founding signatories */
  signature: string
}

// ══════════════════════════════════════════════════════════════════
// Succession Engine (Phase 3D types, co-located with charter)
// ══════════════════════════════════════════════════════════════════

/** What event triggers a succession. GPT #10: includes scheduled review.
 *  GPT #17: includes quorum_loss. GPT #16: includes dissolution. */
export type SuccessionTrigger =
  | 'key_rotation'
  | 'heartbeat_failure'
  | 'explicit_transfer'
  | 'threshold_vote'
  | 'term_expiry'
  | 'emergency_suspension'
  | 'quorum_loss'
  | 'dissolution'

/** A rule defining how succession proceeds for a specific trigger.
 *  Each office can have multiple succession rules for different triggers. */
export interface SuccessionRule {
  /** Unique rule identifier */
  ruleId: string
  /** What event triggers this succession */
  triggerCondition: SuccessionTrigger
  /** Office being vacated */
  fromOffice: string
  /** Office that inherits, or null if office is dissolved */
  toOffice: string | null
  /** Approvals required for this succession to execute */
  requiredApprovals: MultiClassThresholdPolicy
  /** Seconds of grace before succession takes effect */
  gracePeriodSeconds: number
  /** What happens to active delegations during the succession transition */
  delegationHandling: 'freeze' | 'transfer' | 'revoke'
}

/** Quorum failure handling (GPT #17). What happens when an office
 *  loses the minimum number of holders required to operate.
 *  Frozen forever is NOT valid — maxFreezeDurationSeconds enforces a ceiling. */
export interface QuorumFailurePolicy {
  /** Office this policy applies to */
  officeId: string
  /** Minimum number of holders required for the office to function */
  minimumHolders: number
  /** What to do when quorum is lost */
  onQuorumLoss: 'freeze_office' | 'escalate_to_parent' | 'activate_recovery_keys'
  /** Key class authorized for recovery (if onQuorumLoss = 'activate_recovery_keys') */
  recoveryKeyClass?: string
  /** Maximum seconds the office can remain frozen. After this, escalation is forced. */
  maxFreezeDurationSeconds: number
}

// ══════════════════════════════════════════════════════════════════
// Office Registry — Named Roles with Authority Bounds
// ══════════════════════════════════════════════════════════════════

/** Standalone registry of offices for an institution. Extracted from
 *  CharterCore for independent versioning — offices change more often
 *  than constitutional rules. The registry always references its parent charter. */
export interface OfficeRegistry {
  /** Parent charter this registry belongs to */
  charterId: string
  /** Charter version this registry is consistent with */
  charterVersion: string
  /** All offices in this institution */
  offices: Office[]
  /** Succession rules for these offices */
  successionRules: SuccessionRule[]
  /** Quorum failure policies for offices that require multiple holders */
  quorumFailurePolicies: QuorumFailurePolicy[]
  /** ISO timestamp — last modification */
  updatedAt: string
  /** SHA-256 hash of canonical registry content */
  contentHash: string
  /** Ed25519 signature by authorized office (or charter amendment) */
  signature: string
}

// ══════════════════════════════════════════════════════════════════
// Charter Amendment
// ══════════════════════════════════════════════════════════════════

/** A proposed change to a charter. Must satisfy the charter's
 *  amendmentPolicy (multi-class threshold) to take effect.
 *  Mirrors GovernanceArtifact pattern but specific to charter changes. */
export interface CharterAmendment {
  /** Unique amendment identifier */
  amendmentId: string
  /** Charter being amended */
  charterId: string
  /** Version this amendment applies to */
  fromVersion: string
  /** Version after amendment takes effect */
  toVersion: string
  /** Human-readable description of the change */
  description: string
  /** The proposed new CharterCore (full replacement, not patch) */
  proposedCharter: CharterCore
  /** Who proposed this amendment */
  proposedBy: string
  /** ISO timestamp */
  proposedAt: string
  /** ISO timestamp — when amendment takes effect if approved */
  effectiveAt: string
  /** Signatures collected so far */
  signatures: CharterSignature[]
  /** Amendment status */
  status: 'proposed' | 'collecting_signatures' | 'approved' | 'rejected' | 'applied'
}

// ══════════════════════════════════════════════════════════════════
// Charter Verification Results
// ══════════════════════════════════════════════════════════════════

/** Result of verifying a charter's integrity and signatures.
 *  Follows the same pattern as GovernanceVerification, EndorsementVerification. */
export interface CharterVerification {
  valid: boolean
  errors: string[]
  /** Content hash matches charter body */
  contentIntegrity: boolean
  /** All founding signatures are valid Ed25519 */
  signaturesValid: boolean
  /** Founding signatures satisfy the amendment policy threshold */
  quorumMet: boolean
  /** Charter has not been dissolved */
  notDissolved: boolean
  /** Office configuration is internally consistent */
  officesValid: boolean
  /** No incompatibility violations in current holder set */
  incompatibilityClean: boolean
}

/** Result of verifying a charter amendment. */
export interface AmendmentVerification {
  valid: boolean
  errors: string[]
  /** Amendment references an existing, active charter */
  charterExists: boolean
  /** Amendment targets the current charter version */
  versionMatch: boolean
  /** Collected signatures satisfy the charter's amendment policy */
  thresholdMet: boolean
  /** All individual signatures are valid Ed25519 */
  signaturesValid: boolean
  /** Proposed charter is internally consistent */
  proposedCharterValid: boolean
}

// ══════════════════════════════════════════════════════════════════
// Office Transfer — Recording Office Holder Changes
// ══════════════════════════════════════════════════════════════════

/** Records a change in office holder. This is the audit trail for
 *  who held which office and when. Every transfer is signed. */
export interface OfficeTransfer {
  /** Unique transfer identifier */
  transferId: string
  /** Charter this office belongs to */
  charterId: string
  /** Office being transferred */
  officeId: string
  /** Previous holder's public key (null if office was vacant) */
  fromHolder: string | null
  /** New holder's public key (null if office is being vacated) */
  toHolder: string | null
  /** What triggered this transfer */
  trigger: SuccessionTrigger | 'appointment' | 'resignation'
  /** ISO timestamp */
  transferredAt: string
  /** What happened to the previous holder's active delegations */
  delegationHandling: 'frozen' | 'transferred' | 'revoked'
  /** Approvals collected for this transfer */
  approvalSignatures: CharterSignature[]
  /** Ed25519 signature over canonical transfer content */
  signature: string
}
