// ══════════════════════════════════════════════════════════════════
// Cross-Chain Data Flow Authorization — Types
// ══════════════════════════════════════════════════════════════════
// Solves the Confused Deputy problem in multi-principal delegation.
//
// Core invariant: Authority from different principals may not be
// combined in a single effectful action unless the combination
// itself is explicitly authorized.
//
// Three mechanisms:
//   1. Signed Authority Objects (SAOs) — data carries its origin context
//   2. Taint Propagation — derived outputs inherit source taint
//   3. Cross-Chain Permits — explicit authorization for cross-context flows
// ══════════════════════════════════════════════════════════════════

// ── Taint Context ──
// Every piece of data accessed through a delegation carries a taint label.

export interface TaintLabel {
  /** Principal who authorized access */
  principalId: string
  /** Delegation chain that produced this data */
  chainId: string
  /** Specific delegation ID */
  delegationId: string
  /** What usage constraints came with this data */
  usage: TaintUsage
  /** When the taint was applied */
  taintedAt: string
  /** For derived/multi-principal data: all contributing principal IDs.
   *  Enables per-principal permit matching on derived SAOs. */
  sourcePrincipals?: string[]
}

/** What the data owner permits */
export type TaintUsage =
  | 'unrestricted'      // data can flow anywhere (rare)
  | 'same-context-only' // data stays within originating chain (default)
  | 'export-with-permit' // data can cross chains if a permit exists
  | 'read-only'         // data cannot be used as input to any outbound action

// ── Taint Set ──
// When multiple data sources are combined, their taints merge.

export interface TaintSet {
  /** All taint labels from all data sources */
  labels: TaintLabel[]
  /** Unique principal IDs in this set */
  principals: string[]
  /** Whether this set contains labels from multiple principals */
  isCrossChain: boolean
}

// ── Signed Authority Object (SAO) ──
// Data returned by the gateway is wrapped in an SAO.
// The agent can read the data, but outbound tools only accept SAOs.

export interface SignedAuthorityObject {
  saoId: string
  /** The actual data payload */
  data: unknown
  /** Origin taint — who authorized access and under what chain */
  taint: TaintLabel
  /** Hash of the data for integrity verification */
  dataHash: string
  /** Gateway/monitor signature over (dataHash + taint) */
  monitorSignature: string
  /** Public key of the signing monitor */
  monitorPublicKey: string
  /** When the SAO was created */
  createdAt: string
  /** When the SAO expires (data should not be used after this) */
  expiresAt: string
}

// ── Cross-Chain Permit ──
// Explicitly authorizes data flow between two delegation contexts.
// Both principals must sign. Without this, cross-chain flow is BLOCKED.

export interface CrossChainPermit {
  permitId: string
  /** Principal A authorizes their data to flow... */
  sourceContext: {
    principalId: string
    principalPublicKey: string
    /** Which data classes may flow (e.g., 'calendar', 'email', '*') */
    dataClasses: string[]
  }
  /** ...into actions governed by Principal B */
  destinationContext: {
    principalId: string
    principalPublicKey: string
    /** Which action scopes may receive the data */
    allowedScopes: string[]
  }
  /** What purpose justifies the cross-chain flow */
  purpose: string
  /** Destination restrictions (e.g., specific recipients, domains) */
  destinationConstraints?: string[]
  /** When this permit was created */
  createdAt: string
  /** When this permit expires */
  expiresAt: string
  /** Whether this permit has been revoked */
  revoked: boolean
  /** Source principal's signature (over everything above) */
  sourceSignature: string
  /** Destination principal's signature (over everything above) */
  destinationSignature: string
}

// ── Execution Frame Taint ──
// Tracks ALL delegation contexts accessed during a reasoning session.
// Even if the agent "launders" data by summarizing, the frame is tainted.

export interface ExecutionFrame {
  frameId: string
  agentId: string
  /** All delegation contexts accessed during this frame */
  accessedContexts: TaintLabel[]
  /** Accumulated taint set (union of all accessed) */
  frameTaint: TaintSet
  /** When the frame started */
  startedAt: string
  /** Whether frame is still active */
  active: boolean
  /** Hash of the latest step — cryptographic proof of execution order */
  chainHead?: string
  /** Step counter — monotonic, proves no gaps */
  stepCount: number
  /** Frame epoch number — monotonically increases on rotation */
  epoch: number
  /** TTL in minutes — frame expires after this duration (0 = no expiry) */
  ttlMinutes: number
  /** If this frame was sealed by rotation, the sealed timestamp */
  sealedAt?: string
  /** Previous frame's chainHead — links epochs into a super-chain */
  previousFrameChainHead?: string
  /** Principal IDs from previous epochs — survives rotation for cross-chain enforcement.
   *  Prevents the "clean window" attack where rotation clears taint. */
  residuePrincipals: string[]
}

/** A causally-ordered execution step with hash chain linkage */
export interface ExecutionStep {
  /** Step number in this frame (0-indexed, monotonic) */
  stepIndex: number
  /** Hash of the previous step (empty string for step 0) */
  previousStepHash: string
  /** The taint introduced at this step */
  taint: TaintLabel
  /** Hash of this step: sha256(previousStepHash + canonical(taint) + stepIndex) */
  stepHash: string
  /** When this step was recorded */
  recordedAt: string
}

// ── Flow Check Result ──
// What the gateway returns when checking a cross-chain action.

export type FlowVerdict = 'allowed' | 'blocked' | 'permitted'

export interface FlowCheckResult {
  /** Was the action allowed? */
  verdict: FlowVerdict
  /** If blocked: which taint labels caused the block */
  blockingLabels?: TaintLabel[]
  /** If permitted: which cross-chain permit authorized the flow */
  permitId?: string
  /** Human-readable explanation */
  reason: string
  /** The full taint set that was checked */
  taintSet: TaintSet
  /** Timestamp of the check */
  checkedAt: string
}

// ── Taint Transformation ──
// When data is transformed (aggregated, anonymized, hashed),
// the taint is NOT cleared — it is transformed.

export type TransformationType =
  | 'aggregation'     // individual records → summary statistics
  | 'anonymization'   // PII removed
  | 'hashing'         // one-way hash
  | 'redaction'       // sensitive fields removed
  | 'approved-summary' // human-approved summary

export interface TaintTransformation {
  transformationId: string
  /** Original taint labels */
  inputTaints: TaintLabel[]
  /** What transformation was applied */
  type: TransformationType
  /** New classification after transformation */
  outputClassification: 'declassified' | 'downgraded' | 'unchanged'
  /** Who approved this transformation */
  approvedBy: string
  /** Signature of the approver */
  approverSignature: string
  /** When the transformation was approved */
  approvedAt: string
}


// ── Execution Receipt (Mediated Execution Proof) ──
// The gateway's signed proof that it performed all cross-chain
// checks before execution. Answers Sanjeev's question about
// resolve endpoint attestation: the receipt proves the gateway ran.

export interface ExecutionReceipt {
  receiptId: string
  frameId: string
  requestHash: string
  tool: string
  paramsHash: string
  delegationId: string
  taintPrincipals: string[]
  taintSetHash: string
  crossChainDetected: boolean
  crossChainAuthorized: boolean
  permitId?: string
  policyVersion: string
  nonce: string
  timestamp: string
  expiresAt: string
  gatewayId: string
  gatewaySignature: string
}

// ── Cross-Chain Violation ──
// Structured, gateway-signed proof that a cross-chain violation
// was detected and blocked. Audit artifact.

export interface CrossChainViolation {
  frameId: string
  agentId: string
  sourcePrincipalId: string
  destinationPrincipalId: string
  attemptedTool: string
  attemptedScope: string
  blockingLabels: TaintLabel[]
  timestamp: string
  gatewaySignature: string
}
