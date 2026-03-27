// Agent Passport System — Type Definitions

export interface KeyPair {
  privateKey: string  // hex-encoded Ed25519 private key
  publicKey: string   // hex-encoded Ed25519 public key
}

export interface AgentPassport {
  version: string
  agentId: string
  agentName: string
  ownerAlias: string
  publicKey: string
  mission: string
  capabilities: string[]
  runtime: RuntimeInfo
  createdAt: string
  expiresAt: string
  voteWeight: number
  reputation: ReputationScore
  delegations: Delegation[]
  metadata: Record<string, unknown>
}

export interface RuntimeInfo {
  platform: string
  models: string[]
  toolsCount: number
  memoryType: string
}

export interface ReputationScore {
  overall: number
  collaborationsCompleted: number
  proposalsSubmitted: number
  proposalsApproved: number
  tokensContributed: number
  tasksCompleted: number
  lastUpdated: string
}

export interface Delegation {
  delegationId: string
  delegatedTo: string
  delegatedBy: string
  scope: string[]
  scopeInterpretation?: 'exact' | 'glob' | 'hierarchical'  // Module 37: how scope matching works
  expiresAt: string
  /** Optional: delegation is not valid before this timestamp (replay mitigation) */
  notBefore?: string
  spendLimit?: number
  spentAmount?: number
  maxDepth: number
  currentDepth: number
  createdAt: string
  /** Hash of the obligation IDs accepted with this delegation (Module 20) */
  obligationBundleHash?: string
  /** Optional: URL that gateways should poll for revocation status (enables future multi-gateway) */
  revocationCheckUrl?: string
  signature: string  // signed by delegator
}

export interface ActionReceipt {
  receiptId: string
  version: string
  timestamp: string
  agentId: string
  delegationId: string
  action: {
    type: string
    target: string
    method?: string
    scopeUsed: string
    spend?: { amount: number; currency: string }
  }
  result: {
    status: 'success' | 'failure' | 'partial'
    summary: string
  }
  delegationChain: string[]  // public key fingerprints from principal to executor
  signature: string  // signed by executing agent
  /** Optional: independent witness signature (notary pattern — witness ≠ executor) */
  witnessSignature?: string
  /** Optional: hash of previous receipt in chain (for append-only chain verification) */
  previousReceiptHash?: string
  /** If tombstoned (GDPR), payload is redacted but hash chain and signature preserved */
  tombstoned?: boolean
  tombstoneReason?: string
  /** Authorization context: links this receipt to the authorization that permitted execution.
   *  Separate from the receipt itself — the AuthorizationRef is compact; the full
   *  AuthorizationWitness is available for deep forensics via witnessId lookup. */
  authorizationRef?: import('./gateway.js').AuthorizationRef
  /** Receipt maturation: starts 'maturing', becomes 'finalized' after witness or TTL.
   *  Unwitnessed receipts are economically weaker than finalized ones. */
  finality?: import('./finality.js').FinalityState
  /** Full witness attestation (if witnessed) */
  witnessAttestation?: import('./gateway.js').WitnessAttestation
  /** Witness conflict record (if gateway and witness disagree) */
  witnessConflict?: import('./gateway.js').WitnessConflict
}

export interface RevocationRecord {
  revocationId: string
  delegationId: string
  revokedBy: string   // public key of original delegator
  revokedAt: string
  reason: string
  signature: string   // signed by original delegator
}

export interface DelegationStatus {
  valid: boolean
  revoked: boolean
  expired: boolean
  notYetValid: boolean
  depthExceeded: boolean
  revokedAt?: string
  errors: string[]
}

// ── v1.4: Cascade Revocation ──

export interface CascadeRevocationResult {
  rootRevocation: RevocationRecord
  cascadedRevocations: RevocationRecord[]
  totalRevoked: number
  chainDepth: number
}

export interface DelegationChainValidation {
  valid: boolean
  chainLength: number
  links: DelegationChainLink[]
  firstFailure?: {
    index: number
    delegationId: string
    reason: string
  }
}

export interface DelegationChainLink {
  delegationId: string
  delegatedBy: string
  delegatedTo: string
  depth: number
  status: DelegationStatus
}

export interface RevocationEvent {
  type: 'direct' | 'cascade' | 'agent_batch'
  revocation: RevocationRecord
  parentDelegationId?: string  // which parent triggered cascade
  batchAgentId?: string        // which agent triggered batch
}

export interface SignedPassport {
  passport: AgentPassport
  signature: string
  signedAt: string
}

export interface VerificationResult {
  valid: boolean
  errors: string[]
  warnings: string[]
  passport?: AgentPassport
}

export interface Challenge {
  challengeId: string
  nonce: string
  timestamp: string
  expiresAt: string
}

export interface ChallengeResponse {
  challengeId: string
  signature: string
  publicKey: string
}

export interface ReputationEvent {
  type: 'collaboration_completed' | 'proposal_submitted' | 'proposal_approved' |
        'tokens_contributed' | 'task_completed' | 'task_failed' | 'incident'
  quality?: number  // 0-1
  amount?: number
}

export interface CreatePassportOptions {
  agentId: string
  agentName: string
  ownerAlias: string
  mission: string
  capabilities: string[]
  runtime: RuntimeInfo
  expiresInDays?: number
  delegations?: Delegation[]
  metadata?: Record<string, unknown>
  beneficiary?: BeneficiaryInfo
  valuesFloor?: FloorReference
}

// ══════════════════════════════════════
// LAYER 2 — Human Values Floor
// ══════════════════════════════════════

// Graduated enforcement: what happens when a principle check fails.
//   inline — hard deny, agent cannot proceed
//   audit  — logged + flagged for human review, agent proceeds
//   warn   — surfaced immediately to caller, agent proceeds
// Extensions can escalate (warn→audit→inline) but never de-escalate.
export type EnforcementMode = 'inline' | 'audit' | 'warn'

export const ENFORCEMENT_ESCALATION_ORDER: Record<EnforcementMode, number> = {
  warn: 0,
  audit: 1,
  inline: 2
}

export interface FloorPrinciple {
  id: string                   // e.g. "F-001"
  name: string                 // e.g. "Traceability"
  principle: string            // natural language description
  enforcement: {
    mode: EnforcementMode      // graduated enforcement level
    technical?: boolean        // deprecated — use mode. Kept for backward compat.
    mechanism: string          // how it's enforced
    protocolRef?: string       // reference to spec
  }
  weight: 'mandatory' | 'strong_consideration' | 'advisory'
}

export interface FloorExtension {
  id: string                   // e.g. "ext-healthcare-v1"
  name: string
  domain: string
  version: string
  inherits: string             // e.g. "floor@0.1"
  additionalPrinciples: FloorPrinciple[]
}

export interface ValuesFloor {
  version: string
  schema: string
  lastUpdated: string
  governanceUri: string
  floor: FloorPrinciple[]
  extensions?: FloorExtension[]
  governance?: FloorGovernance
}

export interface FloorGovernance {
  amendmentProcess: string
  escalationRules: string[]
  versionHistory?: Array<{
    version: string
    date: string
    changes: string
  }>
}

export interface FloorReference {
  version: string              // which floor version agent attests to
  extensions: string[]         // extension IDs the agent adheres to
  attestationId?: string       // reference to FloorAttestation
}

export interface FloorAttestation {
  attestationId: string
  agentId: string
  publicKey: string
  floorVersion: string
  extensions: string[]
  attestedAt: string
  expiresAt: string
  // The agent signs a commitment: "I will reference these principles during reasoning"
  commitment: string
  signature: string            // Ed25519 signed by agent
}

export interface ComplianceCheck {
  principleId: string
  principleName: string
  status: 'enforced' | 'attested' | 'violation' | 'unverifiable'
  enforcementMode?: EnforcementMode  // graduated enforcement context
  evidence?: string            // receipt ID or delegation ID proving compliance
  detail: string
}

export interface ComplianceReport {
  reportId: string
  agentId: string
  floorVersion: string
  period: { from: string; to: string }
  receiptsAnalyzed: number
  checks: ComplianceCheck[]
  overallCompliance: number    // 0.0 - 1.0
  generatedAt: string
  signature: string            // signed by the verifier
}

export interface SharedGround {
  floorVersion: string | null
  sharedExtensions: string[]
  agentA: string               // public key
  agentB: string               // public key
  negotiatedAt: string
  compatible: boolean
  incompatibilityReasons: string[]
}

// ══════════════════════════════════════
// LAYER 3 — Beneficiary Attribution
// ══════════════════════════════════════

export interface BeneficiaryInfo {
  principalId: string          // human beneficiary identifier
  principalPublicKey?: string  // if human has a keypair for verification
  relationship: 'creator' | 'employer' | 'delegator' | 'owner'
  registeredAt: string
}

export interface BeneficiaryTrace {
  traceId: string
  receiptId: string
  executorAgent: string        // who did the work
  beneficiary: string          // human principal
  chain: DelegationHop[]       // full path from executor to beneficiary
  totalDepth: number
  verified: boolean
}

export interface DelegationHop {
  from: string                 // public key
  to: string                   // public key
  delegationId: string
  scope: string[]
  depth: number
}

export interface AttributionEntry {
  receiptId: string
  agentId: string
  action: string               // action type
  scopeUsed: string
  spend: number
  resultStatus: string
  weight: number               // computed contribution weight
  timestamp: string
}

export interface AttributionReport {
  reportId: string
  beneficiary: string          // human principal ID
  agentId: string
  period: { from: string; to: string }
  entries: AttributionEntry[]
  totalWeight: number
  receiptCount: number
  merkleRoot: string           // commitment to all receipts
  entriesHash: string          // SHA-256 of computed entries (tamper detection)
  generatedAt: string
  signature: string            // signed by generating agent
}

// Merkle proof: prove a single receipt exists in the attribution set
export interface MerkleProof {
  receiptHash: string          // hash of the receipt being proven
  root: string                 // merkle root
  proof: MerkleProofNode[]     // path from leaf to root
  index: number                // leaf position
  verified?: boolean
}

export interface MerkleProofNode {
  hash: string
  position: 'left' | 'right'  // which side this sibling is on
}
