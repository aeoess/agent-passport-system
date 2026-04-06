// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// Agent Attestation Architecture — Type Definitions
// Result of 3-round consilium (Claude + GPT + Gemini + Portal ground truth)
//
// Design principles:
//   P1: Memory, not gates — system REMEMBERS, never blocks
//   P2: Server observes, agent doesn't declare (Tier 0 captured silently)
//   P3: Protocol defines WHAT signals exist (public). Gateway defines HOW they're weighted (private)
//   P4: Every signal tagged with provenance and stability
//   P5: Grades reflect attestation richness, not admission rights
//   P6: Lineage links are scoped and private (four HMAC-derived links)
//   P7: Recovery is first-class (requires cryptographic proof, not just env matching)
//   P8: Evidence designed for portability and third-party review

// ── Passport Grade ──
// Based on attestation richness, NOT admission rights. Grade 0 agents still work.
// Grades are mutable: can be upgraded/downgraded post-issuance as new evidence arrives.
export type PassportGrade = 0 | 1 | 2 | 3;

export const PASSPORT_GRADE_LABELS: Record<PassportGrade, string> = {
  0: 'self_signed',         // bare keypair, no issuer involvement
  1: 'issuer_countersigned', // AEOESS processed the request
  2: 'runtime_bound',       // issuer + challenge-response + trusted attestation + lineage tag
  3: 'principal_bound',     // runtime_bound + verified human/org principal
};

// ── Evidence Quality (A2A#1712 — VCOne-AI) ──
// Classifies the QUALITY of evidence supporting a passport's key binding,
// independent of the identity method prefix. A did:key with TPM attestation
// reaches 'infrastructure' quality; a SPIFFE SVID from a misconfigured cluster
// without verification does not.
export type EvidenceQuality =
  | 'none'              // bare keypair, no proof of generation/storage
  | 'issuer_vouched'    // third party signed the key (countersignature)
  | 'infrastructure'    // evidence of hardware/runtime binding (TPM, SPIFFE, TEE)
  | 'principal_bound';  // verified human or legal entity linked to key

// ── Attestation Provenance (Four-Tier Model) ──
// Universal convergence across all consilium models
export type AttestationProvenance =
  | 'observed'                // Tier 0: server saw it (TLS fingerprint, IP/ASN, timing)
  | 'infrastructure_attested' // Tier 1: sandbox/runtime gateway signed it
  | 'provider_attested'       // Tier 2: third party confirmed it (OAuth, cloud tenant)
  | 'self_declared';          // Tier 3: agent claims it (mission, capabilities)

// ── Signal Stability ──
// How long does this signal remain constant?
export type SignalStability =
  | 'ephemeral'    // changes every request (nonce, timestamp)
  | 'session'      // stable within one session (connection ID)
  | 'runtime'      // stable within one container/VM lifecycle (boot epoch)
  | 'account'      // stable across runtimes for same owner (OAuth subject)
  | 'long_lived';  // stable indefinitely (public key, DID)

// ── Verification Status ──
export type VerificationStatus =
  | 'verified'     // cryptographically confirmed (signature checked)
  | 'observed'     // server recorded it (no cryptographic proof)
  | 'declared'     // agent claims it, unverified
  | 'failed';      // verification attempted, failed

// ── Attested Signal ──
// A single signal with full metadata. Used for Tier 1-3 signals where
// you don't know in advance what signals different providers will send.
// Tier 0 observed signals use the closed ObservedContext instead.
export interface AttestedSignal {
  key: string;                       // e.g. "runtime.boot_epoch", "provider.oauth_issuer"
  valueHash: string;                 // SHA-256 hash of the actual value (raw value NOT in public record)
  provenance: AttestationProvenance;
  verificationStatus: VerificationStatus;
  stability: SignalStability;
  attester?: string;                 // who signed/observed this signal (DID or URI)
  observedAt: string;                // ISO 8601 timestamp
  expiresAt?: string;                // when this signal becomes stale
  evidenceRef?: string;              // signature blob or receipt ID for verification
}

// ── Observed Context (Tier 0 — Closed Schema) ──
// Consilium correction: Tier 0 signals use a closed interface, not generic AttestedSignal[].
// The signals observable at TCP/TLS termination are finite and known.
// This prevents implementation fragmentation ("runtime.boot_epoch" vs "bootEpoch").
export interface ObservedContext {
  clientFingerprintHash?: string;     // JA3 or TLS fingerprint hash
  ipHash?: string;                    // SHA-256 of source IP (privacy: never store raw IP)
  dailyIpHash?: string;              // SHA-256(IP + date) — clusters same-day requests
  asnHash?: string;                  // SHA-256 of ASN number
  tlsJa3Hash?: string;              // JA3 hash of TLS ClientHello
  connectionTimingMs?: number;       // time from TCP SYN to first payload byte
  issuanceVelocity?: number;         // passports issued from this IP in last hour
  transportType?: string;            // 'sse' | 'stdio' | 'http' | 'websocket'
  connectionId?: string;             // opaque session/connection identifier
  requestPayloadFingerprint?: string; // hash of canonical request structure (field names, nesting, presence of optionals)
  mcpClientId?: string;              // MCP client identifier if connecting via MCP
  mcpCapabilitiesHash?: string;      // hash of declared MCP capabilities
  userAgentHash?: string;            // hash of User-Agent string
  observedAt: string;                // ISO 8601 timestamp when observation was made
}

// ── Runtime Attestation (Tier 1 — Challenge-Response Bound) ──
// Infrastructure/sandbox gateway signs this after a challenge-response exchange.
// The nonce binds the attestation to a specific issuance request.
export interface RuntimeAttestation {
  attester: string;                  // URI of attesting gateway (e.g. "openshell://gateway-abc")
  nonce: string;                     // challenge nonce from issuer (binds to specific request)
  publicKeyHash: string;             // SHA-256 of the passport's public key (binds to specific key)
  runtimeClass?: string;             // 'sandbox' | 'vm' | 'bare_metal' | 'ci_runner' | 'serverless'
  bootEpoch?: string;                // ISO 8601 when the runtime started
  runtimeInstanceIdHash?: string;    // SHA-256 of container/VM ID
  storageIdentityHash?: string;      // SHA-256 of persistent volume/workspace ID
  processIdentityHash?: string;      // SHA-256 of process tree signature
  networkClass?: string;             // 'isolated' | 'nat' | 'public' | 'mesh'
  workspaceManifestHash?: string;    // hash of workspace file manifest (not content)
  issuedAt: string;                  // ISO 8601
  expiresAt: string;                 // ISO 8601
  signature: string;                 // Ed25519 signature by the attesting gateway
  /** Typed staleness metadata (A2A#1712). Snapshot (TPM) vs rotating (SPIFFE) vs static. */
  freshness?: import('./passport.js').AttestationFreshness
}

// ── Provider Attestation (Tier 2 — Third-Party Confirmation) ──
// Third-party providers confirm identity claims about the agent.
export interface ProviderAttestation {
  provider: string;                  // OAuth issuer URL, cloud provider, MCP host
  subjectClass: string;              // 'tenant' | 'account' | 'project' | 'host' | 'organization'
  subjectIdHash: string;             // SHA-256 of the subject identifier
  nonce?: string;                    // optional challenge binding
  publicKeyHash?: string;            // optional key binding
  verificationMethod?: string;       // 'oauth2' | 'jwt' | 'api_key' | 'mtls' | 'webhook'
  issuedAt: string;                  // ISO 8601
  expiresAt?: string;                // ISO 8601 (some attestations don't expire)
  signature?: string;                // provider's signature (if they support signing)
  /** Typed staleness metadata (A2A#1712). */
  freshness?: import('./passport.js').AttestationFreshness
}

// ── Issuance Evidence Record ──
// Raw evidence collected during issuance. Separated from assessment (GPT consilium correction).
// Raw facts and issuer opinions must not blur together.
export interface IssuanceEvidenceRecord {
  requestId: string;                          // unique issuance request ID
  requestedAt: string;                        // ISO 8601

  // Tier 0: Server-observed (closed schema, agent didn't provide these)
  observed: ObservedContext;

  // Tier 1: Infrastructure attestations (if available)
  runtimeAttestations: RuntimeAttestation[];

  // Tier 2: Provider attestations (if available)
  providerAttestations: ProviderAttestation[];

  // Tier 3: Agent's own claims (open schema)
  selfDeclaredSignals: AttestedSignal[];

  // Continuity (recovery support)
  priorPassportRef?: string;                   // previous passport ID if claimed
  priorContinuityProof?: string;              // signed proof linking to prior passport key
}

// ── Issuance Assessment ──
// Issuer's computed evaluation of the evidence. Separated from raw evidence.
// This is what the issuer CONCLUDED, not what was OBSERVED.
export interface IssuanceAssessment {
  passportGrade: PassportGrade;
  attestationBundleHash: string;               // SHA-256 of all evidence data
  flags: AttestationFlag[];
  verificationResults: SignalVerificationResult[];

  // Derived signals (GPT consilium addition): computed by issuer from raw evidence
  derivedSignals?: DerivedSignal[];

  // Grade mutability: when/why grade was last changed
  gradeHistory?: GradeChange[];

  assessedAt: string;                          // ISO 8601
}

// ── Derived Signal ──
// Computed by issuer from other evidence, not directly observed or declared.
// Often more valuable than raw signals.
export interface DerivedSignal {
  key: string;                                 // e.g. "issuance_age_ms", "first_action_delay_bucket"
  value: string;                               // computed value (may be hashed for privacy)
  derivedFrom: string[];                       // which evidence fields contributed
  computedAt: string;                          // ISO 8601
}

// ── Signal Verification Result ──
// Per-signal verification outcome from Phase 3.
export interface SignalVerificationResult {
  signalKey: string;                           // which signal was verified
  status: VerificationStatus;
  detail?: string;                             // e.g. "signature valid against known gateway key"
  verifiedAt: string;
}

// ── Grade Change Record ──
// Grades are mutable (Gemini consilium correction). Track when/why grade changed.
export interface GradeChange {
  from: PassportGrade;
  to: PassportGrade;
  reason: string;                              // e.g. "cluster_analysis_downgrade", "provider_attestation_added"
  changedAt: string;                           // ISO 8601
}

// ── Attestation Flags ──
// Coarse public flags on the passport. Partners use these for quick decisions.
// Detailed posture stays private in the gateway.
export type AttestationFlag =
  | 'issuer_bound'        // issuer countersigned (Grade >= 1)
  | 'runtime_bound'       // challenge-response infrastructure attestation (Grade >= 2)
  | 'provider_bound'      // third-party identity confirmation (Grade >= 2)
  | 'principal_bound'     // verified human/org principal (Grade >= 3)
  | 'recovery_linked'     // passport linked to a prior passport via recovery
  | 'continuity_proven';  // cryptographic proof of continuity from prior key

// ── Issuance Context ──
// The complete issuance record combining evidence + assessment.
// Stored by issuer/gateway. This is the permanent record of what happened at issuance.
export interface IssuanceContext {
  evidence: IssuanceEvidenceRecord;
  assessment: IssuanceAssessment;
}

// ── Passport Attestation Summary ──
// What goes ON the public passport. Minimal by design.
// Partners get grade + flags. Detailed posture requires gateway query.
// (Gemini consilium: keep signal weights, cluster risk, raw data PRIVATE)
export interface PassportAttestationSummary {
  passportGrade: PassportGrade;
  attestationBundleHash?: string;              // hash of all evidence (verifiable without seeing evidence)
  flags: AttestationFlag[];
}

// ── Issuance Challenge ──
// Server sends this in Phase 1 of the 5-phase issuance flow.
// Binds the challenge to a specific key and specifies what attestations are desired.
export interface IssuanceChallenge {
  challengeId: string;                         // unique challenge ID
  nonce: string;                               // random, single-use
  requiredPublicKeyHash: string;               // SHA-256 of the passport's public key (binds challenge to key)
  requestedAttestationClasses: AttestationClass[];  // what Tier 1/2 attestations are desired
  expiresAt: string;                           // ISO 8601 (challenge valid for N seconds)
  issuedAt: string;                            // ISO 8601
}

// ── Attestation Class ──
// What types of attestation the issuer wants. Used in IssuanceChallenge.
export type AttestationClass =
  | 'runtime'              // Tier 1: sandbox/infrastructure attestation
  | 'provider'             // Tier 2: third-party identity provider
  | 'principal'            // verified human/org endorsement
  | 'workspace';           // workspace manifest checkpoint

// ── Issuance Challenge Response ──
// Agent returns this in Phase 2 with whatever attestations it has.
export interface IssuanceChallengeResponse {
  challengeId: string;
  runtimeAttestations?: RuntimeAttestation[];
  providerAttestations?: ProviderAttestation[];
  selfDeclaredSignals?: AttestedSignal[];
  priorPassportRef?: string;
  priorContinuityProof?: string;               // signed with prior passport key
  workspaceManifestHash?: string;
}

// ── Workspace Manifest ──
// Hash of workspace STRUCTURE (not content). Consilium corrections:
// - Gemini: single hash is weak, use manifest not content hash
// - GPT: must be infrastructure-attested (Tier 1), not self-declared
// - All: longitudinal series > single snapshot
export interface WorkspaceManifest {
  entries: WorkspaceManifestEntry[];
  totalFiles: number;
  totalSizeBytes: number;
  computedAt: string;                          // ISO 8601
  manifestHash: string;                        // SHA-256 of sorted canonical entries
}

export interface WorkspaceManifestEntry {
  pathHash: string;                            // SHA-256 of relative path (privacy: no raw paths)
  sizeBytes: number;
  lastModifiedBucket: string;                  // floored to hour (privacy: no exact timestamps)
}

// ── Workspace Checkpoint ──
// Periodic infrastructure-signed workspace state. The chain of checkpoints
// is the real "proof of history" (not a single hash).
export interface WorkspaceCheckpoint {
  manifestHash: string;                        // workspace manifest hash at this point
  observedAt: string;                          // ISO 8601
  totalFiles: number;
  totalSizeBytes: number;
  signature: string;                           // infrastructure gateway signature
  attester: string;                            // who signed this checkpoint
  priorCheckpointHash?: string;                // chain link to previous checkpoint
}

// ── Recovery Request ──
// Mandatory correction from all consilium models:
// Recovery MUST require cryptographic proof (prior key signature or recovery key).
// Environment matching = LOOKUP (find dossier). Crypto proof = AUTHORITY (authorize recovery).
export interface RecoveryRequest {
  // Lookup signals (used to FIND the matching dossier, not to AUTHORIZE recovery)
  environmentSignals: Partial<ObservedContext>;
  workspaceManifestHash?: string;
  runtimeClass?: string;

  // Authority signals (at least one REQUIRED for actual recovery)
  priorKeySignature?: string;                  // sign nonce with original passport private key
  recoveryKeySignature?: string;               // sign nonce with pre-committed recovery key
  principalAuthorization?: string;             // principal-signed recovery approval
}

// ── Recovery Result ──
export interface RecoveryResult {
  matched: boolean;
  matchedPassportId?: string;
  confidenceSignals: string[];                 // which signals contributed to the match
  recoveryAuthorized: boolean;                 // false if no crypto proof provided
  authorizationMethod?: 'prior_key' | 'recovery_key' | 'principal';
}


// ══════════════════════════════════════════════════════════════════
// Behavioral Evaluation Types (Issue #9 — lowkey-divine schema)
// Separates evaluation INPUT conditions from evaluation OUTPUT results.
// ══════════════════════════════════════════════════════════════════

/** Input conditions for a behavioral evaluation. Immutable after creation. */
export interface EvaluationContext {
  substrate: string                    // model/runtime identifier
  responseFormatSchema: string         // expected output format
  normalizationMethod: string          // how cross-substrate results are aligned
  evaluationProtocolVersion: string    // sha256:<hash> of methodology
  sampleSize: number                   // MANDATORY: 1 run != 50 runs
  evaluatedAt: string                  // ISO 8601
}

/** Output of a behavioral evaluation. References context by hash. */
export interface BehavioralAttestationResult {
  evaluationContextHash: string        // sha256 of canonical EvaluationContext
  dimensionScores: Record<string, {
    score: number
    weight: number                     // MUST reconstruct aggregate via weights
  }>
  aggregateScore: number
  classification: 'hold' | 'bend' | 'break'
  confidence: number                   // 0.0-1.0
  formatArtifactCorrected: boolean
  dimensionalInversionDetected: boolean  // MUST be derivable from dimensionScores
}
