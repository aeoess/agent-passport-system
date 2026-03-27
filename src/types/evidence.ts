// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// ══════════════════════════════════════════════════════════════════
// Typed Evidence — Structured evidence references for disputes
// ══════════════════════════════════════════════════════════════════
// Evidence is not string[]. Each reference carries its type, source,
// and optional weight. This makes dispute automation and audit possible.
// ══════════════════════════════════════════════════════════════════

/** Evidence type taxonomy */
export type EvidenceType =
  | 'receipt'              // ActionReceipt reference
  | 'witness_attestation'  // WitnessAttestation reference
  | 'delivery_artifact'    // Deliverable from coordination module
  | 'external_log'         // External system log
  | 'human_statement'      // Human-provided testimony
  | 'measurement'          // Automated measurement (fidelity, performance)
  | 'replay_trace'         // Execution replay record
  | 'checkpoint_proof'     // Gateway checkpoint reference

export interface TypedEvidence {
  evidenceId: string
  type: EvidenceType
  /** ID of the referenced artifact */
  artifactId: string
  /** Who submitted this evidence */
  submittedBy: string
  submittedAt: string
  /** Optional evidence weight (0-1). Higher = stronger evidence. */
  weight?: number
}
