// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// ══════════════════════════════════════════════════════════════════
// Execution Attestation — Checkpoint 3 Implementation
// ══════════════════════════════════════════════════════════════════
// The missing piece: proof of what was EXECUTED, not just authorized.
//
// Architecture:
//   Checkpoint 1: PolicyReceipt (what was AUTHORIZED)  — already shipped
//   Checkpoint 2: CompoundDigest (binding intent→receipt) — already shipped
//   Checkpoint 3: ExecutionAttestation (what ACTUALLY RAN) — this file
//
// The sandbox/container/runtime calls createExecutionAttestation()
// after tool execution, signing with its own key (not the agent's).
// Verifiers call verifyExecutionAttestation() to check the attestation
// signature and detect drift between intent and execution.
//
// References:
//   - desiorac qntm#6 "Execution Attestation Interface spec v0.1"
//   - QueBallSharken + desiorac OWASP#802 gap identification
//   - agent-morrow authorized_profile_hash pattern (W3C PR #33)
// ══════════════════════════════════════════════════════════════════

import { createHash, randomUUID } from 'node:crypto'
import { sign, verify } from '../crypto/keys.js'
import { canonicalize } from './canonical.js'
import type {
  ExecutionAttestation,
  ExecutionAttestationVerification,
  ExecutionDrift,
  ExecutionDriftSeverity,
  CreateExecutionAttestationInput,
  DriftClassificationRule,
} from '../types/execution-attestation.js'
import { DEFAULT_DRIFT_RULES } from '../types/execution-attestation.js'

// ── SHA-256 helper ──
function sha256(input: string): string {
  return createHash('sha256').update(input).digest('hex')
}

// ══════════════════════════════════════════════════════════════════
// createExecutionAttestation
// ══════════════════════════════════════════════════════════════════
// Called by the sandbox/runtime AFTER tool execution.
// The attestor signs with its own key — the agent cannot forge this.
//
// Flow:
//   1. Hash actual parameters and result
//   2. Hash declared intent parameters
//   3. Compare parameter hashes to detect drift
//   4. Classify drift severity using rules
//   5. Sign the attestation with attestor's key
export function createExecutionAttestation(
  input: CreateExecutionAttestationInput,
  attestorPrivateKey: string,
  opts?: { driftRules?: DriftClassificationRule[] }
): ExecutionAttestation {
  const rules = opts?.driftRules ?? DEFAULT_DRIFT_RULES

  // Hash what actually executed
  const parameterHash = sha256(canonicalize(input.actualParameters))
  const resultHash = sha256(canonicalize(input.actualResult))

  // Hash what was declared at intent time
  const intentParameterHash = sha256(canonicalize(input.intentParameters))

  // Detect drift
  const match = parameterHash === intentParameterHash
  const drift = match ? null : classifyDrift(
    input.intentParameters, input.actualParameters, rules
  )

  const now = new Date().toISOString()

  // Build attestation body (everything except signature)
  const body = {
    executionId: randomUUID(),
    agentId: input.agentId,
    attestorId: input.attestorId,
    attestorType: input.attestorType,
    toolName: input.toolName,
    parameterHash,
    resultHash,
    policyReceiptId: input.policyReceiptId,
    executionFrameId: input.executionFrameId,
    intentParameterHash,
    match,
    drift,
    executionStartedAt: input.executionStartedAt,
    executionCompletedAt: input.executionCompletedAt,
    attestedAt: now,
  }

  // Sign the entire body with the attestor's key
  const canonical = canonicalize(body)
  const signature = sign(canonical, attestorPrivateKey)

  return { ...body, signature }
}

// ══════════════════════════════════════════════════════════════════
// verifyExecutionAttestation
// ══════════════════════════════════════════════════════════════════
// Any verifier can check:
//   1. Attestor signature (Ed25519 over canonical body)
//   2. Receipt binding (policyReceiptId + executionFrameId present)
//   3. Parameter match consistency (match flag agrees with hashes)
//   4. Timing sanity (execution completed after it started)
export function verifyExecutionAttestation(
  attestation: ExecutionAttestation,
  attestorPublicKey: string,
  receipt?: { policyReceiptId: string; executionFrameId?: string }
): ExecutionAttestationVerification {
  const errors: string[] = []

  // 1. Verify attestor signature
  const { signature, ...body } = attestation
  const canonical = canonicalize(body)
  const signatureValid = verify(canonical, signature, attestorPublicKey)
  if (!signatureValid) errors.push('Attestor signature invalid')

  // 2. Receipt binding
  let receiptBindingValid = true
  if (receipt) {
    if (attestation.policyReceiptId !== receipt.policyReceiptId) {
      receiptBindingValid = false
      errors.push(`Receipt ID mismatch: attestation=${attestation.policyReceiptId}, receipt=${receipt.policyReceiptId}`)
    }
    if (receipt.executionFrameId && attestation.executionFrameId !== receipt.executionFrameId) {
      receiptBindingValid = false
      errors.push(`Frame ID mismatch: attestation=${attestation.executionFrameId}, receipt=${receipt.executionFrameId}`)
    }
  }

  // 3. Parameter match consistency
  const parameterMatch = attestation.parameterHash === attestation.intentParameterHash
  if (parameterMatch !== attestation.match) {
    errors.push(`Match flag inconsistent: hashes ${parameterMatch ? 'match' : 'differ'} but match=${attestation.match}`)
  }

  // 4. Timing sanity
  const start = new Date(attestation.executionStartedAt).getTime()
  const end = new Date(attestation.executionCompletedAt).getTime()
  const attested = new Date(attestation.attestedAt).getTime()
  const timingValid = end >= start && attested >= start
  if (!timingValid) {
    errors.push('Timing invalid: execution completed before start or attested before start')
  }

  return {
    valid: errors.length === 0,
    signatureValid,
    receiptBindingValid,
    parameterMatch,
    timingValid,
    drift: attestation.drift,
    errors,
  }
}

// ══════════════════════════════════════════════════════════════════
// detectExecutionDrift
// ══════════════════════════════════════════════════════════════════
// Standalone drift detection: given an attestation, return the drift
// analysis. Useful when you already have an attestation and want to
// re-classify drift with different rules.
export function detectExecutionDrift(
  attestation: ExecutionAttestation,
  rules?: DriftClassificationRule[]
): ExecutionDrift | null {
  return attestation.drift
}

// ══════════════════════════════════════════════════════════════════
// classifyDrift (internal)
// ══════════════════════════════════════════════════════════════════
// Compare intent vs actual parameters field-by-field and classify
// each difference using the drift rules.
function classifyDrift(
  intentParams: Record<string, unknown>,
  actualParams: Record<string, unknown>,
  rules: DriftClassificationRule[]
): ExecutionDrift {
  const allKeys = new Set([
    ...Object.keys(intentParams),
    ...Object.keys(actualParams),
  ])

  const driftFields: ExecutionDrift['fields'] = []

  for (const key of allKeys) {
    const intentVal = intentParams[key]
    const actualVal = actualParams[key]
    const intentHash = sha256(canonicalize(intentVal ?? null))
    const actualHash = sha256(canonicalize(actualVal ?? null))

    if (intentHash !== actualHash) {
      driftFields.push({
        field: key,
        intentValueHash: intentHash,
        executionValueHash: actualHash,
      })
    }
  }

  // Classify severity: highest severity wins
  const severityOrder: ExecutionDriftSeverity[] = ['none', 'benign', 'suspicious', 'critical']
  let maxSeverity: ExecutionDriftSeverity = 'none'

  for (const df of driftFields) {
    const rule = rules.find(r => r.field === df.field)
      ?? rules.find(r => r.field === '*')
    const sev = rule?.severity ?? 'suspicious'
    if (severityOrder.indexOf(sev) > severityOrder.indexOf(maxSeverity)) {
      maxSeverity = sev
    }
  }

  return { fields: driftFields, severity: maxSeverity }
}
