// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// ══════════════════════════════════════════════════════════════════
// Credential Check Policy — verifyOnAccept and evaluateCredentialCheck
// ══════════════════════════════════════════════════════════════════

import { verifyDelegation } from '../../core/delegation.js'
import type { Delegation } from '../../types/passport.js'
import type {
  CredentialCheckPolicy,
  CredentialCheckMode,
  CredentialCheckResult,
  AcceptanceStamp,
} from './types.js'

/**
 * Resolve the effective check mode for a delegation. Defaults to
 * 'on-process' when no policy is set — backward compatible with the
 * existing APS evaluation path.
 */
export function resolveCheckMode(delegation: Delegation): CredentialCheckMode {
  return delegation.credentialCheckPolicy?.mode ?? 'on-process'
}

/**
 * Run the full acceptance-time check pipeline on a delegation. Verifies
 * the signature and expiry. On success, returns an AcceptanceStamp the
 * verifying party can persist and present at process time.
 *
 * For policies of mode 'on-accept' or 'both', this stamp is required at
 * process time. For 'on-process', the stamp is ignored entirely.
 */
export function verifyOnAccept(opts: {
  delegation: Delegation
  /** Identifier of the party performing the acceptance check (e.g. gateway id). */
  verifierId?: string
  /** Override the stamp timestamp (test fixtures). Defaults to now. */
  verifiedAt?: string
}): { valid: boolean; errors: string[]; stamp?: AcceptanceStamp } {
  const errors: string[] = []
  const status = verifyDelegation(opts.delegation)

  if (!status.valid) {
    errors.push(...(status.errors || ['Delegation signature invalid']))
  }
  if (status.expired) {
    errors.push('Delegation expired at acceptance time')
  }
  if (status.revoked) {
    errors.push('Delegation revoked at acceptance time')
  }

  if (errors.length > 0) {
    return { valid: false, errors }
  }

  const stamp: AcceptanceStamp = {
    delegation_id: opts.delegation.delegationId,
    verified_at: opts.verifiedAt ?? new Date().toISOString(),
    ...(opts.verifierId ? { verifier_id: opts.verifierId } : {}),
  }

  return { valid: true, errors: [], stamp }
}

/**
 * Evaluate a credential against its check policy.
 *
 * Inputs:
 *   - delegation: the credential being evaluated
 *   - acceptanceStamp: the stamp produced by verifyOnAccept (if any)
 *   - liveStateValid: result of the caller's live revocation/state check.
 *     For mode 'on-accept' this is ignored. For 'on-process' it is
 *     authoritative. For 'both' it is required AND the acceptance stamp
 *     is also required.
 *
 * Returns a CredentialCheckResult that the caller uses to decide whether
 * to permit the action and whether further live checks are still needed.
 */
export function evaluateCredentialCheck(opts: {
  delegation: Delegation
  acceptanceStamp?: AcceptanceStamp
  liveStateValid: boolean
  now?: Date
}): CredentialCheckResult {
  const mode = resolveCheckMode(opts.delegation)
  const policy = opts.delegation.credentialCheckPolicy
  const now = opts.now ?? new Date()

  // ── Mode: on-process ─────────────────────────────────────────
  // Default behavior. Live state is authoritative. Stamp ignored.
  if (mode === 'on-process') {
    if (!opts.liveStateValid) {
      return {
        permitted: false,
        mode,
        requiresLiveCheck: true,
        denialCode: 'PROCESS_TIME_INVALID',
        reason: 'Live state check failed (revocation or expiry detected at process time)',
      }
    }
    return { permitted: true, mode, requiresLiveCheck: true }
  }

  // ── Modes that require an acceptance stamp ──────────────────
  // 'on-accept' and 'both' both require the stamp.
  if (!opts.acceptanceStamp) {
    return {
      permitted: false,
      mode,
      requiresLiveCheck: false,
      denialCode: 'CREDENTIAL_NOT_ACCEPTED',
      reason: `Credential check policy is "${mode}" but no acceptance stamp is on file for delegation ${opts.delegation.delegationId}`,
    }
  }

  // Stamp must reference this delegation
  if (opts.acceptanceStamp.delegation_id !== opts.delegation.delegationId) {
    return {
      permitted: false,
      mode,
      requiresLiveCheck: false,
      denialCode: 'CREDENTIAL_NOT_ACCEPTED',
      reason: `Acceptance stamp delegation_id (${opts.acceptanceStamp.delegation_id}) does not match delegation (${opts.delegation.delegationId})`,
    }
  }

  // Check stamp staleness against max_acceptance_age (if set)
  if (typeof policy?.max_acceptance_age === 'number' && policy.max_acceptance_age >= 0) {
    const stampDate = new Date(opts.acceptanceStamp.verified_at)
    if (Number.isNaN(stampDate.getTime())) {
      return {
        permitted: false,
        mode,
        requiresLiveCheck: false,
        denialCode: 'CREDENTIAL_ACCEPT_STALE',
        reason: `Acceptance stamp has invalid timestamp: ${opts.acceptanceStamp.verified_at}`,
      }
    }
    const ageSeconds = (now.getTime() - stampDate.getTime()) / 1000
    if (ageSeconds > policy.max_acceptance_age) {
      return {
        permitted: false,
        mode,
        requiresLiveCheck: false,
        denialCode: 'CREDENTIAL_ACCEPT_STALE',
        reason: `Acceptance stamp is ${Math.floor(ageSeconds)}s old, exceeds max_acceptance_age of ${policy.max_acceptance_age}s`,
      }
    }
  }

  // ── Mode: on-accept ─────────────────────────────────────────
  // Trust the snapshot. Skip live check. Caller may still run it for
  // observability but the result is not authoritative for this gate.
  if (mode === 'on-accept') {
    return { permitted: true, mode, requiresLiveCheck: false }
  }

  // ── Mode: both ─────────────────────────────────────────
  // Acceptance stamp passed. Now require live state check.
  if (!opts.liveStateValid) {
    return {
      permitted: false,
      mode,
      requiresLiveCheck: true,
      denialCode: 'PROCESS_TIME_INVALID',
      reason: 'Live state check failed at process time despite valid acceptance stamp',
    }
  }
  return { permitted: true, mode, requiresLiveCheck: true }
}
