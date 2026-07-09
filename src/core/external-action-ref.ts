// Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// ══════════════════════════════════════════════════════════════════
// External action_ref (action-ref-v1-jcs-sha256): Cross-Ecosystem Correlation Key
// ══════════════════════════════════════════════════════════════════
// This is the cross-ecosystem correlation key. It is NOT the APS-native
// action_ref.
//
// The APS-native action_ref (computeActionRef, draft-pidlisnyi-aps-01 §4.1)
// and this external key are distinct primitives with intentionally different
// preimages. Use computeActionRef for APS receipts and request equivalence.
// Use this helper only to correlate an APS action with the external
// action-ref-v1 form computed by independent ecosystem implementations
// (see docs/specs/action-ref-v1.md and conformance/action-ref-v1/).
//
// Differences from the APS-native §4.1 form:
//   - snake_case preimage keys {action_type, agent_id, scope, timestamp}
//   - scope is a single string, not the APS multi-scope array
//   - timestamp is millisecond RFC 3339 (exactly three fractional digits and
//     a Z suffix), hashed as opaque bytes and never normalized
// ══════════════════════════════════════════════════════════════════

import { canonicalHashJCS } from './canonical-jcs.js'

// Canonical external timestamp shape: RFC 3339 UTC, exactly three
// fractional-second digits, mandatory Z.
const EXTERNAL_TS = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/

/** Input to computeExternalActionRefV1. */
export interface ExternalActionRefV1Input {
  /** External action type, e.g. "payment.send". */
  actionType: string
  /** Agent identifier as the external ecosystem expects it. */
  agentId: string
  /** A single scope string. This differs from the APS-native action_ref,
   *  whose scopeRequired is a multi-scope array. */
  scope: string
  /** Millisecond RFC 3339 UTC instant (YYYY-MM-DDTHH:MM:SS.mmmZ). A canonical
   *  string is hashed as-is; a Date is rendered to the canonical form via
   *  toISOString. Any other string shape is rejected rather than coerced, so
   *  acceptance matches the aps-broker verifier. */
  timestamp: string | Date
}

function externalTimestamp(ts: string | Date): string {
  if (ts instanceof Date) {
    if (Number.isNaN(ts.getTime())) {
      throw new Error('computeExternalActionRefV1: invalid Date timestamp')
    }
    return ts.toISOString()
  }
  if (!EXTERNAL_TS.test(ts)) {
    throw new Error(
      `computeExternalActionRefV1: timestamp must be RFC 3339 UTC with three fractional digits and a Z suffix (YYYY-MM-DDTHH:MM:SS.mmmZ), got ${JSON.stringify(ts)}`,
    )
  }
  return ts
}

/**
 * Compute the external cross-ecosystem correlation key
 * (action-ref-v1-jcs-sha256): lowercase-hex SHA-256 of the RFC 8785 JCS
 * canonicalization of {action_type, agent_id, scope, timestamp}.
 *
 * This is NOT the APS-native action_ref. See the file header for the preimage
 * differences. Use computeActionRef for APS-native receipts and equivalence.
 *
 * Returns: lowercase hex SHA-256 digest.
 */
export function computeExternalActionRefV1(input: ExternalActionRefV1Input): string {
  return canonicalHashJCS({
    action_type: input.actionType,
    agent_id: input.agentId,
    scope: input.scope,
    timestamp: externalTimestamp(input.timestamp),
  })
}
