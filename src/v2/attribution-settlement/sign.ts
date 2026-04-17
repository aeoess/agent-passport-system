// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// ══════════════════════════════════════════════════════════════════
// Attribution Settlement — signing (Build C)
// ══════════════════════════════════════════════════════════════════
// Ed25519 signature over the canonical JSON of the settlement record
// minus its `signature` field. Mirrors Build A's envelope-signing
// pattern (canonicalize → utf-8 → sign). The Python port
// (agent_passport/v2/attribution_settlement/sign.py) reproduces the
// exact bytes so TS-signed records verify in Python and vice versa.
// ══════════════════════════════════════════════════════════════════

import { createHash } from 'node:crypto'
import { canonicalize } from '../../core/canonical.js'
import { sign as ed25519Sign, verify as ed25519Verify } from '../../crypto/keys.js'
import type { SettlementRecord } from './types.js'

/** Produce the canonical byte string a verifier signs/recomputes. The
 *  `signature` field is omitted (the canonicalizer already drops
 *  undefined keys, but we strip explicitly for clarity across ports). */
export function settlementSigningPayload(
  record: Omit<SettlementRecord, 'signature'>,
): string {
  const { ...body } = record as Record<string, unknown>
  // Ensure no `signature` bleeds through if the caller hands us a full
  // record and asks for the body. Canonicalize is stable under key
  // removal, so the order of removal doesn't matter.
  delete body.signature
  return canonicalize(body)
}

/** Canonical settlement_record_hash — hex sha256 of the signing payload.
 *  Stable across Python/TS so verifiers can short-circuit signature
 *  checks to a single 32-byte commitment. */
export function settlementRecordHash(
  record: Omit<SettlementRecord, 'signature'>,
): string {
  return createHash('sha256').update(settlementSigningPayload(record)).digest('hex')
}

/** Sign a settlement record. Returns the hex signature. Callers assemble
 *  the full `SettlementRecord` by writing the signature into the record. */
export function signSettlementRecord(
  record: Omit<SettlementRecord, 'signature'>,
  gatewayPrivateKeyHex: string,
): string {
  if (!gatewayPrivateKeyHex || typeof gatewayPrivateKeyHex !== 'string') {
    throw new Error('attribution-settlement: gatewayPrivateKeyHex required')
  }
  return ed25519Sign(settlementSigningPayload(record), gatewayPrivateKeyHex)
}

/** Verify just the Ed25519 signature on a settlement record. Returns a
 *  boolean; for full S1–S5 verification use `verifySettlementRecord`. */
export function verifySettlementSignature(
  record: SettlementRecord,
  gatewayPublicKeyHex: string,
): boolean {
  if (!gatewayPublicKeyHex) return false
  if (typeof record.signature !== 'string' || record.signature.length === 0) return false
  try {
    const { signature, ...body } = record
    void signature
    return ed25519Verify(
      settlementSigningPayload(body as Omit<SettlementRecord, 'signature'>),
      record.signature,
      gatewayPublicKeyHex,
    )
  } catch {
    return false
  }
}
