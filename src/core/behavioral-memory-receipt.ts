// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// Behavioral Memory Receipts — lifecycle audit trail for BMOs

import { v4 as uuidv4 } from 'uuid'
import { sign, verify } from '../crypto/keys.js'
import { canonicalize } from './canonical.js'
import type { BMOReceipt } from '../types/behavioral-memory.js'

export function createBMOReceipt(opts: {
  bmo_id: string
  event_type: BMOReceipt['event_type']
  actor_id: string
  private_key: string
}): BMOReceipt {
  if (!opts.bmo_id || typeof opts.bmo_id !== 'string') throw new Error('createBMOReceipt: bmo_id must be a non-empty string')
  if (!opts.actor_id || typeof opts.actor_id !== 'string') throw new Error('createBMOReceipt: actor_id must be a non-empty string')
  const receipt: Omit<BMOReceipt, 'signature'> = {
    receipt_id: `bmo_rcpt_${uuidv4().slice(0, 12)}`,
    bmo_id: opts.bmo_id,
    event_type: opts.event_type,
    actor_id: opts.actor_id,
    timestamp: new Date().toISOString(),
  }
  const canonical = canonicalize(receipt)
  const signature = sign(canonical, opts.private_key)
  return { ...receipt, signature } as BMOReceipt
}

export function verifyBMOReceipt(receipt: BMOReceipt, publicKey: string): boolean {
  const { signature, ...unsigned } = receipt
  const canonical = canonicalize(unsigned)
  return verify(canonical, signature, publicKey)
}
