// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0
// Behavioral Memory Objects — create, verify, expire, export/import

import { v4 as uuidv4 } from 'uuid'
import { sign, verify } from '../crypto/keys.js'
import { canonicalize, canonicalizeForWrite } from './canonical.js'
import { parseRfc3339, formatRfc3339 } from './rfc3339.js'
import type { BehavioralMemoryObject, BMOExportBundle } from '../types/behavioral-memory.js'

export function createBehavioralMemoryObject(opts: {
  principal_id: string
  issuer_id: string
  issuer_private_key: string
  pattern: BehavioralMemoryObject['pattern']
  derivation_source: string
  retention_ttl: number
  relational_entities: boolean
  portable: boolean
}): BehavioralMemoryObject {
  const now = new Date()
  const bmo: Omit<BehavioralMemoryObject, 'issuer_signature'> = {
    id: `bmo_${uuidv4().slice(0, 12)}`,
    principal_id: opts.principal_id,
    issuer_id: opts.issuer_id,
    pattern: opts.pattern,
    derivation_source: opts.derivation_source,
    retention_policy: {
      ttl: opts.retention_ttl,
      // Emission from an instant already held as a number. Same bytes.
      expires_at: formatRfc3339(now.getTime() + opts.retention_ttl * 1000),
    },
    relational_entities: opts.relational_entities,
    portable: opts.portable,
    format_version: '1.0',
  }
  const canonical = canonicalizeForWrite(bmo)
  const issuer_signature = sign(canonical, opts.issuer_private_key)
  return { ...bmo, issuer_signature } as BehavioralMemoryObject
}

export function verifyBehavioralMemoryObject(bmo: BehavioralMemoryObject, publicKey: string): boolean {
  const { issuer_signature, ...unsigned } = bmo
  const canonical = canonicalize(unsigned)
  return verify(canonical, issuer_signature, publicKey)
}

export function isBMOExpired(bmo: BehavioralMemoryObject): boolean {
  const expiresAt = bmo.retention_policy?.expires_at
  if (!expiresAt) return true // missing expiry = expired
  // An expiry this reader cannot parse is not an expiry it can honour, so
  // the retention window is treated as elapsed rather than as unbounded.
  const expiry = parseRfc3339(expiresAt)
  if (!expiry.ok) return true // unreadable expiry = expired
  return expiry.ms < Date.now()
}

export function exportBehavioralMemory(
  bmos: BehavioralMemoryObject[],
  exporterId: string,
  privateKey: string,
): BMOExportBundle {
  const bundle: Omit<BMOExportBundle, 'signature'> = {
    bundle_id: `bundle_${uuidv4().slice(0, 12)}`,
    exported_at: new Date().toISOString(),
    bmos,
    exporter_id: exporterId,
  }
  const canonical = canonicalizeForWrite(bundle)
  const signature = sign(canonical, privateKey)
  return { ...bundle, signature } as BMOExportBundle
}

export function importBehavioralMemory(
  bundle: BMOExportBundle,
  exporterPublicKey: string,
): { valid: boolean; bmos: BehavioralMemoryObject[]; errors: string[] } {
  const { signature, ...unsigned } = bundle
  const canonical = canonicalize(unsigned)
  const errors: string[] = []

  if (!verify(canonical, signature, exporterPublicKey)) {
    errors.push('Bundle signature invalid')
    return { valid: false, bmos: [], errors }
  }

  // Verify each BMO is not expired
  const validBmos: BehavioralMemoryObject[] = []
  for (const bmo of bundle.bmos) {
    if (isBMOExpired(bmo)) {
      errors.push(`BMO ${bmo.id} expired at ${bmo.retention_policy.expires_at}`)
    } else {
      validBmos.push(bmo)
    }
  }

  return { valid: errors.length === 0, bmos: validBmos, errors }
}
