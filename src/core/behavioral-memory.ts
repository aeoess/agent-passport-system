// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// Behavioral Memory Objects — create, verify, expire, export/import

import { v4 as uuidv4 } from 'uuid'
import { sign, verify } from '../crypto/keys.js'
import { canonicalize } from './canonical.js'
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
      expires_at: new Date(now.getTime() + opts.retention_ttl * 1000).toISOString(),
    },
    relational_entities: opts.relational_entities,
    portable: opts.portable,
    format_version: '1.0',
  }
  const canonical = canonicalize(bmo)
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
  const d = new Date(expiresAt)
  if (isNaN(d.getTime())) return true // invalid date = expired
  return d < new Date()
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
  const canonical = canonicalize(bundle)
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
