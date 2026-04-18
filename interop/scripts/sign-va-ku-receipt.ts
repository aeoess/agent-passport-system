// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// ══════════════════════════════════════════════════════════════════
// Sign an APS DecisionLineageReceipt over a VeritasActa Knowledge
// Unit bundle, for drop-in into bundle.external_receipts.aps.receipt.
// ══════════════════════════════════════════════════════════════════
//
// Companion to VeritasActa/verify#2 + #6.
//
// Usage:
//   npx tsx interop/scripts/sign-va-ku-receipt.ts <bundle.json> [out.json]
//
// Reads a VeritasActa cross-verify bundle, computes a per-receipt
// JCS hash for every entry in `bundle.receipts`, and emits a signed
// APS DecisionLineageReceipt whose contributingSources commit to those
// hashes. Tampering any byte of any KU receipt changes its hash, so
// the recorded accessReceiptId no longer matches the bundle — the APS
// attestation is observably stale even though APS's own signature
// stays cryptographically valid (proving APS was not the tamperer).
//
// Determinism:
//   - Test signing key derived from a fixed seed (no entropy).
//   - Receipt id and timestamp are deterministic constants.
//   - Re-running against the same bundle produces byte-identical output.

import { readFileSync, writeFileSync } from 'node:fs'
import { createHash } from 'node:crypto'
import { sign, publicKeyFromPrivate } from '../../src/crypto/keys.js'
import { canonicalize } from '../../src/core/canonical.js'
import { canonicalizeJCS } from '../../src/core/canonical-jcs.js'
import type { DecisionLineageReceipt, ContributingSource } from '../../src/types/data-lifecycle.js'

// Fixed seed → deterministic Ed25519 keypair. Test key, NOT an
// AEOESS production issuer. Documented in the file header so any
// reviewer can re-derive it.
const APS_TEST_SEED = 'aps:veritasacta:ku-cross-verify:v1'
const APS_TEST_PRIVATE_KEY = createHash('sha256').update(APS_TEST_SEED).digest('hex')
const APS_TEST_PUBLIC_KEY = publicKeyFromPrivate(APS_TEST_PRIVATE_KEY)

const RECEIPT_ID = 'dlr_va_ku_4b3f7c2a9d8e1f05'
const RECEIPT_TIMESTAMP = '2026-04-18T00:00:00Z'

interface KuReceipt {
  v: number
  type: string
  algorithm: string
  kid: string
  issuer: string
  issued_at: string
  payload: Record<string, unknown>
  signature: string
}

interface KuBundle {
  format: string
  ku_id: string
  receipts: KuReceipt[]
  external_receipts?: { aps?: { receipt?: unknown } }
}

function sha256Hex(s: string): string {
  return createHash('sha256').update(s).digest('hex')
}

function buildReceipt(bundle: KuBundle): DecisionLineageReceipt {
  const kuId = bundle.ku_id
  const receipts = bundle.receipts ?? []

  const contributingSources: ContributingSource[] = receipts.map((r, i) => ({
    sourceId: r.issuer,
    accessReceiptId: 'sha256:' + sha256Hex(canonicalizeJCS(r)),
    derivationDepth: i + 1,
    transformPath: ['aggregation'],
    termsVersionAtAccess: bundle.format,
    lineageConfidence: 'complete',
    compensationStatus: 'settled',
  }))

  // Terminal aggregate hash — the deliberation's Merkle commitment.
  const aggregate = receipts[receipts.length - 1]
  const aggregateHash = aggregate ? sha256Hex(canonicalizeJCS(aggregate)) : ''

  const unsigned: Omit<DecisionLineageReceipt, 'signature'> = {
    receiptId: RECEIPT_ID,
    timestamp: RECEIPT_TIMESTAMP,
    decisionArtifactId: `veritasacta:ku:${kuId}`,
    decisionType: 'knowledge_unit_deliberation',
    contributingSources,
    lineageCompleteness: 'complete',
    externalHopsPresent: true,
    transformChain: ['aggregation'],
    governingPurpose: 'research:academic',
    jurisdictionContext: bundle.format,
    explanation:
      `APS DecisionLineageReceipt attesting to VeritasActa Knowledge Unit ${kuId}. ` +
      `Bundle terminal aggregate sha256: ${aggregateHash}. ` +
      `Each entry in contributingSources commits to the JCS-canonical sha256 of one ` +
      `KU receipt; tampering any byte of any KU receipt invalidates the recorded ` +
      `accessReceiptId, breaking cross-layer integrity even though APS's Ed25519 ` +
      `signature over this DecisionLineageReceipt remains cryptographically valid.`,
  }

  const signature = sign(canonicalize(unsigned), APS_TEST_PRIVATE_KEY)
  return { ...unsigned, signature }
}

function main(): void {
  const args = process.argv.slice(2)
  if (args.length === 0) {
    console.error('usage: sign-va-ku-receipt.ts <bundle.json> [out.json]')
    process.exit(2)
  }
  const bundlePath = args[0]
  const outPath = args[1]

  const bundle = JSON.parse(readFileSync(bundlePath, 'utf8')) as KuBundle
  const receipt = buildReceipt(bundle)

  const envelope = {
    receipt,
    signing_key: {
      kty: 'OKP',
      crv: 'Ed25519',
      use: 'sig',
      issuer: 'aps:test:ku-cross-verify',
      // Documented test key. Re-derive: sha256("aps:veritasacta:ku-cross-verify:v1").
      public_key_hex: APS_TEST_PUBLIC_KEY,
      seed_note: `derived from sha256("${APS_TEST_SEED}") — test key, NOT a production issuer`,
    },
  }

  const json = JSON.stringify(envelope, null, 2)
  if (outPath) {
    writeFileSync(outPath, json + '\n')
    console.error(`wrote ${outPath} (${json.length} bytes, signature ${receipt.signature.slice(0, 16)}…)`)
  } else {
    process.stdout.write(json + '\n')
  }
}

main()
