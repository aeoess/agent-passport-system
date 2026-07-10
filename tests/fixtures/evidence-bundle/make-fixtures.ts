// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0
// Regenerates the evidence-bundle fixtures. Run from the repo root:
//   npx tsx tests/fixtures/evidence-bundle/make-fixtures.ts
//
// valid/bundle.json: a signed bundle whose members exercise the axis
// mapping without time-sensitive members (no revocation_observation,
// so the revocation axis honestly reports MISSING forever; the
// passport expires in 2036 so the authority axis stays ASSERTED).
// tampered-member/bundle.json: the same bundle with one member payload
// mutated AFTER signing, so its digest no longer matches the manifest.

import { mkdirSync, writeFileSync } from 'node:fs'
import { join, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'
import { generateKeyPair } from '../../../src/crypto/keys.js'
import { createPassport } from '../../../src/core/passport.js'
import { createEvidenceBundle } from '../../../src/core/evidence-bundle.js'
import type { EvidenceBundle } from '../../../src/types/evidence-bundle.js'

const HERE = dirname(fileURLToPath(import.meta.url))

const signer = generateKeyPair()
const { signedPassport } = createPassport({
  agentId: 'fixture-agent-t8',
  agentName: 'fixture-agent-t8',
  ownerAlias: 'sprint-vwe-fixtures',
  mission: 'Static fixture for evidence-bundle tests',
  capabilities: ['code_execution'],
  runtime: { platform: 'node', models: ['fixture'] },
  validityWindow: { notAfter: '2036-01-01T00:00:00.000Z' },
})

// Two structural bilateral receipt copies carrying the same action_ref
// (the F1 slot, read structurally per F7), so the action axis can
// compare them via actionRefsMatch.
const actionRef = 'a'.repeat(64)
const bilateralLocal = {
  receiptId: 'br-fixture-1',
  version: '1.0',
  requestingAgentId: 'fixture-agent-t8',
  servingAgentId: 'fixture-counterparty',
  outcome: { toolName: 'echo', requestHash: 'b'.repeat(64), responseHash: 'c'.repeat(64), status: 'success', summary: 'fixture interaction' },
  requestedAt: '2026-07-10T00:00:00Z',
  completedAt: '2026-07-10T00:00:01Z',
  agreedAt: '2026-07-10T00:00:02Z',
  requestingAgentSignature: 'd'.repeat(128),
  servingAgentSignature: 'e'.repeat(128),
  action_ref: actionRef,
}
const bilateralCounterparty = { ...bilateralLocal, receiptId: 'br-fixture-2' }

const bundle = createEvidenceBundle({
  members: [
    { member_id: 'passport-1', member_type: 'passport', payload: signedPassport },
    { member_id: 'bilateral-local', member_type: 'bilateral_receipt', payload: bilateralLocal },
    { member_id: 'bilateral-counterparty', member_type: 'bilateral_receipt', payload: bilateralCounterparty },
    { member_id: 'note-1', member_type: 'other', payload: { note: 'uncommitted context attachment' } },
  ],
  signerPrivateKey: signer.privateKey,
  signerPublicKey: signer.publicKey,
  createdAt: '2026-07-10T00:00:00Z',
})

const tampered: EvidenceBundle = JSON.parse(JSON.stringify(bundle))
const victim = tampered.members.find(m => m.member_id === 'bilateral-local')
if (!victim) throw new Error('fixture generation: expected member missing')
;(victim.payload as { outcome: { summary: string } }).outcome.summary = 'tampered after signing'

for (const [dir, content] of [['valid', bundle], ['tampered-member', tampered]] as const) {
  mkdirSync(join(HERE, dir), { recursive: true })
  writeFileSync(join(HERE, dir, 'bundle.json'), JSON.stringify(content, null, 2) + '\n')
  console.log(`wrote ${join(HERE, dir, 'bundle.json')}`)
}
