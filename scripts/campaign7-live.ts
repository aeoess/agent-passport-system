#!/usr/bin/env npx tsx
/**
 * Campaign 7: Live E2E Test — Real Infrastructure
 *
 * Uses: Corpo staging API + qntm relay + echo bot
 * Conversation: 43949472072a829bc12c19db0d8f5525
 */

import { createHash, randomBytes } from 'node:crypto'
import sodium from 'libsodium-wrappers'
import {
  generateKeyPair, clearStores, createDID,
  createDecisionLineageReceipt, verifyDecisionLineageReceipt,
  createMinimalEnvelope, verifyExecutionEnvelope,
  decodeQntmInvite, deriveQntmKeys,
  qntmEncrypt, serializeEnvelope, computeKeyId,
  sign, canonicalize,
} from '../src/index.js'

const LIVE_INVITE_TOKEN = 'p2F2AWR0eXBlZmRpcmVjdGVzdWl0ZWVRU1AtMWdjb252X2lkUEOUlHIHKoKbwSwZ2w2PVSVraW52aXRlX3NhbHRYIAZB_kggvJK3kKNdE10iWwOdSAzELDECOBWwSwnDJVJ7bWludml0ZV9zZWNyZXRYINXqIMnk_nZILQF1dvAsFk0Feo1uWfB1hMGBaFm0TQsDbWludml0ZXJfaWtfcGtYIDqR0N-oD166Yo-cvYwm9sjsKUOa1fzvZe-5vqvQR1KY'
const CORPO_VERIFY_URL = 'https://api.corpo.llc/api/v1/entities/test-entity/verify'
const RELAY_URL = 'https://inbox.qntm.corpo.llc/v1/send'

async function main() {
  await sodium.ready
  clearStores()
  console.log('═══ Campaign 7 Live E2E Test ═══\n')

  // ═══ STEP 1: Verify Entity via Corpo API ═══
  console.log('Step 1: Corpo Entity Verification...')
  const entityRes = await fetch(CORPO_VERIFY_URL)
  const entity = await entityRes.json() as any
  console.log(`  Status: ${entityRes.status}`)
  console.log(`  Entity: ${entity.name} (${entity.entity_type})`)
  console.log(`  Status: ${entity.status}`)
  console.log(`  Ceiling: [${entity.authority_ceiling?.join(', ')}]`)

  if (entity.status !== 'active') {
    console.error('❌ Entity not active. Aborting.')
    process.exit(1)
  }
  console.log('  ✅ Entity verified: active\n')

  // ═══ STEP 2: Create APS governance artifacts ═══
  console.log('Step 2: Create governance artifacts...')
  const agent = generateKeyPair()
  const evaluator = generateKeyPair()
  const agentDid = createDID(agent.publicKey)
  const evaluatorDid = createDID(evaluator.publicKey)

  const lineageReceipt = createDecisionLineageReceipt({
    decisionArtifactId: 'campaign7-live-decision-001',
    decisionType: 'loan_risk_assessment',
    contributingSources: [
      {
        sourceId: 'credit-bureau', accessReceiptId: 'ar-credit-001',
        derivationDepth: 1, transformPath: ['subset', 'embedding'],
        termsVersionAtAccess: '3.0', lineageConfidence: 'complete',
        compensationStatus: 'settled',
      },
      {
        sourceId: 'income-api', accessReceiptId: 'ar-income-001',
        derivationDepth: 2, transformPath: ['subset', 'aggregation'],
        termsVersionAtAccess: '1.0', lineageConfidence: 'partial',
        compensationStatus: 'pending',
      },
    ],
    lineageCompleteness: 'partial',
    transformChain: ['subset', 'embedding', 'aggregation', 'decision_artifact'],
    governingPurpose: 'inference:decision_support',
    explanation: 'Campaign 7 live test: loan risk 720, recommend approve.',
    privateKey: agent.privateKey,
  })

  const verified = verifyDecisionLineageReceipt(lineageReceipt, agent.publicKey)
  console.log(`  Lineage receipt: ${lineageReceipt.receiptId}`)
  console.log(`  Sources: ${lineageReceipt.contributingSources.length}`)
  console.log(`  Verified: ${verified}`)
  console.log('  ✅ Governance artifact created\n')

  // ═══ STEP 3: Wrap in SignedExecutionEnvelope ═══
  console.log('Step 3: Create execution envelope...')
  const decisionPayload = canonicalize({ verdict: 'permit', lineageReceiptId: lineageReceipt.receiptId })
  const decisionHash = createHash('sha256').update(decisionPayload).digest('hex')
  const evalSig = sign(decisionPayload, evaluator.privateKey)

  const envelope = createMinimalEnvelope({
    agentDid,
    runId: 'campaign7-live-run-001',
    actionId: 'campaign7-live-action-001',
    scope: ['inference:decision_support', 'data:read'],
    revocationStatus: 'active',
    decisionHash,
    policyRef: 'floor-v1.0',
    evaluationMethod: 'deterministic',
    verdict: 'permit',
    evaluatedAt: new Date().toISOString(),
    evaluatorDid,
    evaluatorSignature: evalSig,
    receiptHash: createHash('sha256').update(canonicalize(lineageReceipt)).digest('hex'),
    signerPrivateKey: agent.privateKey,
    signerPublicKey: agent.publicKey,
  })

  const envCheck = verifyExecutionEnvelope(envelope)
  console.log(`  Envelope: ${envelope.run_id}`)
  console.log(`  Signature valid: ${envCheck.signatureValid}`)
  console.log('  ✅ Envelope created and verified\n')

  // ═══ STEP 4: Encrypt via QSP-1 and POST to relay ═══
  console.log('Step 4: QSP-1 encrypt + relay send...')
  const invite = decodeQntmInvite(LIVE_INVITE_TOKEN)
  const keys = deriveQntmKeys(invite)

  const transportPayload = JSON.stringify({
    protocol: 'APS',
    type: 'Campaign7LiveTest',
    envelope,
    lineageReceipt,
    entity: { entityId: entity.entity_id, status: entity.status, type: entity.entity_type },
    timestamp: new Date().toISOString(),
  })

  const plaintext = new TextEncoder().encode(transportPayload)
  const senderKeyId = computeKeyId(Buffer.from(agent.publicKey, 'hex'))

  const qntmEnvelope = await qntmEncrypt(plaintext, keys, senderKeyId, Date.now() % 100000)
  const serialized = serializeEnvelope(qntmEnvelope)

  console.log(`  Conversation: ${Buffer.from(invite.conv_id).toString('hex')}`)
  console.log(`  Plaintext: ${plaintext.length} bytes`)
  console.log(`  Ciphertext: ${qntmEnvelope.ciphertext.length} bytes`)

  // Build relay message using the bridge's format
  const relayBody = JSON.stringify({
    conv_id: Buffer.from(invite.conv_id).toString('hex'),
    envelope_b64: serialized,
  })

  console.log(`  Sending to relay...`)
  const relayRes = await fetch(RELAY_URL, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: relayBody,
  })

  const relayText = await relayRes.text()
  console.log(`  Relay response: HTTP ${relayRes.status}`)
  console.log(`  Body: ${relayText.slice(0, 200)}`)

  if (relayRes.status === 201 || relayRes.status === 200) {
    console.log('  ✅ Relay accepted encrypted payload\n')
  } else {
    console.log(`  ⚠️ Unexpected status: ${relayRes.status}\n`)
  }

  // ═══ RESULTS ═══
  console.log('═══ Campaign 7 Live Test Results ═══')
  console.log(`  Corpo Entity: ${entity.status === 'active' ? '✅' : '❌'} ${entity.name}`)
  console.log(`  Lineage Receipt: ${verified ? '✅' : '❌'} ${lineageReceipt.receiptId}`)
  console.log(`  Envelope Sig: ${envCheck.signatureValid ? '✅' : '❌'}`)
  console.log(`  QSP-1 Encrypt: ✅ ${qntmEnvelope.ciphertext.length} bytes`)
  console.log(`  Relay Send: ${relayRes.status === 201 || relayRes.status === 200 ? '✅' : '❌'} HTTP ${relayRes.status}`)
  console.log(`  Agent DID: ${agentDid}`)
  console.log(`\n  Full chain: DID → Entity (Corpo) → Governance (APS) → Transport (QSP-1) → Relay`)
  console.log('  Three specs. One key. Real infrastructure.\n')
}

main().catch(e => { console.error('Fatal:', e); process.exit(1) })
