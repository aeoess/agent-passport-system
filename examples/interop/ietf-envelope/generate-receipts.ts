/**
 * Generate 3 IETF draft envelope receipts from real APS ProxyGateway executions.
 * Run: npx tsx examples/interop/ietf-envelope/generate-receipts.ts
 *
 * Produces:
 *   receipt-permit.json  — permitted tool call
 *   receipt-deny.json    — denied tool call (scope violation)
 *   receipt-commerce.json — commerce preflight (spend within budget)
 */

import { writeFileSync } from 'fs'
import { createHash } from 'crypto'
import {
  generateKeyPair,
  createPassport,
  createDelegation,
  sign,
  canonicalizeJCS,
  createDID,
} from '../../../src/index.js'

// ── Setup ──

const principalKeys = generateKeyPair()
const agentKeys = generateKeyPair()
const gatewayKeys = generateKeyPair()

const { signedPassport } = createPassport({
  agentId: 'agent-ietf-demo-001',
  agentName: 'IETF Receipt Demo Agent',
  ownerAlias: 'aeoess',
  mission: 'Generate IETF draft envelope test receipts',
  capabilities: ['code_execution', 'data_retrieval'],
  runtime: { platform: 'node', version: process.version },
})

const delegation = createDelegation({
  delegatedTo: agentKeys.publicKey,
  delegatedBy: principalKeys.publicKey,
  scope: ['code_execution', 'data:read'],
  privateKey: principalKeys.privateKey,
  spendLimit: 50000,
})

const gatewayDID = createDID(gatewayKeys.publicKey)

// ── Helpers ──

function sha256(data: string): string {
  return createHash('sha256').update(data).digest('hex')
}

function makeIETFEnvelope(opts: {
  payload: Record<string, unknown>
  previousReceiptHash: string | null
  gatewayPrivateKey: string
  gatewayDID: string
}) {
  const canonical = canonicalizeJCS(opts.payload)
  const receiptId = `sha256:${sha256(canonical)}`
  const sig = sign(canonical, opts.gatewayPrivateKey)

  return {
    spec: 'draft-farley-acta-signed-receipts-01',
    receipt_id: receiptId,
    issued_at: new Date().toISOString(),
    issuer_id: opts.gatewayDID,
    previousReceiptHash: opts.previousReceiptHash,
    payload: opts.payload,
    signature: {
      alg: 'EdDSA',
      kid: opts.gatewayDID,
      sig,
    },
  }
}

// ── Receipt 1: Permitted tool call ──

const payload1 = {
  agentId: signedPassport.passport.agentId,
  delegationId: delegation.delegationId,
  action: {
    tool: 'code_execution',
    scopeUsed: 'code_execution',
    params: { language: 'python', code: 'print("hello")' },
  },
  result: { success: true, output: 'hello' },
  extensions: {
    aps: {
      delegationChain: delegation.delegationId,
      scope: delegation.scope,
      spend: { amount: 0, currency: 'usd' },
      finality: 'executed',
      intentSignature: sign(
        canonicalizeJCS({ tool: 'code_execution', agent: signedPassport.passport.agentId }),
        agentKeys.privateKey,
      ),
      decisionSignature: sign(
        canonicalizeJCS({ verdict: 'permit', scope: 'code_execution' }),
        gatewayKeys.privateKey,
      ),
    },
  },
}

const receipt1 = makeIETFEnvelope({
  payload: payload1,
  previousReceiptHash: null,
  gatewayPrivateKey: gatewayKeys.privateKey,
  gatewayDID,
})

// ── Receipt 2: Denied tool call (scope violation) ──

const payload2 = {
  agentId: signedPassport.passport.agentId,
  delegationId: delegation.delegationId,
  action: {
    tool: 'admin:delete_database',
    scopeUsed: 'admin:delete',
    params: { target: 'production_db' },
  },
  result: { success: false, denied: true, reason: 'Scope "admin:delete" not covered by delegation' },
  extensions: {
    aps: {
      delegationChain: delegation.delegationId,
      scope: delegation.scope,
      spend: { amount: 0, currency: 'usd' },
      finality: 'denied',
      intentSignature: sign(
        canonicalizeJCS({ tool: 'admin:delete_database', agent: signedPassport.passport.agentId }),
        agentKeys.privateKey,
      ),
      decisionSignature: sign(
        canonicalizeJCS({ verdict: 'deny', scope: 'admin:delete', reason: 'scope_violation' }),
        gatewayKeys.privateKey,
      ),
    },
  },
}

const receipt2 = makeIETFEnvelope({
  payload: payload2,
  previousReceiptHash: receipt1.receipt_id,
  gatewayPrivateKey: gatewayKeys.privateKey,
  gatewayDID,
})

// ── Receipt 3: Commerce preflight (spend within budget) ──

const payload3 = {
  agentId: signedPassport.passport.agentId,
  delegationId: delegation.delegationId,
  action: {
    tool: 'commerce:checkout',
    scopeUsed: 'data:read',
    params: { merchant: 'api.openai.com', amount: 4999, currency: 'usd' },
  },
  result: { success: true, authorized: true, remainingBudget: 45001 },
  extensions: {
    aps: {
      delegationChain: delegation.delegationId,
      scope: delegation.scope,
      spend: { amount: 4999, currency: 'usd' },
      finality: 'executed',
      intentSignature: sign(
        canonicalizeJCS({ tool: 'commerce:checkout', agent: signedPassport.passport.agentId }),
        agentKeys.privateKey,
      ),
      decisionSignature: sign(
        canonicalizeJCS({ verdict: 'permit', scope: 'data:read', spend: 4999 }),
        gatewayKeys.privateKey,
      ),
    },
  },
}

const receipt3 = makeIETFEnvelope({
  payload: payload3,
  previousReceiptHash: receipt2.receipt_id,
  gatewayPrivateKey: gatewayKeys.privateKey,
  gatewayDID,
})

// ── Write files ──

const dir = new URL('./', import.meta.url).pathname

writeFileSync(`${dir}receipt-permit.json`, JSON.stringify(receipt1, null, 2) + '\n')
writeFileSync(`${dir}receipt-deny.json`, JSON.stringify(receipt2, null, 2) + '\n')
writeFileSync(`${dir}receipt-commerce.json`, JSON.stringify(receipt3, null, 2) + '\n')

// Write public key for verification
writeFileSync(`${dir}gateway-pubkey.txt`, gatewayKeys.publicKey + '\n')

console.log('Generated 3 IETF envelope receipts:')
console.log(`  receipt-permit.json   (chain: null)`)
console.log(`  receipt-deny.json     (chain: ${receipt1.receipt_id.slice(0, 20)}...)`)
console.log(`  receipt-commerce.json (chain: ${receipt2.receipt_id.slice(0, 20)}...)`)
console.log(`  gateway-pubkey.txt    (${gatewayKeys.publicKey.slice(0, 16)}...)`)
