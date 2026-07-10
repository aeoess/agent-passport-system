// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0
// End-to-end verifiable workflow: principal -> delegation -> narrower
// sub-delegation -> bilateral pair (aud + action_ref) -> revocation
// observation -> evidence bundles -> CLI verify-bundle gating.
// Emits five bundles into ./bundles and asserts the CLI exit codes:
// valid 0; payload-changed, wrong-audience, fake-success-unilateral,
// action-after-stale-revocation all 2.
// Build first: npm run build (imports the compiled dist).

import { execFileSync } from 'node:child_process'
import { mkdirSync, writeFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

import {
  generateKeyPair,
  createV2Delegation,
  createBilateralReceipt,
  bindAudience,
  computeActionRef,
  reconcileBilateralPair,
  buildRevocationObservation,
  createLocalSigner,
  createEvidenceBundle,
} from '../../dist/src/index.js'

const __dir = dirname(fileURLToPath(import.meta.url))
const OUT = join(__dir, 'bundles')
mkdirSync(OUT, { recursive: true })

// ── principals and keys ──
const principal = generateKeyPair() // human principal's key, root of authority
const agentA = generateKeyPair()    // requesting agent
const agentB = generateKeyPair()    // serving agent
const bundleSigner = generateKeyPair()
const A = 'did:aps:zWorkflowRequester'
const B = 'did:aps:zWorkflowServer'

const policyContext = () => {
  const now = new Date()
  return {
    policy_version: '2.0',
    values_floor_version: '1.0',
    trust_epoch: 1,
    issuer_id: 'principal-demo',
    created_at: now.toISOString(),
    valid_from: now.toISOString(),
    valid_until: new Date(now.getTime() + 3600_000).toISOString(),
  }
}

// ── delegation chain: principal grants A, A sub-delegates narrower to B ──
const rootDelegation = createV2Delegation({
  delegator: principal.publicKey,
  delegatee: A,
  scope: ['commerce:read', 'commerce:write', 'repo:write'],
  policy_context: policyContext(),
  delegator_private_key: principal.privateKey,
})
const subDelegation = createV2Delegation({
  delegator: agentA.publicKey,
  delegatee: B,
  scope: ['commerce:read'], // strictly narrower: authority only decreases
  policy_context: policyContext(),
  delegator_private_key: agentA.privateKey,
})

// ── the authorized interaction, correlated by the native action_ref ──
const requestedAt = '2026-07-10T04:00:00Z'
const actionRef = computeActionRef({
  agentId: A,
  action: { type: 'commerce_preflight', target: 'order-7781', scopeRequired: ['commerce:read'] },
  createdAt: requestedAt,
})
const outcome = {
  toolName: 'commerce_preflight',
  requestHash: 'a'.repeat(64),
  responseHash: 'b'.repeat(64),
  status: 'success',
  summary: 'preflight authorized',
}
const mkReceipt = (over = {}) => createBilateralReceipt({
  requestingAgentId: A,
  servingAgentId: B,
  outcome,
  requestedAt,
  completedAt: '2026-07-10T04:00:01Z',
  requestingAgentPrivateKey: agentA.privateKey,
  servingAgentPrivateKey: agentB.privateKey,
  aud: bindAudience([A, B]),
  action_ref: actionRef,
  ...over,
})

const honest = mkReceipt()
const pairPolicy = { selfRecipientId: A, requireAudience: true }

// ── revocation observations ──
const observerSigner = createLocalSigner({ privateKeyHex: principal.privateKey })
const freshObservation = await buildRevocationObservation({
  authority_ref: subDelegation.delegation_id ?? 'delegation-sub',
  status_source: { kind: 'source', id: 'https://revocation.example/status' },
  observed_at: new Date().toISOString(),
  maximum_staleness_ms: 3600_000,
  decision: { effect: 'allow' },
}, observerSigner)
// Checked long ago with a short freshness contract: STALE at verification.
const staleObservation = await buildRevocationObservation({
  authority_ref: subDelegation.delegation_id ?? 'delegation-sub',
  status_source: { kind: 'source', id: 'https://revocation.example/status' },
  observed_at: '2026-07-01T00:00:00Z',
  maximum_staleness_ms: 60_000,
  decision: { effect: 'allow' },
}, observerSigner)

// ── bundle builders ──
const member = (id, type, payload) => ({ member_id: id, member_type: type, payload })
const baseMembers = () => [
  member('delegation-root', 'delegation', rootDelegation),
  member('delegation-sub', 'delegation', subDelegation),
]
const emit = (name, members) => {
  const bundle = createEvidenceBundle({
    members,
    signerPrivateKey: bundleSigner.privateKey,
    signerPublicKey: bundleSigner.publicKey,
  })
  const path = join(OUT, `${name}.json`)
  writeFileSync(path, JSON.stringify(bundle, null, 2) + '\n')
  return path
}

// 1. valid: honest pair, both copies identical, reconciled, fresh revocation check.
const verdictValid = reconcileBilateralPair(honest, honest, pairPolicy)
const pValid = emit('valid', [
  ...baseMembers(),
  member('receipt-local', 'bilateral_receipt', honest),
  member('receipt-counterparty', 'bilateral_receipt', honest),
  member('pair-verdict', 'bilateral_pair_verdict', verdictValid),
  member('revocation-check', 'revocation_observation', freshObservation),
])

// 2. payload-changed: counterparty re-minted the receipt with a different responseHash.
const tamperedPayload = mkReceipt({ outcome: { ...outcome, responseHash: 'c'.repeat(64) } })
const verdictPayload = reconcileBilateralPair(honest, tamperedPayload, pairPolicy)
const pPayload = emit('payload-changed', [
  ...baseMembers(),
  member('receipt-local', 'bilateral_receipt', honest),
  member('receipt-counterparty', 'bilateral_receipt', tamperedPayload),
  member('pair-verdict', 'bilateral_pair_verdict', verdictPayload),
  member('revocation-check', 'revocation_observation', freshObservation),
])

// 3. wrong-audience: counterparty copy audience-bound to a third party, not to A.
const wrongAud = mkReceipt({ aud: bindAudience(['did:aps:zSomeoneElse', B]) })
const verdictAud = reconcileBilateralPair(honest, wrongAud, pairPolicy)
const pAud = emit('wrong-audience', [
  ...baseMembers(),
  member('receipt-local', 'bilateral_receipt', honest),
  member('receipt-counterparty', 'bilateral_receipt', wrongAud),
  member('pair-verdict', 'bilateral_pair_verdict', verdictAud),
  member('revocation-check', 'revocation_observation', freshObservation),
])

// 4. fake-success-unilateral: one side claims success, the counterparty's copy
// says failure. The contradicted claim reconciles as mismatch/unilateral_success
// and the action axis reports INVALID. (A truly silent counterparty would be
// verdict status 'unilateral' -> ASSERTED, a claim boundary, not a failure.)
const failureCopy = mkReceipt({ outcome: { ...outcome, status: 'failure', summary: 'preflight denied' } })
const verdictFake = reconcileBilateralPair(honest, failureCopy, pairPolicy)
const pFake = emit('fake-success-unilateral', [
  ...baseMembers(),
  member('receipt-local', 'bilateral_receipt', honest),
  member('receipt-counterparty', 'bilateral_receipt', failureCopy),
  member('pair-verdict', 'bilateral_pair_verdict', verdictFake),
  member('revocation-check', 'revocation_observation', freshObservation),
])

// 5. action-after-stale-revocation: the revocation answer on file is STALE
// (allow, observed far outside its freshness contract), and the action minted
// after that point cannot correlate to the authorized request: its action_ref
// (new timestamp) mismatches the authorized pair's, so the action axis is
// INVALID while the revocation axis shows the stale check that let it happen.
const lateRef = computeActionRef({
  agentId: A,
  action: { type: 'commerce_preflight', target: 'order-7781', scopeRequired: ['commerce:read'] },
  createdAt: '2026-07-10T05:30:00Z', // after the observation went stale
})
const lateAction = { action_ref: lateRef, agentId: A, type: 'commerce_preflight', executedAt: '2026-07-10T05:30:00Z' }
const pStale = emit('action-after-stale-revocation', [
  ...baseMembers(),
  member('receipt-authorized', 'bilateral_receipt', honest),
  member('receipt-late-action', 'action_receipt', lateAction),
  member('revocation-check-stale', 'revocation_observation', staleObservation),
])

// ── run the CLI gate over all five ──
const CLI = join(__dir, '..', '..', 'dist', 'src', 'cli', 'index.js')
const expected = [[pValid, 0], [pPayload, 2], [pAud, 2], [pFake, 2], [pStale, 2]]
let failures = 0
for (const [path, want] of expected) {
  let got = 0
  let out = ''
  try {
    out = execFileSync('node', [CLI, 'verify-bundle', path, '--json'], { encoding: 'utf8' })
  } catch (e) {
    got = e.status ?? -1
    out = String(e.stdout ?? '')
  }
  const name = path.split('/').pop()
  const axes = (() => { try { return JSON.parse(out).axes } catch { return {} } })()
  const ok = got === want
  if (!ok) failures++
  console.log(`${ok ? 'PASS' : 'FAIL'} ${name}: exit ${got} (want ${want}) axes=${JSON.stringify(axes)}`)
}
if (failures > 0) {
  console.error(`${failures} bundle gate assertion(s) failed`)
  process.exit(1)
}
console.log('all five bundle gates hold: 0, 2, 2, 2, 2')
