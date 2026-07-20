// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0
//
// Emits the three Liu composition vectors through SDK APIs only. Inputs are
// the Liu-shaped fixtures in vectors/*/input.json (their field names, see
// drafts/EXTRACTED-FIELDS.md); outputs are signed APS records in record.json
// plus a keys.json sidecar carrying the public half of the fresh test keys.
// Existing record shapes only: ReceiptV1 (profile aps-receipt-v1) for the
// permit and denial, SignedRevocationObservation for the observation. Keys are
// fixed test keys derived from published seeds; DIDs and agent ids are
// synthetic throughout.

import { createHash, createPrivateKey, createPublicKey } from 'node:crypto'
import { readFileSync, writeFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { dirname, join } from 'node:path'
import { strictJCS } from '../../src/v2/receipt-core/jcs.js'
import { createReceiptV1 } from '../../src/v2/receipt-core/receipt.js'
import { buildDecisionRefV1, computeDecisionComponentRefV1 } from '../../src/v2/receipt-core/decision-ref.js'
import type { CoreDecisionOutputV1, EvidenceRefV1, JsonValue, ReceiptV1 } from '../../src/v2/receipt-core/types.js'
import { computeActionRefV2, createActionReferenceInputV2 } from '../../src/v2/action-reference/v2.js'
import { buildRevocationObservation } from '../../src/v2/revocation-enforcement/observation.js'
import { LocalEd25519Signer } from '../../src/adapters/remote-signer/local-signer.js'

const HERE = dirname(fileURLToPath(import.meta.url))
const sha256Hex = (s: string): string => createHash('sha256').update(s, 'utf8').digest('hex')
const digestOf = (value: JsonValue): string => sha256Hex(strictJCS(value))

// DETERMINISTIC TEST KEYS, publish-safe by design. The committed vector
// records must be byte-stable across re-runs, so both signing keys derive
// from fixed ASCII seeds instead of fresh randomness. These are TEST keys,
// published intentionally with the vectors; never use them for any real
// identity and never reuse them outside this harness.
const TEST_SEED_ISSUER = Buffer.from('APS-test-issuer-seed-00000000001', 'utf8').toString('hex')
const TEST_SEED_OBSERVER = Buffer.from('APS-test-observer-seed-000000001', 'utf8').toString('hex')
const ED25519_PKCS8_PREFIX = Buffer.from('302e020100300506032b657004220420', 'hex')

function testKeyPairFromSeed(seedHex: string): { privateKey: string; publicKey: string } {
  if (seedHex.length !== 64) throw new Error('test seed must be 32 bytes of hex')
  const priv = createPrivateKey({
    key: Buffer.concat([ED25519_PKCS8_PREFIX, Buffer.from(seedHex, 'hex')]),
    format: 'der',
    type: 'pkcs8'
  })
  const spki = createPublicKey(priv).export({ format: 'der', type: 'spki' }) as Buffer
  return { privateKey: seedHex, publicKey: spki.subarray(spki.length - 32).toString('hex') }
}

// Fixed timestamps and fixed test keys together make every emitted byte
// reproducible; re-running emit rewrites identical files.
const ISSUED_AT = '2026-07-18T19:30:00.000Z'
const OBSERVED_AT = '2026-07-18T19:31:00.000Z'

interface LiuHop {
  delegator_id: string
  delegatee_id: string
  delegation_timestamp: number
  root_evidence_ref: string
  delegated_policy: { type: string; content: string; entry_point: string }
  operation_summary: string
  delegator_signature: string
  as_signature: string
  [k: string]: JsonValue
}

/** Actions a hop's rego policy allows, read from the draft's own clause form
 *  `input.action == "<name>"` (chain-delegation-00 Figure 1 uses exactly this). */
export function allowedActions(hop: LiuHop): Set<string> {
  const out = new Set<string>()
  for (const m of hop.delegated_policy.content.matchAll(/input\.action == "([^"]+)"/g)) out.add(m[1])
  return out
}

/** The chain's narrowed subset is the final hop's allowed set. The harness also
 *  checks the Liu narrowing invariant: every hop's set is a subset of its
 *  parent's. */
export function narrowedSubset(chain: LiuHop[]): { narrowed: Set<string>; monotonic: boolean } {
  let monotonic = true
  for (let i = 1; i < chain.length; i++) {
    const parent = allowedActions(chain[i - 1])
    for (const a of allowedActions(chain[i])) if (!parent.has(a)) monotonic = false
  }
  return { narrowed: allowedActions(chain[chain.length - 1]), monotonic }
}

function loadInput(vector: string): Record<string, JsonValue> {
  return JSON.parse(readFileSync(join(HERE, 'vectors', vector, 'input.json'), 'utf8'))
}

function emitDecisionReceipt(vector: 'v1-permit' | 'v2-denial'): void {
  const input = loadInput(vector)
  const chain = input.delegation_chain as unknown as LiuHop[]
  const authorizationDetails = input.authorization_details as JsonValue
  const ctx = input.rego_decision_context as {
    policy_ref: { id: string; version: string; hash: string }
    evaluated_input: { action: string; item_id: string; agent: string }
    input_hash: string
    result: 'allow' | 'deny'
    evaluation_timestamp: number
  }

  // Fill the 9.7 tuple's input hash from the actual evaluated input, and pin
  // policy_ref.hash to the final hop's rego content in the draft's
  // algorithm-base64value format.
  const finalHop = chain[chain.length - 1]
  ctx.input_hash = `sha256:${digestOf(ctx.evaluated_input as unknown as JsonValue)}`
  ctx.policy_ref.hash = `sha256-${Buffer.from(sha256Hex(finalHop.delegated_policy.content), 'hex').toString('base64')}`

  const { narrowed, monotonic } = narrowedSubset(chain)
  if (!monotonic) throw new Error(`${vector}: fixture violates the narrowing invariant`)
  const requested = ctx.evaluated_input.action
  const inSubset = narrowed.has(requested)
  const expectDeny = vector === 'v2-denial'
  if (expectDeny === inSubset) throw new Error(`${vector}: fixture scope does not match its intent`)
  if ((ctx.result === 'allow') !== inSubset) throw new Error(`${vector}: rego result disagrees with the subset check`)

  const subject = finalHop.delegatee_id
  const actionRefInput = createActionReferenceInputV2({
    agent_id: subject,
    action_type: requested,
    target: `item:${ctx.evaluated_input.item_id}`,
    payload_ref: digestOf(ctx.evaluated_input as unknown as JsonValue),
    scope_required: [requested],
    issued_at: ISSUED_AT,
    // 32 lowercase hex chars, deterministic per vector so re-emits are comparable.
    nonce: sha256Hex(`liu-composition-${vector}`).slice(0, 32),
  })
  const action_ref = computeActionRefV2(actionRefInput)

  const chainState = { delegation_chain: chain } as unknown as JsonValue
  const decisionOutput: CoreDecisionOutputV1 = ctx.result === 'allow'
    ? { profile: 'aps-core-decision-output-v1', verdict: 'permit',
        effective_authority_ref: computeDecisionComponentRefV1('authority', chainState),
        constraints: [...narrowed].sort() }
    : { profile: 'aps-core-decision-output-v1', verdict: 'deny',
        effective_authority_ref: null,
        constraints: [`requested_action_outside_narrowed_subset:${requested}`] }

  const { decision_ref } = buildDecisionRefV1({
    action_ref,
    authority_state: chainState,
    policy_input: ctx.policy_ref as unknown as JsonValue,
    decision_context: {
      policy_ref: ctx.policy_ref, input_hash: ctx.input_hash,
      result: ctx.result, evaluation_timestamp: ctx.evaluation_timestamp,
    } as unknown as JsonValue,
    decision_output: decisionOutput as unknown as JsonValue,
  })

  const evidence_refs: EvidenceRefV1[] = [
    { artifact_type: 'liu-oauth-authorization-evidence-01/authorization_details', sha256: digestOf(authorizationDetails) },
    { artifact_type: 'liu-oauth-chain-delegation-00/delegation_chain', sha256: digestOf(chainState) },
  ]

  const issuerKeys = testKeyPairFromSeed(TEST_SEED_ISSUER)
  const issuer = 'did:aps:test:liu-composition-issuer'
  const receipt: ReceiptV1 = createReceiptV1({
    profile: 'aps-receipt-v1',
    receipt_type: 'policy-decision',
    issuer,
    subject_agent: subject,
    action_ref,
    delegation_ref: `liu-chain:sha256:${digestOf(chainState)}`,
    decision_ref,
    issued_at: ISSUED_AT,
    evidence_refs,
    result: ctx.result === 'allow'
      ? { decision: 'allow', policy_id: ctx.policy_ref.id, narrowed_subset: [...narrowed].sort() }
      : { decision: 'deny', policy_id: ctx.policy_ref.id,
          reason: 'requested_action_outside_narrowed_subset',
          requested_action: requested, narrowed_subset: [...narrowed].sort() },
  }, [{ signer: issuer, key_id: 'test-key-1', private_key: issuerKeys.privateKey }])

  writeFileSync(join(HERE, 'vectors', vector, 'record.json'), JSON.stringify(receipt, null, 1) + '\n')
  writeFileSync(join(HERE, 'vectors', vector, 'keys.json'), JSON.stringify({
    signer: issuer, key_id: 'test-key-1', public_key_hex: issuerKeys.publicKey,
  }, null, 1) + '\n')
  console.log(`${vector}: receipt ${receipt.receipt_id} (${ctx.result})`)
}

async function emitObservation(): Promise<void> {
  const input = loadInput('v3-observation')
  const chain = input.delegation_chain as unknown as LiuHop[]
  const signal = input.revocation_signal as {
    set_jti: string
    revoked_hop: { delegator_id: string; delegatee_id: string }
    revoked_at: string
  }
  const { narrowed } = narrowedSubset(chain)
  const keys = testKeyPairFromSeed(TEST_SEED_OBSERVER)
  const signer = new LocalEd25519Signer({ privateKeyHex: keys.privateKey, keyId: 'observer-key-1' })
  const record = await buildRevocationObservation({
    authority_ref: `liu-chain-hop:${signal.revoked_hop.delegator_id}->${signal.revoked_hop.delegatee_id}`,
    status_source: { kind: 'set', jti: signal.set_jti },
    revoked_at: signal.revoked_at,
    observed_at: OBSERVED_AT,
    maximum_staleness_ms: 300000,
    affected_scope: [...narrowed].sort().join(' '),
    decision: { effect: 'deny' },
  }, signer)
  writeFileSync(join(HERE, 'vectors', 'v3-observation', 'record.json'), JSON.stringify(record, null, 1) + '\n')
  console.log(`v3-observation: observation signed by ${record.observer_key_id}`)
}

export async function emitAll(): Promise<void> {
  emitDecisionReceipt('v1-permit')
  emitDecisionReceipt('v2-denial')
  await emitObservation()
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  emitAll().then(() => console.log('all vectors emitted')).catch(err => { console.error(err); process.exit(1) })
}
