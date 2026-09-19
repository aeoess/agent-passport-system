// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0
//
// Producer-side generator for the APS inputs promised on
// aeoess/agent-passport-system#163. Built at the v6.0.1 tag.
//
// This file lives inside the SDK repository on purpose. It imports two things
// that are NOT part of the 6.0.1 package-root export surface
// (buildDecisionRefV1 and the aps-action-ref-v2 functions). A consumer never
// runs this file. A consumer loads the committed JSON under cases/ and verifies
// it through the package root, which is what verify-from-package-root.mjs does.
//
// Every key below is derived from a fixed public label. These are TEST KEYS.
// Anyone can recompute them. They must never protect anything.

import { createHash } from 'node:crypto'
import { mkdirSync, readFileSync, readdirSync, rmSync, writeFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

import { publicKeyFromPrivate } from '../../src/crypto/keys.js'
import {
  computeActionRefV2,
  computePayloadRefV1,
  createActionReferenceInputV2,
} from '../../src/v2/action-reference/v2.js'
import {
  AUTHORITY_DELEGATION_RECORD_TYPE,
  AUTHORITY_DELEGATION_VERSION,
  REPUTATION_PROFILE_V1,
  REVERSIBILITY_PROFILE_V1,
  SCOPE_PROFILE_V1,
  VALUES_PROFILE_V1,
  issueAuthorityDelegation,
  verifyAuthorityDelegationChain,
} from '../../src/v2/authority-delegation/index.js'
import type { AuthorityVectorV1 } from '../../src/v2/authority-delegation/index.js'
import { buildDecisionRefV1, normalizeCoreDecisionOutputV1 } from '../../src/v2/receipt-core/decision-ref.js'
import { strictJCS } from '../../src/v2/receipt-core/jcs.js'
import { createReceiptV1, verifyReceiptV1 } from '../../src/v2/receipt-core/receipt.js'
import { verifyReceiptWithDecisionV1 } from '../../src/v2/receipt-core/composite.js'
import type { DecisionEvidenceV1 } from '../../src/v2/receipt-core/composite.js'
import type { CoreDecisionOutputV1, JsonValue, ReceiptV1 } from '../../src/v2/receipt-core/types.js'

const HERE = dirname(fileURLToPath(import.meta.url))
const CASES_DIR = join(HERE, 'cases')
const CHECK_ONLY = process.argv.includes('--check')

const sha256Hex = (s: string | Buffer): string => createHash('sha256').update(s).digest('hex')
const seed = (role: string): string => sha256Hex(`aps-163-priorseal-fixture:${role}:v1`)

// ── Parties ──────────────────────────────────────────────────────────────────
const PRINCIPAL = { id: 'did:example:principal', method: 'did:example:principal#key-1', sk: seed('principal') }
const AGENT = { id: 'did:example:agent', key_id: 'key-1', sk: seed('agent') }
const BOUNDARY = { id: 'did:example:boundary', key_id: 'key-1', sk: seed('boundary') }

// ── Fixed clock ──────────────────────────────────────────────────────────────
const DELEGATION_ISSUED_AT = '2026-09-19T00:00:00.000Z'
const INTENT_ISSUED_AT = '2026-09-19T10:00:00.000Z'
const DECISION_ISSUED_AT = '2026-09-19T10:00:01.000Z'
/** Suggested offline reference time for the consumer's own currency check. */
const REFERENCE_TIME = '2026-09-19T10:05:00.000Z'
const VALID_UNTIL_LIVE = '2026-09-19T10:10:00.000Z' // after REFERENCE_TIME
const VALID_UNTIL_LAPSED = '2026-09-19T10:01:00.000Z' // after issued_at, before REFERENCE_TIME

// ── The one delegation every case selects ────────────────────────────────────
// Visibly local: APS 6.0.1 defines no EVM scope namespace or action type.
const LOCAL_SCOPE = 'fixture:evm:call'
const SPEND_UNIT = 'eip155:31337:native:wei'
const authority: AuthorityVectorV1 = {
  scope: { profile: SCOPE_PROFILE_V1, grants: [LOCAL_SCOPE] },
  spend: { mode: 'bounded', unit: SPEND_UNIT, per_action: '5000000000000000', cumulative: '20000000000000000' },
  depth: { remaining: 0 },
  time: { not_before: DELEGATION_ISSUED_AT, not_after: '2026-10-19T00:00:00.000Z' },
  reputation: { profile: REPUTATION_PROFILE_V1, ceiling: 50 },
  values: { profile: VALUES_PROFILE_V1, required: ['F-001'] },
  reversibility: { profile: REVERSIBILITY_PROFILE_V1, ceiling: 'irreversible' },
}

const delegation = issueAuthorityDelegation({
  record_type: AUTHORITY_DELEGATION_RECORD_TYPE,
  version: AUTHORITY_DELEGATION_VERSION,
  parent_delegation_id: null,
  issuer: PRINCIPAL.id,
  subject: AGENT.id,
  verification_method: PRINCIPAL.method,
  issued_at: DELEGATION_ISSUED_AT,
  nonce: sha256Hex('aps-163-priorseal-fixture:delegation-nonce:v1').slice(0, 32),
  authority,
}, PRINCIPAL.sk)

const chainCheck = verifyAuthorityDelegationChain([delegation], {
  now: DECISION_ISSUED_AT,
  resolveVerificationKey: (_issuer, method) => (method === PRINCIPAL.method ? publicKeyFromPrivate(PRINCIPAL.sk) : null),
  trustRoot: candidate => candidate.issuer === PRINCIPAL.id,
  resolveRevocation: () => 'active',
})
if (!chainCheck.valid) throw new Error(`delegation chain did not verify: ${JSON.stringify(chainCheck.failures)}`)

// ── Case table ───────────────────────────────────────────────────────────────
const TARGET_ADDRESS = '0x000000000000000000000000000000000000dead'
const CONSTRAINT_TO = `fixture:evm.to=${TARGET_ADDRESS}`
const CONSTRAINT_VALUE = 'fixture:evm.value_wei<=1000000000000000'

// effective_authority_ref. draft-03 Section 5.3.2 fixes the shape of this member
// and defines no construction, so both forms below are LOCAL to these inputs.
//
//   permit: the admitted authority is the selected leaf delegation unchanged, so
//   the ref is the hex of its delegation_id. This follows the existing
//   fixtures/oracle-safety-check generator in this repository.
//
//   narrow: the admitted authority is smaller than the leaf, so no existing digest
//   names it. The ref is a domain-separated digest over a fixture-local object.
const EFFECTIVE_AUTHORITY_TAG = 'APS-163-FIXTURE-EFFECTIVE-AUTHORITY-V1'
const EFFECTIVE_AUTHORITY_PROFILE = 'fixture:aps-163-effective-authority-v1'

type EffectiveAuthority =
  | { construction: 'leaf_delegation_id'; delegation_id: string }
  | { construction: 'fixture_local_digest'; domain_tag: string; value: { profile: string; base_delegation_id: string; authority: AuthorityVectorV1 } }

function effectiveAuthorityRef(e: EffectiveAuthority): string {
  if (e.construction === 'leaf_delegation_id') return e.delegation_id.slice('sha256:'.length)
  // One structural conversion: AuthorityVectorV1 is plain JSON data, and strictJCS
  // takes JsonValue. strictJCS itself rejects anything that is not I-JSON.
  return sha256Hex(`${e.domain_tag}\0${strictJCS(e.value as unknown as JsonValue)}`)
}

const LEAF_UNCHANGED: EffectiveAuthority = { construction: 'leaf_delegation_id', delegation_id: delegation.delegation_id }
const NARROWED: EffectiveAuthority = {
  construction: 'fixture_local_digest',
  domain_tag: EFFECTIVE_AUTHORITY_TAG,
  value: {
    profile: EFFECTIVE_AUTHORITY_PROFILE,
    base_delegation_id: delegation.delegation_id,
    authority: {
      ...authority,
      spend: { mode: 'bounded', unit: SPEND_UNIT, per_action: '1000000000000000', cumulative: '1000000000000000' },
    },
  },
}

type CaseName = 'permit' | 'narrow' | 'deny' | 'expired'

interface CaseSpec {
  name: CaseName
  summary: string
  value_wei: string
  verdict: CoreDecisionOutputV1['verdict']
  constraints: string[]
  valid_until: string | null
  effective_authority: EffectiveAuthority | null
}

const SPECS: CaseSpec[] = [
  {
    name: 'permit',
    summary: 'Permit, unexpired at the reference time. The composite verifier returns valid true.',
    value_wei: '1000000000000000', verdict: 'permit', constraints: [],
    valid_until: VALID_UNTIL_LIVE, effective_authority: LEAF_UNCHANGED,
  },
  {
    name: 'narrow',
    summary: 'Narrow with two constraints, unexpired at the reference time. The composite verifier returns valid true. The constraint strings are fixture-local and carry no APS-defined semantics.',
    value_wei: '1000000000000000', verdict: 'narrow', constraints: [CONSTRAINT_TO, CONSTRAINT_VALUE],
    valid_until: VALID_UNTIL_LIVE, effective_authority: NARROWED,
  },
  {
    name: 'deny',
    summary: 'Deny. The receipt signature and the decision binding hold, and the composite verifier returns valid false with valid_until_absent, because a deny carries no validity window.',
    value_wei: '9000000000000000', verdict: 'deny', constraints: [],
    valid_until: null, effective_authority: null,
  },
  {
    name: 'expired',
    summary: 'Permit whose valid_until is after the receipt issued_at and before the reference time. The composite verifier returns valid true. Currency at the reference time is the consumer check, and it must reject this case.',
    value_wei: '1000000000000000', verdict: 'permit', constraints: [],
    valid_until: VALID_UNTIL_LAPSED, effective_authority: LEAF_UNCHANGED,
  },
]

const keyTable: Record<string, string> = {
  [`${AGENT.id}\u0000${AGENT.key_id}`]: publicKeyFromPrivate(AGENT.sk),
  [`${BOUNDARY.id}\u0000${BOUNDARY.key_id}`]: publicKeyFromPrivate(BOUNDARY.sk),
}
const resolveKey = (signer: string, keyId: string): string | undefined => keyTable[`${signer}\u0000${keyId}`]

interface BuiltCase {
  intent: ReceiptV1
  decision: ReceiptV1
  evidence: DecisionEvidenceV1
  meta: {
    case: CaseName
    summary: string
    requested_call: { chain_id: string; to: string; value_wei: string; data: string }
    action_reference_input: ReturnType<typeof createActionReferenceInputV2>
    effective_authority: EffectiveAuthority | null
    expected: {
      verifyReceiptWithDecisionV1: { valid: boolean; decision_ref_present: boolean; decision_ref_bound: boolean; temporal_relation_valid: boolean; errors: string[] }
      unexpired_at_reference_time: boolean | null
    }
  }
}

function buildCase(spec: CaseSpec): BuiltCase {
  const call = { chain_id: '31337', to: TARGET_ADDRESS, value_wei: spec.value_wei, data: '0x' }
  const actionInput = createActionReferenceInputV2({
    agent_id: AGENT.id,
    action_type: LOCAL_SCOPE,
    target: `eip155:31337:${TARGET_ADDRESS}`,
    payload_ref: computePayloadRefV1(call),
    scope_required: [LOCAL_SCOPE],
    issued_at: INTENT_ISSUED_AT,
    nonce: sha256Hex(`aps-163-priorseal-fixture:action-nonce:${spec.name}:v1`).slice(0, 32),
  })
  const action_ref = computeActionRefV2(actionInput)

  // Section 5.3.1: the agent declares the action before policy evaluation.
  const intent = createReceiptV1({
    profile: 'aps-receipt-v1',
    receipt_type: 'aps:action-intent:v1',
    issuer: AGENT.id,
    subject_agent: AGENT.id,
    action_ref,
    delegation_ref: delegation.delegation_id,
    issued_at: INTENT_ISSUED_AT,
    evidence_refs: [],
    result: { profile: 'aps-action-intent-result-v1', status: 'declared' },
  }, [{ signer: AGENT.id, key_id: AGENT.key_id, private_key: AGENT.sk }])

  // Normalized ONCE. This exact object is the evidence member, the receipt result and
  // the input to buildDecisionRefV1. The builder normalizes internally without touching
  // its argument, so an unnormalized object here would still verify while the committed
  // record broke the Section 5.3.2 rule that constraints are NFC, unique and sorted.
  const declared_output: CoreDecisionOutputV1 = {
    profile: 'aps-core-decision-output-v1',
    verdict: spec.verdict,
    effective_authority_ref: spec.effective_authority === null ? null : effectiveAuthorityRef(spec.effective_authority),
    constraints: spec.constraints,
    valid_until: spec.valid_until,
  }
  const decision_output = normalizeCoreDecisionOutputV1(declared_output)
  if (JSON.stringify(decision_output) !== JSON.stringify(declared_output)) {
    throw new Error(`${spec.name}: the case table declares a decision output that is not already canonical`)
  }

  // Section 5.4: authority_state carries the selected chain, the authority-basis
  // resolution, the revocation observations and the spend state the decision used.
  // The signed delegation record is plain JSON data, hence the one conversion.
  const evidence: DecisionEvidenceV1 = {
    authority_state: {
      selected_chain: [delegation as unknown as JsonValue],
      authority_basis: { kind: 'verifier_selected_root', root_issuer: PRINCIPAL.id },
      revocation_observations: [{ delegation_id: delegation.delegation_id, state: 'active', observed_at: DECISION_ISSUED_AT }],
      spend_state: { unit: SPEND_UNIT, cumulative_spent: '0' },
    },
    policy_input: { policy_id: 'fixture:evm-call-policy', policy_version: '1', requested_call: call },
    decision_context: { evaluated_at: DECISION_ISSUED_AT },
    decision_output,
  }

  const { decision_ref } = buildDecisionRefV1({ action_ref, ...evidence })

  // Section 5.3.2: the enforcement boundary issues the decision, prev is the intent.
  const decision = createReceiptV1({
    profile: 'aps-receipt-v1',
    receipt_type: 'aps:policy-decision:v1',
    issuer: BOUNDARY.id,
    subject_agent: AGENT.id,
    action_ref,
    delegation_ref: delegation.delegation_id,
    decision_ref,
    issued_at: DECISION_ISSUED_AT,
    evidence_refs: [],
    result: { ...decision_output },
    prev: intent.receipt_id,
  }, [{ signer: BOUNDARY.id, key_id: BOUNDARY.key_id, private_key: BOUNDARY.sk }])

  if (!verifyReceiptV1(intent, resolveKey).valid) throw new Error(`${spec.name}: intent receipt did not verify`)
  const composite = verifyReceiptWithDecisionV1(decision, evidence, resolveKey)

  return {
    intent, decision, evidence,
    meta: {
      case: spec.name,
      summary: spec.summary,
      requested_call: call,
      action_reference_input: actionInput,
      effective_authority: spec.effective_authority,
      expected: {
        verifyReceiptWithDecisionV1: {
          valid: composite.valid,
          decision_ref_present: composite.decision_ref_present,
          decision_ref_bound: composite.decision_ref_bound,
          temporal_relation_valid: composite.temporal_relation_valid,
          errors: composite.errors,
        },
        unexpired_at_reference_time: spec.valid_until === null ? null : Date.parse(spec.valid_until) > Date.parse(REFERENCE_TIME),
      },
    },
  }
}

// What each case must produce. Stated here, not read back from the verifier, so a
// change in verifier behavior fails generation instead of rewriting the expectation.
const REQUIRED: Record<CaseName, { valid: boolean; bound: boolean; errors: string[]; unexpired: boolean | null }> = {
  permit: { valid: true, bound: true, errors: [], unexpired: true },
  narrow: { valid: true, bound: true, errors: [], unexpired: true },
  deny: { valid: false, bound: true, errors: ['valid_until_absent'], unexpired: null },
  expired: { valid: true, bound: true, errors: [], unexpired: false },
}

const outputs = new Map<string, string>()
const put = (rel: string, value: unknown): void => { outputs.set(rel, `${JSON.stringify(value, null, 2)}\n`) }

const seenDecisionRefs = new Set<string>()
for (const spec of SPECS) {
  const built = buildCase(spec)
  const got = built.meta.expected.verifyReceiptWithDecisionV1
  const want = REQUIRED[spec.name]
  if (got.valid !== want.valid || got.decision_ref_bound !== want.bound ||
      JSON.stringify(got.errors) !== JSON.stringify(want.errors) ||
      built.meta.expected.unexpired_at_reference_time !== want.unexpired) {
    throw new Error(`${spec.name}: outcome differs from the required one: ${JSON.stringify(built.meta.expected)}`)
  }
  const ref = built.decision.decision_ref
  if (ref === undefined || seenDecisionRefs.has(ref)) throw new Error(`${spec.name}: decision_ref missing or shared with another case`)
  seenDecisionRefs.add(ref)
  put(`cases/${spec.name}/action-intent-receipt.json`, built.intent)
  put(`cases/${spec.name}/policy-decision-receipt.json`, built.decision)
  put(`cases/${spec.name}/decision-evidence.json`, built.evidence)
  put(`cases/${spec.name}/case.json`, built.meta)
}

put('keys.json', {
  note: 'TEST KEYS derived from public labels. Public halves only. A consumer pins these values on its own side and does not trust this file because it arrived next to the cases.',
  alg: 'Ed25519',
  encoding: 'raw 32-byte public key, lowercase hex',
  receipt_signers: [
    { signer: AGENT.id, key_id: AGENT.key_id, public_key: publicKeyFromPrivate(AGENT.sk), signs: 'aps:action-intent:v1' },
    { signer: BOUNDARY.id, key_id: BOUNDARY.key_id, public_key: publicKeyFromPrivate(BOUNDARY.sk), signs: 'aps:policy-decision:v1' },
  ],
  delegation_verification_methods: [
    { issuer: PRINCIPAL.id, verification_method: PRINCIPAL.method, public_key: publicKeyFromPrivate(PRINCIPAL.sk) },
  ],
  reference_time: REFERENCE_TIME,
})

const manifestLines = [...outputs.entries()]
  .sort(([a], [b]) => (a < b ? -1 : 1))
  .map(([rel, body]) => `${sha256Hex(body)}  ${rel}`)
outputs.set('MANIFEST.sha256', `${manifestLines.join('\n')}\n`)

function listCaseFiles(): string[] {
  const found: string[] = []
  let names: string[] = []
  try { names = readdirSync(CASES_DIR) } catch { return found }
  for (const name of names) for (const f of readdirSync(join(CASES_DIR, name))) found.push(`cases/${name}/${f}`)
  return found
}

if (CHECK_ONLY) {
  let drift = 0
  for (const [rel, body] of outputs) {
    let onDisk = ''
    try { onDisk = readFileSync(join(HERE, rel), 'utf8') } catch { /* missing counts as drift */ }
    if (onDisk !== body) { drift++; console.error(`DRIFT ${rel}`) }
  }
  for (const rel of listCaseFiles()) if (!outputs.has(rel)) { drift++; console.error(`STRAY ${rel}`) }
  console.log(`checked ${outputs.size} files, drift ${drift}`)
  process.exit(drift === 0 ? 0 : 1)
}

rmSync(CASES_DIR, { recursive: true, force: true })
for (const [rel, body] of outputs) {
  mkdirSync(dirname(join(HERE, rel)), { recursive: true })
  writeFileSync(join(HERE, rel), body)
}
console.log(`wrote ${outputs.size} files`)
