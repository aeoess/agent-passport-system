// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0
//
// Consumer-side check. Imports ONLY the agent-passport-system package root, the
// same boundary an external adapter has. Run it from a project that has
// agent-passport-system@6.0.1 installed from the registry:
//
//   node verify-from-package-root.mjs /path/to/fixtures/priorseal-decision-binding
//
// It regenerates nothing. It reads the committed bytes and reports what the
// released verifier says about them.
//
// Limits of this script, stated so nobody reads more into a green run:
//   - The pinned keys below and the fixtures share one author and one repository.
//     A pass shows internal cryptographic consistency. It is not evidence of signer
//     authority. An adapter pins the keys on its own side.
//   - action_ref is NOT recomputed here. computeActionRefV2 is not exported from the
//     6.0.1 package root. decision_ref IS recomputed, inside the composite verifier.

import { createHash } from 'node:crypto'
import { readFileSync } from 'node:fs'
import { join, resolve } from 'node:path'
import {
  verifyAuthorityDelegationChain,
  verifyReceiptV1Serialized,
  verifyReceiptWithDecisionV1,
} from 'agent-passport-system'

// Pinned in this file, not read from keys.json. keys.json is checked AGAINST these.
const PINNED = {
  receipt: {
    'did:example:agent\u0000key-1': 'f80727401f51c1b7e41eeda7004b29aca9c9d7a017144c31f7370725514d6260',
    'did:example:boundary\u0000key-1': '6468a72acb50bf67fc180d0a092e22d1aa44a43268c8e2dc7b6302dc9199126c',
  },
  delegation: {
    'did:example:principal#key-1': 'd69859e9701161194f0f583a2369d287ce895bf0e96b70db753b9e1e27b2bc94',
  },
  rootIssuer: 'did:example:principal',
}
const resolveKey = (signer, keyId) => PINNED.receipt[`${signer}\u0000${keyId}`]

const dir = resolve(process.argv[2] ?? '.')
const read = rel => readFileSync(join(dir, rel), 'utf8')
let failures = 0
const check = (label, ok, detail = '') => {
  if (!ok) failures++
  console.log(`${ok ? 'ok  ' : 'FAIL'} ${label}${detail ? `  ${detail}` : ''}`)
}
const sameJson = (a, b) => JSON.stringify(a) === JSON.stringify(b)
const keysOf = o => Object.keys(o).sort().join(',')

// 1. The committed bytes are the bytes the producer hashed.
for (const line of read('MANIFEST.sha256').trim().split('\n')) {
  const [digest, rel] = line.split(/\s+/)
  check(`manifest ${rel}`, createHash('sha256').update(read(rel)).digest('hex') === digest)
}

// 2. keys.json agrees with the pins.
const keys = JSON.parse(read('keys.json'))
check('keys.json receipt signers equal the pinned keys',
  keys.receipt_signers.length === 2 && keys.receipt_signers.every(k => PINNED.receipt[`${k.signer}\u0000${k.key_id}`] === k.public_key))
check('keys.json delegation key equals the pinned key',
  keys.delegation_verification_methods.length === 1 && keys.delegation_verification_methods.every(k => PINNED.delegation[k.verification_method] === k.public_key))

const cases = {}
for (const name of ['permit', 'narrow', 'deny', 'expired']) {
  const rawIntent = read(`cases/${name}/action-intent-receipt.json`)
  const rawDecision = read(`cases/${name}/policy-decision-receipt.json`)
  const intent = JSON.parse(rawIntent)
  const decision = JSON.parse(rawDecision)
  const evidence = JSON.parse(read(`cases/${name}/decision-evidence.json`))
  const meta = JSON.parse(read(`cases/${name}/case.json`))
  cases[name] = { decision, evidence }

  // Serialized route over the exact committed bytes: this is what rejects duplicate members.
  check(`${name}: intent receipt verifies from its committed bytes`, verifyReceiptV1Serialized(rawIntent, resolveKey).valid === true)
  check(`${name}: decision receipt verifies from its committed bytes`, verifyReceiptV1Serialized(rawDecision, resolveKey).valid === true)

  // Section 5.3.1. The generic verifier does not enforce these, so they are asserted here.
  check(`${name}: intent receipt_type is aps:action-intent:v1`, intent.receipt_type === 'aps:action-intent:v1')
  check(`${name}: intent issuer equals subject_agent`, intent.issuer === intent.subject_agent)
  check(`${name}: intent has no prev and no decision_ref`, !('prev' in intent) && !('decision_ref' in intent))
  check(`${name}: intent result is exactly the declared result`,
    sameJson(intent.result, { profile: 'aps-action-intent-result-v1', status: 'declared' }))
  check(`${name}: intent is signed by the agent`, intent.signatures.some(s => s.signer === intent.subject_agent))

  // Section 5.3.2.
  check(`${name}: decision receipt_type is aps:policy-decision:v1`, decision.receipt_type === 'aps:policy-decision:v1')
  check(`${name}: decision issuer is not the agent`, decision.issuer !== decision.subject_agent)
  check(`${name}: decision prev is the intent receipt_id`, decision.prev === intent.receipt_id)
  check(`${name}: decision_ref is present`, typeof decision.decision_ref === 'string')
  check(`${name}: both receipts name one agent, action_ref and delegation_ref`,
    decision.subject_agent === intent.subject_agent && decision.action_ref === intent.action_ref && decision.delegation_ref === intent.delegation_ref)
  check(`${name}: decision is issued after the intent`, Date.parse(decision.issued_at) > Date.parse(intent.issued_at))
  check(`${name}: decision result equals decision_evidence.decision_output`, sameJson(decision.result, evidence.decision_output))
  check(`${name}: decision verdict is ${name === 'expired' ? 'permit' : name}`, decision.result.verdict === (name === 'expired' ? 'permit' : name))

  // Section 5.4: the four members authority_state must carry.
  check(`${name}: authority_state has the four required members`,
    keysOf(evidence.authority_state) === 'authority_basis,revocation_observations,selected_chain,spend_state')

  const want = meta.expected.verifyReceiptWithDecisionV1
  const got = verifyReceiptWithDecisionV1(decision, evidence, resolveKey)
  check(`${name}: composite valid is ${want.valid}`, got.valid === want.valid)
  check(`${name}: decision_ref_bound is ${want.decision_ref_bound}`, got.decision_ref_bound === want.decision_ref_bound)
  check(`${name}: errors are ${JSON.stringify(want.errors)}`, sameJson(got.errors, want.errors), JSON.stringify(got.errors))

  const chain = evidence.authority_state.selected_chain
  const chainResult = verifyAuthorityDelegationChain(chain, {
    now: decision.issued_at,
    resolveVerificationKey: (_issuer, method) => PINNED.delegation[method] ?? null,
    trustRoot: candidate => candidate.issuer === PINNED.rootIssuer,
    resolveRevocation: () => 'active',
  })
  check(`${name}: selected delegation chain verifies at the decision time`, chainResult.valid === true, JSON.stringify(chainResult.failures))
  const leaf = chain[chain.length - 1]
  check(`${name}: delegation_ref is the leaf delegation_id and the leaf subject is the agent`,
    leaf.delegation_id === decision.delegation_ref && leaf.subject === decision.subject_agent)

  const validUntil = evidence.decision_output.valid_until
  const unexpired = validUntil === null ? null : Date.parse(validUntil) > Date.parse(keys.reference_time)
  check(`${name}: unexpired at reference time is ${meta.expected.unexpired_at_reference_time}`, unexpired === meta.expected.unexpired_at_reference_time)
}

// 3. Negatives an adapter should also see fail.
const noKey = verifyReceiptWithDecisionV1(cases.permit.decision, cases.permit.evidence, () => undefined)
check('negative: unresolved key fails at receipt_invalid', noKey.valid === false && noKey.errors[0] === 'receipt_invalid')

const wrongKey = verifyReceiptWithDecisionV1(cases.permit.decision, cases.permit.evidence, () => PINNED.receipt['did:example:agent\u0000key-1'])
check('negative: the agent key does not verify a boundary signature', wrongKey.valid === false && wrongKey.errors[0] === 'receipt_invalid')

const swapped = verifyReceiptWithDecisionV1(cases.narrow.decision, cases.permit.evidence, resolveKey)
check('negative: evidence from another case fails at decision_ref_mismatch', swapped.valid === false && swapped.errors.includes('decision_ref_mismatch'))

// The duplicate is injected at the very start of the document, so it is the TOP-LEVEL
// receipt profile that repeats. The mutation is checked before the verifier sees it.
const cleanRaw = read('cases/permit/policy-decision-receipt.json')
const HEAD = '{\n  "profile": "aps-receipt-v1",\n'
const dupRaw = HEAD + '  "profile": "aps-receipt-v1",\n' + cleanRaw.slice(HEAD.length)
const occurrences = text => text.split('"profile": "aps-receipt-v1"').length - 1
check('negative setup: the clean receipt opens with its profile, and the mutation adds exactly one top-level copy',
  cleanRaw.startsWith(HEAD) && occurrences(cleanRaw) === 1 && occurrences(dupRaw) === 2 && dupRaw.length === cleanRaw.length + '  "profile": "aps-receipt-v1",\n'.length)
const dup = verifyReceiptV1Serialized(dupRaw, resolveKey)
check('negative: a duplicated top-level member in the bytes fails at parse_error', dup.valid === false && dup.errors[0] === 'parse_error', JSON.stringify(dup.errors))

const refs = new Set(Object.values(cases).map(c => c.decision.decision_ref))
check('the four decision_ref values are distinct', refs.size === 4)

console.log(failures === 0 ? 'ALL CHECKS PASSED' : `${failures} CHECK(S) FAILED`)
process.exit(failures === 0 ? 0 : 1)
