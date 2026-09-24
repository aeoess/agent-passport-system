// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0
//
// Conformance and cross-language parity for the PROPOSED activation-condition module.
//
// Every expectation comes from conformance/activation/v0/vectors.json, which is the SHARED
// fixture: the Python SDK vendors a byte-identical copy and runs the same cases through its
// own port. Expectations are hand specified in the generator that emits the file, never
// computed by the code under test, so the test is not circular. The file's SHA-256 is pinned
// in both repositories, so the two copies can be shown identical without either repo
// importing the other.

import { test, describe } from 'node:test'
import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

import {
  ACTIVATION_ASSERTIONS,
  ACTIVATION_ATTESTATION_ID_DOMAIN,
  ACTIVATION_ATTESTATION_SIGNATURE_DOMAIN,
  ACTIVATION_ATTESTATION_TYPE,
  ACTIVATION_CONDITION_KINDS,
  ACTIVATION_CONDITION_SIGNATURE_DOMAIN,
  ACTIVATION_CONDITION_TYPE,
  ACTIVATION_FINDINGS,
  ACTIVATION_INSTANT_BASES,
  ACTIVATION_REASON_CODES,
  ATTESTOR_ROLE_STANDINGS,
  ActivationError,
  activationAttestationBody,
  activationAttestationSignatureInput,
  activationConditionSignatureInput,
  composeActivation,
  computeActivationAttestationId,
  validateActivationCondition,
  verifyActivation,
  type ActivationAttestationV0,
  type ActivationConditionV0,
  type ActivationResult,
  type AttestorRoleStanding,
} from '../../src/v2/activation/index.js'
import type { AuthorityValidationResult } from '../../src/v2/authority-delegation/types.js'

const here = dirname(fileURLToPath(import.meta.url))
const vectorsPath = join(here, '..', '..', 'conformance', 'activation', 'v0', 'vectors.json')
const vectorsBytes = readFileSync(vectorsPath)

/** Pinned so the Python SDK's vendored copy can be shown byte identical. If this moves, the
 *  Python repo's copy and its own pin move with it, in the same change. */
const VECTORS_SHA256 = '9340152cc3ddd4c0ac02d07b8cb8ccb85f7174ab72e4ffab6ad279d6027ee48e'

interface Vectors {
  profile: string
  status: string
  vocabulary: {
    condition_kinds: string[]
    instant_bases: string[]
    assertions: string[]
    attestor_role_standings: string[]
    findings: string[]
    reason_codes: string[]
  }
  record_types: { condition: string; attestation: string }
  verification_keys: Record<string, string>
  attestor_role_registry: Record<string, string[]>
  clock: Record<string, string>
  delegation_id: string
  conditions: Record<string, Record<string, unknown>>
  attestations: Record<string, ActivationAttestationV0>
  condition_validation_cases: Array<{
    id: string
    condition: Record<string, unknown>
    expected: { ok: boolean; error_code?: string }
  }>
  verify_cases: Array<{
    id: string
    condition: string
    action_at: string
    presented: string[]
    expected: {
      verdict: string
      reason_code: string
      missing?: string[]
      findings: Array<{ attestation: string; finding: string }>
      rejections: Array<{ attestation: string; reason_code: string }>
    }
  }>
  compose_cases: Array<{
    id: string
    chain_result: AuthorityValidationResult
    activation_from_case: string | null
    mapping?: { not_yet_valid_as_not_yet_effective?: boolean }
    expected: {
      chain_state: string
      lifecycle_verdict: string
      lifecycle_reason_code: string
      lifecycle_missing?: string[]
    }
  }>
}

const vectors = JSON.parse(vectorsBytes.toString('utf8')) as Vectors

/** Role standing resolved OUTSIDE the record, from the vectors' own registry. An attestor the
 *  registry has never heard of is `unknown` for every role: ignorance, never a denial. */
function resolveAttestorRole(attestor: string, role: string): AttestorRoleStanding {
  const held = vectors.attestor_role_registry[attestor]
  if (held === undefined) return 'unknown'
  return held.includes(role) ? 'holds' : 'does_not_hold'
}

/** Keyed on the verification method alone, so a record naming one attestor while presenting
 *  another's method still resolves a key and the attestor-binding check is what catches it. */
function resolveVerificationKey(_attestor: string, method: string): string | null {
  return vectors.verification_keys[method] ?? null
}

function conditionOf(label: string): ActivationConditionV0 {
  return vectors.conditions[label] as unknown as ActivationConditionV0
}

function runVerifyCase(id: string): ActivationResult {
  const vector = vectors.verify_cases.find(c => c.id === id)
  assert.ok(vector, `verify case ${id} is in the vectors`)
  return verifyActivation({
    condition: conditionOf(vector.condition),
    delegationId: vectors.delegation_id,
    actionInstant: vectors.clock[vector.action_at],
    attestations: vector.presented.map(label => vectors.attestations[label]),
    resolveAttestorRole,
    resolveVerificationKey,
  })
}

describe('activation vectors: integrity and vocabulary', () => {
  test('the shared vectors file is the pinned one', () => {
    assert.equal(createHash('sha256').update(vectorsBytes).digest('hex'), VECTORS_SHA256)
  })

  test('the file states it is proposed', () => {
    assert.equal(vectors.profile, 'aps-activation-v0')
    assert.equal(vectors.status, 'proposed')
  })

  test('the vocabulary in the file is the vocabulary the module exports', () => {
    assert.deepEqual(vectors.vocabulary.condition_kinds, [...ACTIVATION_CONDITION_KINDS])
    assert.deepEqual(vectors.vocabulary.instant_bases, [...ACTIVATION_INSTANT_BASES])
    assert.deepEqual(vectors.vocabulary.assertions, [...ACTIVATION_ASSERTIONS])
    assert.deepEqual(vectors.vocabulary.attestor_role_standings, [...ATTESTOR_ROLE_STANDINGS])
    assert.deepEqual(vectors.vocabulary.findings, [...ACTIVATION_FINDINGS])
    assert.deepEqual(vectors.vocabulary.reason_codes, [...ACTIVATION_REASON_CODES])
    assert.equal(vectors.record_types.condition, ACTIVATION_CONDITION_TYPE)
    assert.equal(vectors.record_types.attestation, ACTIVATION_ATTESTATION_TYPE)
  })

  test('the record types carry a proposed namespace, so nothing here reads as minted APS vocabulary', () => {
    assert.ok(ACTIVATION_CONDITION_TYPE.startsWith('proposed:'))
    assert.ok(ACTIVATION_ATTESTATION_TYPE.startsWith('proposed:'))
  })

  test('every domain tag says PROPOSED and ends in one zero byte', () => {
    for (const domain of [
      ACTIVATION_ATTESTATION_SIGNATURE_DOMAIN,
      ACTIVATION_ATTESTATION_ID_DOMAIN,
      ACTIVATION_CONDITION_SIGNATURE_DOMAIN,
    ]) {
      assert.ok(domain.includes('PROPOSED'), domain)
      assert.ok(domain.endsWith('\0'), domain)
      assert.equal(domain.indexOf('\0'), domain.length - 1, domain)
    }
  })

  test('the three domain tags are distinct, so bytes minted for one are never read as another', () => {
    const domains = new Set([
      ACTIVATION_ATTESTATION_SIGNATURE_DOMAIN,
      ACTIVATION_ATTESTATION_ID_DOMAIN,
      ACTIVATION_CONDITION_SIGNATURE_DOMAIN,
    ])
    assert.equal(domains.size, 3)
  })
})

describe('activation canonical bytes', () => {
  const attestation = vectors.attestations.ATT_OCCURRED_ON_TIME

  test('the signed body excludes exactly the two members derived from it', () => {
    const body = activationAttestationBody(attestation)
    assert.ok(!('attestation_id' in body))
    assert.ok(!('signature' in body))
    assert.equal(Object.keys(body).length, Object.keys(attestation).length - 2)
  })

  test('every other member is inside the preimage, including ones this module never reads', () => {
    const preimage = activationAttestationSignatureInput({
      ...attestation,
      operator_note: 'rides along',
    })
    assert.ok(preimage.includes('operator_note'))
  })

  test('the identifier is recomputable from the body rather than taken on trust', () => {
    assert.equal(computeActivationAttestationId(attestation), attestation.attestation_id)
  })

  test('the identifier changes when any signed member changes', () => {
    assert.notEqual(
      computeActivationAttestationId({ ...attestation, occurred_at: '2026-09-20T09:00:01.000Z' }),
      attestation.attestation_id,
    )
  })

  test('a condition preimage is available for a deployment that signs its conditions', () => {
    const input = activationConditionSignatureInput(conditionOf('COND_EVENT'))
    assert.ok(input.startsWith(ACTIVATION_CONDITION_SIGNATURE_DOMAIN))
  })
})

describe('validateActivationCondition: shape rules are thrown, never verdicts', () => {
  for (const vector of vectors.condition_validation_cases) {
    test(vector.id, () => {
      if (vector.expected.ok) {
        const validated = validateActivationCondition(
          vector.condition as unknown as ActivationConditionV0,
        )
        assert.equal(validated, vector.condition)
        return
      }
      assert.throws(
        () => validateActivationCondition(vector.condition as unknown as ActivationConditionV0),
        (error: unknown) => {
          assert.ok(error instanceof ActivationError)
          assert.equal(error.code, vector.expected.error_code)
          return true
        },
      )
    })
  }
})

describe('verifyActivation: the shared vectors', () => {
  for (const vector of vectors.verify_cases) {
    test(vector.id, () => {
      const result = runVerifyCase(vector.id)
      assert.equal(result.state.verdict, vector.expected.verdict, 'verdict')
      assert.equal(result.state.reason_code, vector.expected.reason_code, 'reason code')
      assert.deepEqual(
        result.state.missing === undefined ? undefined : [...result.state.missing],
        vector.expected.missing,
        'establishment limbs',
      )
      assert.deepEqual(
        result.findings.map(f => ({
          attestation: f.attestation_id,
          finding: f.finding,
        })),
        vector.expected.findings.map(f => ({
          attestation: vectors.attestations[f.attestation].attestation_id,
          finding: f.finding,
        })),
        'findings',
      )
      assert.deepEqual(
        result.rejections.map(r => ({
          attestation: r.attestation_id,
          reason_code: r.reason_code,
        })),
        vector.expected.rejections.map(r => ({
          attestation: vectors.attestations[r.attestation].attestation_id,
          reason_code: r.reason_code,
        })),
        'rejections',
      )
      assert.equal(result.condition_id, conditionOf(vector.condition).condition_id)
    })
  }

  test('invalid is NEVER a verdict this module reaches, across every vector', () => {
    for (const vector of vectors.verify_cases) {
      assert.notEqual(runVerifyCase(vector.id).state.verdict, 'invalid', vector.id)
    }
  })

  test('only three of the six lifecycle verdicts are reachable here', () => {
    const reached = new Set(vectors.verify_cases.map(v => runVerifyCase(v.id).state.verdict))
    assert.deepEqual(
      [...reached].sort(),
      ['not_established', 'not_yet_effective', 'valid'],
    )
  })

  test('every not_established verdict names at least one establishment limb', () => {
    for (const vector of vectors.verify_cases) {
      const state = runVerifyCase(vector.id).state
      if (state.verdict !== 'not_established') continue
      assert.ok(state.missing !== undefined && state.missing.length > 0, vector.id)
    }
  })

  test('freshness is never claimed, because this module is given no bound to measure against', () => {
    for (const vector of vectors.verify_cases) {
      const state = runVerifyCase(vector.id).state
      assert.ok(!(state.missing ?? []).includes('freshness'), vector.id)
    }
  })

  test('one entry per presented attestation, across findings and rejections', () => {
    for (const vector of vectors.verify_cases) {
      if (conditionOf(vector.condition).condition_type === 'date') continue
      if (vector.expected.reason_code === 'CONDITION_DELEGATION_MISMATCH') continue
      const result = runVerifyCase(vector.id)
      assert.equal(
        result.findings.length + result.rejections.length,
        vector.presented.length,
        vector.id,
      )
    }
  })

  test('the result is frozen, so a caller cannot edit a verdict after the fact', () => {
    const result = runVerifyCase('AC-01-occurrence-before-action-valid')
    assert.ok(Object.isFrozen(result))
    assert.ok(Object.isFrozen(result.findings))
    assert.ok(Object.isFrozen(result.rejections))
  })
})

describe('verifyActivation: call-site rules', () => {
  const base = {
    condition: conditionOf('COND_EVENT'),
    delegationId: 'acv-grant-1',
    actionInstant: '2026-09-20T10:00:00.000Z',
    resolveAttestorRole,
    resolveVerificationKey,
  }

  test('a role resolver is required, because standing is resolved outside the record always', () => {
    assert.throws(
      () => verifyActivation({ ...base, resolveAttestorRole: undefined as never }),
      (e: unknown) => (e as ActivationError).code === 'ROLE_RESOLVER_REQUIRED',
    )
  })

  test('a role resolver is required even for a date condition, so the event path needs no new plumbing later', () => {
    assert.throws(
      () =>
        verifyActivation({
          ...base,
          condition: conditionOf('COND_DATE'),
          resolveAttestorRole: undefined as never,
        }),
      (e: unknown) => (e as ActivationError).code === 'ROLE_RESOLVER_REQUIRED',
    )
  })

  test('a key resolver is required', () => {
    assert.throws(
      () => verifyActivation({ ...base, resolveVerificationKey: undefined as never }),
      (e: unknown) => (e as ActivationError).code === 'KEY_RESOLVER_REQUIRED',
    )
  })

  test('a delegation id is required', () => {
    assert.throws(
      () => verifyActivation({ ...base, delegationId: '' }),
      (e: unknown) => (e as ActivationError).code === 'DELEGATION_ID_REQUIRED',
    )
  })

  test('a malformed action instant throws rather than producing a verdict', () => {
    assert.throws(
      () => verifyActivation({ ...base, actionInstant: '2026-09-20' }),
      (e: unknown) => (e as ActivationError).code === 'INSTANT_MALFORMED',
    )
  })

  test('a caller-supplied preimage must come with the record types the model accepts', () => {
    assert.throws(
      () => verifyActivation({ ...base, attestationPreimage: () => 'x' }),
      (e: unknown) => (e as ActivationError).code === 'ACCEPTED_RECORD_TYPES_REQUIRED',
    )
  })

  test('this function reads no clock: the same call at any wall time gives the same answer', () => {
    const first = runVerifyCase('AC-30-date-not-reached-not-yet-effective')
    const second = runVerifyCase('AC-30-date-not-reached-not-yet-effective')
    assert.deepEqual(first.state, second.state)
  })
})

describe('verifyActivation: the escape hatch for evidence this module does not own', () => {
  // A model can accept condition evidence in a record shape this module never defined. Which
  // bytes a signature covers is a property of a record type, so the caller supplies both the
  // preimage and the types it accepts. This is the path the lab fixture family takes.
  const FOREIGN_TYPE = 'fixture:some-other-attestation:v0'
  const foreign = vectors.attestations.ATT_WRONG_RECORD_TYPE

  test('a declared foreign record type is accepted when the caller supplies its preimage', () => {
    const result = verifyActivation({
      condition: conditionOf('COND_EVENT'),
      delegationId: vectors.delegation_id,
      actionInstant: vectors.clock.T_ACTION,
      attestations: [foreign],
      resolveAttestorRole,
      resolveVerificationKey,
      acceptedAttestationRecordTypes: [FOREIGN_TYPE],
      attestationPreimage: activationAttestationSignatureInput,
    })
    assert.equal(result.state.verdict, 'valid')
    assert.equal(result.state.reason_code, 'ACTIVATION_ESTABLISHED')
  })

  test('an undeclared record type is still rejected even with a preimage supplied', () => {
    const result = verifyActivation({
      condition: conditionOf('COND_EVENT'),
      delegationId: vectors.delegation_id,
      actionInstant: vectors.clock.T_ACTION,
      attestations: [foreign],
      resolveAttestorRole,
      resolveVerificationKey,
      acceptedAttestationRecordTypes: ['fixture:something-else:v0'],
      attestationPreimage: activationAttestationSignatureInput,
    })
    assert.equal(result.state.verdict, 'not_established')
    assert.equal(result.state.reason_code, 'ATTESTATION_RECORD_TYPE_NOT_ACCEPTED')
  })

  test('a preimage that does not match the signed bytes rejects the record', () => {
    const result = verifyActivation({
      condition: conditionOf('COND_EVENT'),
      delegationId: vectors.delegation_id,
      actionInstant: vectors.clock.T_ACTION,
      attestations: [foreign],
      resolveAttestorRole,
      resolveVerificationKey,
      acceptedAttestationRecordTypes: [FOREIGN_TYPE],
      attestationPreimage: () => 'bytes nobody signed',
    })
    assert.equal(result.state.reason_code, 'ATTESTATION_SIGNATURE_UNVERIFIED')
  })
})

describe('composeActivation: reported alongside a chain result, never merged into it', () => {
  for (const vector of vectors.compose_cases) {
    test(vector.id, () => {
      const activation =
        vector.activation_from_case === null ? null : runVerifyCase(vector.activation_from_case)
      const composite = composeActivation(vector.chain_result, activation, {
        mapping:
          vector.mapping === undefined
            ? undefined
            : {
                notYetValidAsNotYetEffective: vector.mapping.not_yet_valid_as_not_yet_effective,
              },
      })
      assert.equal(composite.chain.state, vector.expected.chain_state, 'chain state')
      assert.equal(
        composite.lifecycle?.verdict,
        vector.expected.lifecycle_verdict,
        'lifecycle verdict',
      )
      assert.equal(
        composite.lifecycle?.reason_code,
        vector.expected.lifecycle_reason_code,
        'lifecycle reason code',
      )
      assert.deepEqual(
        composite.lifecycle?.missing === undefined ? undefined : [...composite.lifecycle.missing],
        vector.expected.lifecycle_missing,
        'establishment limbs',
      )
    })
  }

  test('the chain result is returned byte for byte, never rewritten', () => {
    const chain: AuthorityValidationResult = { state: 'valid', valid: true, failures: [] }
    const before = JSON.stringify(chain)
    const composite = composeActivation(
      chain,
      runVerifyCase('AC-15-accepted-negative-not-yet-effective'),
    )
    assert.equal(composite.chain, chain)
    assert.equal(JSON.stringify(chain), before)
  })

  test('nothing in this module can turn an invalid chain into a valid lifecycle verdict', () => {
    for (const state of ['invalid', 'indeterminate', 'unsupported'] as const) {
      const composite = composeActivation(
        {
          state,
          valid: false,
          failures: [{ code: 'REVOKED', message: 'revoked', index: 0 }],
        } as AuthorityValidationResult,
        runVerifyCase('AC-01-occurrence-before-action-valid'),
      )
      assert.notEqual(composite.lifecycle?.verdict, 'valid', state)
    }
  })

  test('INVARIANT L1: a revoked pre-committing instrument is not rescued by activation evidence', () => {
    // CAND-13's pre-committed replacement grant is an ordinary grant with an ordinary
    // condition. The ordering is what keeps L1 intact.
    const composite = composeActivation(
      {
        state: 'invalid',
        valid: false,
        failures: [{ code: 'REVOKED', message: 'ancestor revoked', index: 0 }],
      } as AuthorityValidationResult,
      runVerifyCase('AC-01-occurrence-before-action-valid'),
    )
    assert.equal(composite.lifecycle?.verdict, 'invalid')
    assert.equal(composite.lifecycle?.reason_code, 'REVOKED')
  })
})
