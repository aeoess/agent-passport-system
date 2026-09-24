// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0
//
// Conformance and cross-language parity for the PROPOSED authority-state surface: markers,
// the monotonicity comparison, the fencing gate on a write, and withdrawal of a recorded
// revocation.
//
// Every expectation in the vector-driven sections comes from
// conformance/authority-state/v0/vectors.json, which is the SHARED fixture: the Python SDK
// vendors a byte-identical copy and runs the same cases through its own port. Expectations
// are hand specified in the vectors, never computed by the code under test. The file's
// SHA-256 is pinned in both repositories, so the two copies can be shown identical without
// either repo importing the other.
//
// The sections after the vectors are the parts that need real Ed25519 records, so they
// cannot live in a language-neutral vector file. Every record in them is minted by the
// modules under test. No digest, identifier or signature is written down by hand.

import { test, describe } from 'node:test'
import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

import { publicKeyFromPrivate } from '../../src/crypto/keys.js'
import {
  AUTHORITY_DELEGATION_RECORD_TYPE,
  AUTHORITY_DELEGATION_VERSION,
  REPUTATION_PROFILE_V1,
  REVERSIBILITY_PROFILE_V1,
  SCOPE_PROFILE_V1,
  VALUES_PROFILE_V1,
  issueAuthorityDelegation,
  issueSubAuthorityDelegation,
  verifyAuthorityDelegationChain,
} from '../../src/v2/authority-delegation/index.js'
import type {
  AuthorityDelegationBodyV1,
  AuthorityDelegationV1,
  RevocationResolution,
} from '../../src/v2/authority-delegation/index.js'
import {
  InMemoryAuthorityRevocationStore,
  createAuthorityRevocationResolver,
  issueAuthorityRevocation,
  recordAuthorityRevocation,
  verifyAuthorityRevocation,
} from '../../src/v2/authority-revocation/index.js'
import type { AuthorityRevocationV1 } from '../../src/v2/authority-revocation/index.js'
import {
  STATE_MARKER_SCOPES,
  MONOTONICITY_OUTCOMES,
  UNPLACEABLE_DISPOSITIONS,
  FENCED_WRITE_REFUSAL_CODES,
  WITHDRAWAL_STANDINGS,
  WITHDRAWAL_OUTCOME_CODES,
  REVOCATION_WITHDRAWAL_RECORD_TYPE,
  REVOCATION_WITHDRAWAL_VERSION,
  AuthorityStateError,
  FencedAuthorityStateLog,
  advanceHighWaterMark,
  authorityStateReport,
  compareStateMarker,
  correctedRevocationView,
  createMonotonicRevocationResolver,
  evaluateRevocationWithdrawal,
  reportAuthorityState,
  resolveUnderRetainedState,
  revocationWithdrawal,
  stateMarker,
  withdrawalSignerIsRevoker,
} from '../../src/v2/authority-state/index.js'
import type {
  RevocationWithdrawalV0,
  StateMarker,
  WithdrawalStanding,
  WithdrawalStandingResolver,
} from '../../src/v2/authority-state/index.js'

const here = dirname(fileURLToPath(import.meta.url))
const vectorsPath = join(here, '..', '..', 'conformance', 'authority-state', 'v0', 'vectors.json')
const vectorsBytes = readFileSync(vectorsPath)

/** Pinned so the Python SDK's vendored copy can be shown byte identical. If this moves, the
 *  Python repo's copy and its own pin move with it, in the same change. */
const VECTORS_SHA256 = '4c2292d56f4e26fee62e7d70518d1d4a2fc5d7b2762ebfe4d3e8bc804cd15f45'

interface MarkerLiteral {
  value: string
  scope: string
  scope_ref?: string
}

interface Vectors {
  profile: string
  vocabulary: {
    state_marker_scopes: string[]
    monotonicity_outcomes: string[]
    unplaceable_dispositions: string[]
    fenced_write_refusal_codes: string[]
    withdrawal_standings: string[]
    withdrawal_outcome_codes: string[]
    revocation_withdrawal_record_type: string
    revocation_withdrawal_version: string
  }
  marker_cases: Array<{
    id: string
    input: MarkerLiteral
    expected: { ok: boolean; marker?: MarkerLiteral; error_code?: string }
  }>
  comparison_cases: Array<{
    id: string
    established: MarkerLiteral | null
    presented: MarkerLiteral | null
    expected: { outcome: string; high_water_mark_after: MarkerLiteral | null }
  }>
  routing_cases: Array<{
    id: string
    established: MarkerLiteral | null
    presented_marker: MarkerLiteral | null
    presented_answer: RevocationResolution
    retained_records_present: boolean
    on_unplaceable: string
    expected: { monotonicity: string; resolution: string; high_water_mark_after: MarkerLiteral | null }
  }>
  fencing_cases: Array<{
    id: string
    writes: Array<{
      token: MarkerLiteral | null
      payload: string
      expected: { accepted: boolean; code?: string }
    }>
    expected: { published_payload: string | null; highest_token: MarkerLiteral | null }
  }>
  withdrawal_cases: Array<{
    id: string
    held: Array<{ revocation_id: string; delegation_id: string; revoker: string }>
    withdrawal: Record<string, unknown>
    standing_resolver: string
    expected: { accepted: boolean; reason_code: string; standing: string | null }
  }>
  corrected_view_cases: Array<{
    id: string
    revocation: { revocation_id: string; delegation_id: string; revoker: string }
    withdrawals: Array<Record<string, unknown>>
    standing_resolver: string
    expected: {
      revocation_present: boolean
      accepted_count: number
      refused_count: number
      accepted_reason_codes: string[]
      refused_reason_codes: string[]
    }
  }>
}

const vectors = JSON.parse(vectorsBytes.toString('utf8')) as Vectors

/** A marker literal from the vectors, as the type the API takes. The vectors carry shapes
 *  the constructor is meant to reject, so the negative cases deliberately bypass it. */
function asMarker(literal: MarkerLiteral | null): StateMarker | null {
  return literal === null ? null : (literal as unknown as StateMarker)
}

const STANDING_RESOLVERS: Readonly<Record<string, WithdrawalStandingResolver>> = Object.freeze({
  signer_is_revoker: withdrawalSignerIsRevoker,
  always_unknown: () => 'unknown' as WithdrawalStanding,
  always_has_standing: () => 'has_standing' as WithdrawalStanding,
})

describe('authority-state: shared fixture', () => {
  test('the vectors file is the pinned bytes', () => {
    assert.equal(createHash('sha256').update(vectorsBytes).digest('hex'), VECTORS_SHA256)
  })

  test('the vocabulary in the vectors is the vocabulary the module exports', () => {
    assert.deepEqual([...STATE_MARKER_SCOPES], vectors.vocabulary.state_marker_scopes)
    assert.deepEqual([...MONOTONICITY_OUTCOMES], vectors.vocabulary.monotonicity_outcomes)
    assert.deepEqual([...UNPLACEABLE_DISPOSITIONS], vectors.vocabulary.unplaceable_dispositions)
    assert.deepEqual([...FENCED_WRITE_REFUSAL_CODES], vectors.vocabulary.fenced_write_refusal_codes)
    assert.deepEqual([...WITHDRAWAL_STANDINGS], vectors.vocabulary.withdrawal_standings)
    assert.deepEqual([...WITHDRAWAL_OUTCOME_CODES], vectors.vocabulary.withdrawal_outcome_codes)
    assert.equal(REVOCATION_WITHDRAWAL_RECORD_TYPE, vectors.vocabulary.revocation_withdrawal_record_type)
    assert.equal(REVOCATION_WITHDRAWAL_VERSION, vectors.vocabulary.revocation_withdrawal_version)
  })
})

describe('authority-state: marker constructor', () => {
  for (const vector of vectors.marker_cases) {
    test(vector.id, () => {
      if (vector.expected.ok) {
        const marker = stateMarker(vector.input as never)
        assert.deepEqual({ ...marker }, vector.expected.marker)
      } else {
        assert.throws(
          () => stateMarker(vector.input as never),
          (error: unknown) => {
            assert.ok(error instanceof AuthorityStateError)
            assert.equal(error.code, vector.expected.error_code)
            return true
          },
        )
      }
    })
  }
})

describe('authority-state: monotonicity comparison', () => {
  for (const vector of vectors.comparison_cases) {
    test(vector.id, () => {
      const established = asMarker(vector.established)
      const presented = asMarker(vector.presented)
      assert.equal(compareStateMarker(established, presented), vector.expected.outcome)
      const after = advanceHighWaterMark(established, presented)
      assert.deepEqual(
        after === null ? null : { ...after },
        vector.expected.high_water_mark_after,
      )
    })
  }
})

describe('authority-state: resolver routing', () => {
  for (const vector of vectors.routing_cases) {
    test(vector.id, () => {
      const resolver = createMonotonicRevocationResolver({
        presented: () => vector.presented_answer,
        presentedMarker: asMarker(vector.presented_marker),
        retained: { records: [], highWaterMark: asMarker(vector.established) },
        verification: { resolveVerificationKey: () => null },
        onUnplaceable: vector.on_unplaceable as never,
      })
      assert.equal(resolver.monotonicity, vector.expected.monotonicity)
      assert.equal(
        resolver.resolve({} as AuthorityDelegationV1),
        vector.expected.resolution,
      )
      assert.deepEqual(
        resolver.highWaterMarkAfter === null ? null : { ...resolver.highWaterMarkAfter },
        vector.expected.high_water_mark_after,
      )
    })
  }
})

describe('authority-state: fencing gate', () => {
  for (const vector of vectors.fencing_cases) {
    test(vector.id, () => {
      const log = new FencedAuthorityStateLog<string>()
      for (const write of vector.writes) {
        const outcome = log.write({
          token: asMarker(write.token) as StateMarker,
          payload: write.payload,
        })
        assert.equal(outcome.accepted, write.expected.accepted)
        if (!outcome.accepted) assert.equal(outcome.code, write.expected.code)
      }
      assert.equal(log.published() ?? null, vector.expected.published_payload)
      const highest = log.highestToken()
      assert.deepEqual(highest === null ? null : { ...highest }, vector.expected.highest_token)
    })
  }
})

describe('authority-state: withdrawal evaluation', () => {
  for (const vector of vectors.withdrawal_cases) {
    test(vector.id, () => {
      const evaluation = evaluateRevocationWithdrawal(
        vector.withdrawal as unknown as RevocationWithdrawalV0,
        vector.held as unknown as AuthorityRevocationV1[],
        STANDING_RESOLVERS[vector.standing_resolver],
      )
      assert.equal(evaluation.accepted, vector.expected.accepted)
      assert.equal(evaluation.reason_code, vector.expected.reason_code)
      assert.equal(evaluation.standing, vector.expected.standing)
    })
  }
})

describe('authority-state: corrected revocation view', () => {
  for (const vector of vectors.corrected_view_cases) {
    test(vector.id, () => {
      const view = correctedRevocationView(
        vector.revocation as unknown as AuthorityRevocationV1,
        vector.withdrawals as unknown as RevocationWithdrawalV0[],
        STANDING_RESOLVERS[vector.standing_resolver],
      )
      assert.equal(view.revocation !== undefined, vector.expected.revocation_present)
      assert.deepEqual(view.revocation, vector.revocation)
      assert.equal(view.accepted.length, vector.expected.accepted_count)
      assert.equal(view.refused.length, vector.expected.refused_count)
      assert.deepEqual(
        view.accepted.map(e => e.reason_code),
        vector.expected.accepted_reason_codes,
      )
      assert.deepEqual(
        view.refused.map(e => e.reason_code),
        vector.expected.refused_reason_codes,
      )
    })
  }
})

// ── Against real records ──────────────────────────────────────────────────────────────
// Everything below mints its own delegations and revocations through the SDK's own issuance
// path, so a `revoked` answer here is earned by verification rather than asserted.

const ROOT_KEY = '11'.repeat(32)
const CHILD_KEY = '22'.repeat(32)
const ROOT_ISSUER = 'did:example:aer-principal'
const ROOT_SUBJECT = 'did:example:aer-agent-a'
const CHILD_SUBJECT = 'did:example:aer-agent-b'
const ROOT_VM = `${ROOT_ISSUER}#key-1`
const CHILD_VM = `${ROOT_SUBJECT}#key-1`

const publicKeys = new Map([
  [ROOT_VM, publicKeyFromPrivate(ROOT_KEY)],
  [CHILD_VM, publicKeyFromPrivate(CHILD_KEY)],
])

function resolveVerificationKey(_controller: string, method: string): string | null {
  return publicKeys.get(method) ?? null
}

const verification = { resolveVerificationKey }
const NOW = '2026-09-20T13:00:00.000Z'
const REVOKED_AT = '2026-09-20T11:30:00.000Z'

function rootBody(): AuthorityDelegationBodyV1 {
  return {
    record_type: AUTHORITY_DELEGATION_RECORD_TYPE,
    version: AUTHORITY_DELEGATION_VERSION,
    parent_delegation_id: null,
    issuer: ROOT_ISSUER,
    subject: ROOT_SUBJECT,
    verification_method: ROOT_VM,
    issued_at: '2026-09-20T10:00:00.000Z',
    nonce: '00112233445566778899aabbccddeeff',
    authority: {
      scope: { profile: SCOPE_PROFILE_V1, grants: ['commerce:*'] },
      spend: { mode: 'bounded', unit: 'iso4217:USD:minor', per_action: '100', cumulative: '100' },
      depth: { remaining: 3 },
      time: { not_before: '2026-09-20T10:00:00.000Z', not_after: '2026-09-20T23:00:00.000Z' },
      reputation: { profile: REPUTATION_PROFILE_V1, ceiling: 80 },
      values: { profile: VALUES_PROFILE_V1, required: ['F-001'] },
      reversibility: { profile: REVERSIBILITY_PROFILE_V1, ceiling: 'compensable' },
    },
  }
}

function childBody(parent: AuthorityDelegationV1): AuthorityDelegationBodyV1 {
  return {
    record_type: AUTHORITY_DELEGATION_RECORD_TYPE,
    version: AUTHORITY_DELEGATION_VERSION,
    parent_delegation_id: parent.delegation_id,
    issuer: ROOT_SUBJECT,
    subject: CHILD_SUBJECT,
    verification_method: CHILD_VM,
    issued_at: '2026-09-20T10:05:00.000Z',
    nonce: 'ffeeddccbbaa99887766554433221100',
    authority: {
      scope: { profile: SCOPE_PROFILE_V1, grants: ['commerce:checkout'] },
      spend: { mode: 'bounded', unit: 'iso4217:USD:minor', per_action: '80', cumulative: '80' },
      depth: { remaining: 2 },
      time: { not_before: '2026-09-20T10:05:00.000Z', not_after: '2026-09-20T22:55:00.000Z' },
      reputation: { profile: REPUTATION_PROFILE_V1, ceiling: 70 },
      values: { profile: VALUES_PROFILE_V1, required: ['F-001'] },
      reversibility: { profile: REVERSIBILITY_PROFILE_V1, ceiling: 'tentative' },
    },
  }
}

interface Scenario {
  root: AuthorityDelegationV1
  child: AuthorityDelegationV1
  revocation: AuthorityRevocationV1
  /** epoch 6: both delegations tracked, no revocation held. */
  before: InMemoryAuthorityRevocationStore
  /** epoch 7: the root revocation held. */
  after: InMemoryAuthorityRevocationStore
}

function scenario(): Scenario {
  const root = issueAuthorityDelegation(rootBody(), ROOT_KEY)
  const child = issueSubAuthorityDelegation(root, childBody(root), CHILD_KEY, {
    now: '2026-09-20T10:05:00.000Z',
    resolveVerificationKey,
    resolveRevocation: () => 'active',
  })
  const revocation = issueAuthorityRevocation(
    root,
    {
      now: REVOKED_AT,
      revoker: ROOT_ISSUER,
      verification_method: ROOT_VM,
      reason_code: 'recorded_in_error',
      nonce: 'a0a1a2a3a4a5a6a7a8a9aaabacadaeaf',
    },
    ROOT_KEY,
  )

  const before = new InMemoryAuthorityRevocationStore()
  before.track(root.delegation_id)
  before.track(child.delegation_id)

  const after = new InMemoryAuthorityRevocationStore()
  after.track(root.delegation_id)
  after.track(child.delegation_id)
  const recorded = recordAuthorityRevocation(after, root, revocation, verification)
  assert.equal(recorded.recorded, true)

  return { root, child, revocation, before, after }
}

const EPOCH_6 = stateMarker({ value: '6', scope: 'global' })
const EPOCH_7 = stateMarker({ value: '7', scope: 'global' })
const EPOCH_8 = stateMarker({ value: '8', scope: 'global' })

function chainResult(
  s: Scenario,
  resolveRevocation: (d: AuthorityDelegationV1) => RevocationResolution,
) {
  return verifyAuthorityDelegationChain([s.root, s.child], {
    now: NOW,
    resolveVerificationKey,
    trustRoot: candidate => candidate.delegation_id === s.root.delegation_id,
    resolveRevocation,
  })
}

describe('authority-state: a retained record set is not a store', () => {
  test('a retained record that verifies answers revoked', () => {
    const s = scenario()
    assert.equal(
      resolveUnderRetainedState(s.root, { records: [s.revocation], highWaterMark: EPOCH_7 }, verification),
      'revoked',
    )
  })

  test('a retained set that does not mention this delegation answers unknown, never active', () => {
    const s = scenario()
    assert.equal(
      resolveUnderRetainedState(s.child, { records: [s.revocation], highWaterMark: EPOCH_7 }, verification),
      'unknown',
    )
  })

  test('an empty retained set answers unknown', () => {
    const s = scenario()
    assert.equal(
      resolveUnderRetainedState(s.root, { records: [], highWaterMark: EPOCH_7 }, verification),
      'unknown',
    )
  })

  test('a retained record whose key does not resolve answers unknown, not revoked', () => {
    const s = scenario()
    assert.equal(
      resolveUnderRetainedState(
        s.root,
        { records: [s.revocation], highWaterMark: EPOCH_7 },
        { resolveVerificationKey: () => null },
      ),
      'unknown',
    )
  })
})

describe('authority-state: rollback against a real chain', () => {
  test('epoch 7 presented to a verifier at epoch 7 is invalid at the root index', () => {
    const s = scenario()
    const resolver = createMonotonicRevocationResolver({
      presented: createAuthorityRevocationResolver(s.after, verification),
      presentedMarker: EPOCH_7,
      retained: { records: [s.revocation], highWaterMark: EPOCH_7 },
      verification,
      onUnplaceable: 'read_presented',
    })
    const result = chainResult(s, resolver.resolve)
    assert.equal(resolver.monotonicity, 'forward')
    assert.equal(result.state, 'invalid')
    assert.equal(result.failures[0]?.code, 'REVOKED')
    assert.equal(result.failures[0]?.index, 0)
  })

  test('epoch 6 presented to a verifier that has seen nothing later is valid', () => {
    const s = scenario()
    const resolver = createMonotonicRevocationResolver({
      presented: createAuthorityRevocationResolver(s.before, verification),
      presentedMarker: EPOCH_6,
      retained: { records: [], highWaterMark: EPOCH_6 },
      verification,
      onUnplaceable: 'read_presented',
    })
    const result = chainResult(s, resolver.resolve)
    assert.equal(resolver.monotonicity, 'forward')
    assert.equal(result.state, 'valid')
  })

  test('a restored snapshot against a verifier that retained the record is invalid, not valid', () => {
    const s = scenario()
    // The same epoch-6 store as the case above. Only the verifier differs.
    assert.equal(createAuthorityRevocationResolver(s.before, verification)(s.root), 'active')

    const resolver = createMonotonicRevocationResolver({
      presented: createAuthorityRevocationResolver(s.before, verification),
      presentedMarker: EPOCH_6,
      retained: { records: [s.revocation], highWaterMark: EPOCH_7 },
      verification,
      onUnplaceable: 'read_presented',
    })
    const result = chainResult(s, resolver.resolve)
    assert.equal(resolver.monotonicity, 'regressed')
    assert.equal(resolver.resolve(s.root), 'revoked')
    assert.equal(result.state, 'invalid')
    assert.equal(result.failures[0]?.code, 'REVOKED')
    assert.equal(result.failures[0]?.index, 0)
    assert.deepEqual({ ...(resolver.highWaterMarkAfter as StateMarker) }, { ...EPOCH_7 })
  })

  test('a lagging replica against a verifier that retained only the mark is indeterminate', () => {
    const s = scenario()
    const resolver = createMonotonicRevocationResolver({
      presented: createAuthorityRevocationResolver(s.before, verification),
      presentedMarker: EPOCH_6,
      retained: { records: [], highWaterMark: EPOCH_7 },
      verification,
      onUnplaceable: 'read_presented',
    })
    const result = chainResult(s, resolver.resolve)
    assert.equal(resolver.monotonicity, 'regressed')
    assert.equal(resolver.resolve(s.root), 'unknown')
    assert.equal(result.state, 'indeterminate')
    assert.equal(result.failures[0]?.code, 'REVOCATION_UNKNOWN')
    assert.equal(result.failures[0]?.index, 0)
  })

  test('a forward move is read normally and the mark advances', () => {
    const s = scenario()
    const resolver = createMonotonicRevocationResolver({
      presented: createAuthorityRevocationResolver(s.after, verification),
      presentedMarker: EPOCH_8,
      retained: { records: [s.revocation], highWaterMark: EPOCH_7 },
      verification,
      onUnplaceable: 'read_presented',
    })
    const result = chainResult(s, resolver.resolve)
    assert.equal(resolver.monotonicity, 'forward')
    assert.deepEqual({ ...(resolver.highWaterMarkAfter as StateMarker) }, { ...EPOCH_8 })
    assert.equal(result.state, 'invalid')
    assert.equal(result.failures[0]?.code, 'REVOKED')
  })

  test('first contact takes the caller disposition, and the two dispositions differ', () => {
    const s = scenario()
    const shared = {
      presented: createAuthorityRevocationResolver(s.before, verification),
      presentedMarker: EPOCH_6,
      retained: { records: [], highWaterMark: null },
      verification,
    }
    const read = createMonotonicRevocationResolver({ ...shared, onUnplaceable: 'read_presented' })
    const refuse = createMonotonicRevocationResolver({ ...shared, onUnplaceable: 'refuse' })
    assert.equal(read.monotonicity, 'unplaceable')
    assert.equal(refuse.monotonicity, 'unplaceable')
    assert.equal(chainResult(s, read.resolve).state, 'valid')
    assert.equal(chainResult(s, refuse.resolve).state, 'indeterminate')
  })
})

describe('authority-state: fencing on the write path, with real stores', () => {
  test('a stale token cannot republish pre-revocation state', () => {
    const s = scenario()
    const log = new FencedAuthorityStateLog<InMemoryAuthorityRevocationStore>()
    const current = log.write({ token: stateMarker({ value: '42', scope: 'global' }), payload: s.after })
    assert.equal(current.accepted, true)

    const stale = log.write({ token: stateMarker({ value: '41', scope: 'global' }), payload: s.before })
    assert.equal(stale.accepted, false)
    assert.equal(stale.accepted === false && stale.code, 'stale_fencing_token')

    const published = log.published() as InMemoryAuthorityRevocationStore
    const result = chainResult(s, createAuthorityRevocationResolver(published, verification))
    assert.equal(result.state, 'invalid')
    assert.equal(result.failures[0]?.code, 'REVOKED')
  })

  test('an unfenced publisher republishes it, and the same chain then verifies valid', () => {
    // The defect the gate exists to catch, shown rather than asserted: with no token check
    // the pre-revocation store becomes what is read, and every signature still checks out.
    const s = scenario()
    const unfenced = createAuthorityRevocationResolver(s.before, verification)
    const result = chainResult(s, unfenced)
    assert.equal(result.state, 'valid')
  })
})

describe('authority-state: a withdrawal is a record, not a resurrection', () => {
  function withdrawal(s: Scenario, by: string): RevocationWithdrawalV0 {
    return revocationWithdrawal({
      revocation_id: s.revocation.revocation_id,
      delegation_id: s.revocation.delegation_id,
      withdrawn_by: by,
      withdrawn_at: '2026-09-20T12:30:00.000Z',
      reason_code: 'recorded-in-error',
    })
  }

  test('an accepted withdrawal leaves the revocation held, verifying and effective', () => {
    const s = scenario()
    const view = correctedRevocationView(s.revocation, [withdrawal(s, ROOT_ISSUER)], withdrawalSignerIsRevoker)
    assert.equal(view.accepted.length, 1)
    assert.equal(view.refused.length, 0)

    // Still in the store, and still verifies byte for byte.
    assert.deepEqual(s.after.get(s.root.delegation_id), s.revocation)
    assert.equal(verifyAuthorityRevocation(s.revocation, s.root, verification).state, 'valid')

    // And the chain verdict has not moved one step toward valid.
    const result = chainResult(s, createAuthorityRevocationResolver(s.after, verification))
    assert.equal(result.state, 'invalid')
    assert.equal(result.failures[0]?.code, 'REVOKED')

    const report = reportAuthorityState(result, { corrections: [view] })
    assert.equal(report.chain, result)
    assert.equal(report.lifecycle?.verdict, 'invalid')
    assert.equal(report.lifecycle?.reason_code, 'REVOKED')
    assert.equal(report.corrections?.[0]?.accepted.length, 1)
    assert.deepEqual(report.corrections?.[0]?.revocation, s.revocation)
  })

  test('a withdrawal from a party without standing is refused with a named reason', () => {
    const s = scenario()
    const view = correctedRevocationView(s.revocation, [withdrawal(s, ROOT_SUBJECT)], withdrawalSignerIsRevoker)
    assert.equal(view.accepted.length, 0)
    assert.equal(view.refused.length, 1)
    assert.equal(view.refused[0]?.reason_code, 'WITHDRAWAL_SIGNER_WITHOUT_STANDING')
    assert.equal(view.refused[0]?.standing, 'no_standing')
  })

  test('no path in this module removes a revocation from a store', () => {
    const s = scenario()
    correctedRevocationView(s.revocation, [withdrawal(s, ROOT_ISSUER)], withdrawalSignerIsRevoker)
    evaluateRevocationWithdrawal(withdrawal(s, ROOT_ISSUER), [s.revocation], withdrawalSignerIsRevoker)
    assert.deepEqual(s.after.get(s.root.delegation_id), s.revocation)
    assert.equal(s.after.tracks(s.root.delegation_id), true)
    // The store surface is unchanged: no removal method was added anywhere.
    assert.equal((s.after as unknown as Record<string, unknown>).remove, undefined)
    assert.equal((s.after as unknown as Record<string, unknown>).delete, undefined)
  })

  test('a standing resolver that throws is read as unknown, not as standing', () => {
    const s = scenario()
    const evaluation = evaluateRevocationWithdrawal(
      withdrawal(s, ROOT_ISSUER),
      [s.revocation],
      () => {
        throw new Error('resolver exploded')
      },
    )
    assert.equal(evaluation.accepted, false)
    assert.equal(evaluation.reason_code, 'WITHDRAWAL_STANDING_NOT_ESTABLISHED')
    assert.equal(evaluation.standing, 'unknown')
  })
})

describe('authority-state: nothing existing changed', () => {
  test('the chain verifier still takes the one-argument resolver it always took', () => {
    const s = scenario()
    const result = chainResult(s, createAuthorityRevocationResolver(s.after, verification))
    assert.equal(result.state, 'invalid')
    assert.equal(result.failures[0]?.code, 'REVOKED')
  })

  test('the report carries the chain result through untouched', () => {
    const s = scenario()
    const result = chainResult(s, createAuthorityRevocationResolver(s.after, verification))
    const snapshot = JSON.parse(JSON.stringify(result))
    const report = authorityStateReport({ chain: result, monotonicity: 'forward' })
    assert.deepEqual(JSON.parse(JSON.stringify(report.chain)), snapshot)
    assert.equal(report.lifecycle, undefined)
    assert.equal(report.monotonicity, 'forward')
  })
})
