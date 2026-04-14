// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// Provisional Statement — default for agent-to-agent negotiation statements.

import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import {
  generateKeyPair,
  createProvisional,
  isBinding,
  verifyAuthorSignature,
  withdrawProvisional,
  withdrawalPayload,
  promoteStatement,
  processDeadMan,
  promotionSigningPayload,
  verifyPromotion,
  createHybridTimestamp,
} from '../../src/index.js'
import { sign } from '../../src/crypto/keys.js'
import type {
  ProvisionalStatement, PromotionEvent, PromotionPolicy,
} from '../../src/index.js'

const GW = 'gateway-test'

function makeAuthor() {
  return generateKeyPair()
}
function makePrincipal() {
  return generateKeyPair()
}

function freshStatement(opts: {
  content?: string
  deadMan?: ReturnType<typeof createHybridTimestamp>
} = {}): {
  statement: ProvisionalStatement
  author: ReturnType<typeof generateKeyPair>
  principal: ReturnType<typeof generateKeyPair>
} {
  const author = makeAuthor()
  const principal = makePrincipal()
  const statement = createProvisional({
    author: author.publicKey,
    author_principal: principal.publicKey,
    content: opts.content ?? 'I offer 100 units at price 5',
    authorPrivateKey: author.privateKey,
    gatewayId: GW,
    ...(opts.deadMan ? { dead_man_expires_at: opts.deadMan } : {}),
  })
  return { statement, author, principal }
}

function buildPromotionEvent(opts: {
  statement: ProvisionalStatement
  promoter: ReturnType<typeof generateKeyPair>
  policyId: string
  kind?: PromotionEvent['kind']
  promoted_at?: ReturnType<typeof createHybridTimestamp>
}): PromotionEvent {
  const promoted_at = opts.promoted_at ?? createHybridTimestamp(GW)
  const kind = opts.kind ?? 'principal_signature'
  const payload = promotionSigningPayload({
    statement_id: opts.statement.id,
    kind,
    promoted_at,
    promoter: opts.promoter.publicKey,
    policy_reference: opts.policyId,
  })
  return {
    kind,
    promoted_at,
    promoter: opts.promoter.publicKey,
    promoter_signature: sign(payload, opts.promoter.privateKey),
    policy_reference: opts.policyId,
  }
}

describe('ProvisionalStatement — creation', () => {
  it('created statement is provisional by default', () => {
    const { statement } = freshStatement()
    assert.equal(statement.status, 'provisional')
    assert.equal(statement.version, '1.0')
    assert.ok(statement.id && statement.id.length > 0)
    assert.ok(statement.author_signature.length > 0)
  })

  it('verifyAuthorSignature passes for a freshly created statement', () => {
    const { statement } = freshStatement()
    assert.equal(verifyAuthorSignature(statement), true)
  })

  it('isBinding returns false for provisional', () => {
    const { statement } = freshStatement()
    assert.equal(isBinding(statement), false)
  })

  it('counterparty reading envelope sees status field', () => {
    const { statement } = freshStatement()
    // A counterparty only has the wire-level object: the status must be
    // directly readable without calling any helper.
    assert.equal((statement as { status: string }).status, 'provisional')
  })
})

describe('ProvisionalStatement — promotion', () => {
  const policy: PromotionPolicy = {
    id: 'policy-1of1',
    required_signers: [],
    threshold: 1,
    max_time_to_promote: 60_000,
  }

  it('promote with principal_signature satisfying m-of-n policy, isBinding true', () => {
    const { statement, principal } = freshStatement()
    const p: PromotionPolicy = { ...policy, required_signers: [principal.publicKey] }
    const event = buildPromotionEvent({ statement, promoter: principal, policyId: p.id })
    const promoted = promoteStatement(statement, event, p)
    assert.equal(promoted.status, 'promoted')
    assert.equal(isBinding(promoted), true)
    assert.equal(verifyPromotion(promoted, p).valid, true)
  })

  it('promote with insufficient signers (threshold=2), verification fails', () => {
    const { statement, principal } = freshStatement()
    const p: PromotionPolicy = {
      id: 'policy-2of2',
      required_signers: [principal.publicKey, makePrincipal().publicKey],
      threshold: 2,
      max_time_to_promote: 60_000,
    }
    const event = buildPromotionEvent({ statement, promoter: principal, policyId: p.id })
    assert.throws(() => promoteStatement(statement, event, p), /Threshold/)
  })

  it('promote with wrong principal, verification fails', () => {
    const { statement, principal } = freshStatement()
    const stranger = makePrincipal()
    const p: PromotionPolicy = { ...policy, required_signers: [principal.publicKey] }
    const event = buildPromotionEvent({ statement, promoter: stranger, policyId: p.id })
    assert.throws(
      () => promoteStatement(statement, event, p),
      /not in policy.required_signers/,
    )
  })

  it('promote with forged signature (signer in policy but bad sig), fails', () => {
    const { statement, principal } = freshStatement()
    const p: PromotionPolicy = { ...policy, required_signers: [principal.publicKey] }
    const event = buildPromotionEvent({ statement, promoter: principal, policyId: p.id })
    const forged: PromotionEvent = { ...event, promoter_signature: '00'.repeat(64) }
    assert.throws(() => promoteStatement(statement, forged, p), /signature invalid/)
  })

  it('promotion policy_reference mismatch is rejected', () => {
    const { statement, principal } = freshStatement()
    const p: PromotionPolicy = { ...policy, required_signers: [principal.publicKey] }
    const event = buildPromotionEvent({ statement, promoter: principal, policyId: 'some-other' })
    assert.throws(() => promoteStatement(statement, event, p), /does not match policy/)
  })

  it('promotion exceeding max_time_to_promote is rejected', () => {
    const { statement, principal } = freshStatement()
    const p: PromotionPolicy = { ...policy, required_signers: [principal.publicKey], max_time_to_promote: 10 }
    const future = createHybridTimestamp(GW)
    future.wallClockEarliest = statement.created_at.wallClockLatest + 1_000
    future.wallClockLatest = future.wallClockEarliest + 100
    const event = buildPromotionEvent({ statement, promoter: principal, policyId: p.id, promoted_at: future })
    assert.throws(() => promoteStatement(statement, event, p), /max_time_to_promote/)
  })

  it('nested promotion (promote twice) rejects second attempt', () => {
    const { statement, principal } = freshStatement()
    const p: PromotionPolicy = { ...policy, required_signers: [principal.publicKey] }
    const event = buildPromotionEvent({ statement, promoter: principal, policyId: p.id })
    const promoted = promoteStatement(statement, event, p)
    const again = buildPromotionEvent({ statement: promoted, promoter: principal, policyId: p.id })
    assert.throws(() => promoteStatement(promoted, again, p), /already promoted/)
  })

  it('tampered content after promotion: verification fails', () => {
    const { statement, principal } = freshStatement()
    const p: PromotionPolicy = { ...policy, required_signers: [principal.publicKey] }
    const event = buildPromotionEvent({ statement, promoter: principal, policyId: p.id })
    const promoted = promoteStatement(statement, event, p)
    const tampered: ProvisionalStatement = { ...promoted, content: 'I offer 200 units at price 1' }
    const result = verifyPromotion(tampered, p)
    assert.equal(result.valid, false)
    assert.ok(result.errors.some(e => /Author signature invalid/.test(e)))
  })

  it('threshold < 1 is rejected as invalid policy', () => {
    const { statement, principal } = freshStatement()
    const p: PromotionPolicy = { ...policy, required_signers: [principal.publicKey], threshold: 0 }
    const event = buildPromotionEvent({ statement, promoter: principal, policyId: p.id })
    assert.throws(() => promoteStatement(statement, event, p), /threshold must be >= 1/)
  })
})

describe('ProvisionalStatement — dead-man timer', () => {
  it('dead-man elapsed: auto-withdraw, NOT auto-promote', () => {
    const past = createHybridTimestamp(GW)
    past.wallClockEarliest = Date.now() - 2_000
    past.wallClockLatest = Date.now() - 1_000
    const { statement } = freshStatement({ deadMan: past })
    const processed = processDeadMan(statement)
    assert.equal(processed.status, 'withdrawn')
    assert.notEqual(processed.status as string, 'promoted')
    assert.equal(isBinding(processed), false)
    assert.equal(processed.promotion?.kind, 'dead_man_elapsed')
  })

  it('dead-man not yet elapsed: no state change', () => {
    const future = createHybridTimestamp(GW)
    future.wallClockEarliest = Date.now() + 60_000
    future.wallClockLatest = Date.now() + 61_000
    const { statement } = freshStatement({ deadMan: future })
    const processed = processDeadMan(statement)
    assert.equal(processed.status, 'provisional')
    assert.equal(processed.promotion, undefined)
  })

  it('promote attempts with kind=dead_man_elapsed are rejected', () => {
    const { statement, principal } = freshStatement()
    const p: PromotionPolicy = {
      id: 'p',
      required_signers: [principal.publicKey],
      threshold: 1,
      max_time_to_promote: 60_000,
    }
    const event = buildPromotionEvent({
      statement, promoter: principal, policyId: p.id, kind: 'dead_man_elapsed',
    })
    assert.throws(
      () => promoteStatement(statement, event, p),
      /dead_man_elapsed does not promote/,
    )
  })

  it('cannot promote a statement after its dead_man_expires_at bound', () => {
    const past = createHybridTimestamp(GW)
    past.wallClockEarliest = Date.now() - 2_000
    past.wallClockLatest = Date.now() - 1_000
    const { statement, principal } = freshStatement({ deadMan: past })
    const p: PromotionPolicy = {
      id: 'p-dead',
      required_signers: [principal.publicKey],
      threshold: 1,
      max_time_to_promote: 10_000_000,
    }
    // Promoter signs "now" — strictly after past deadline.
    const event = buildPromotionEvent({ statement, promoter: principal, policyId: p.id })
    assert.throws(() => promoteStatement(statement, event, p), /already auto-withdrawn/)
  })
})

describe('ProvisionalStatement — withdrawal', () => {
  it('withdraw before promotion: statement becomes withdrawn', () => {
    const { statement, author } = freshStatement()
    const sig = sign(withdrawalPayload(statement.id), author.privateKey)
    const withdrawn = withdrawProvisional(statement, sig)
    assert.equal(withdrawn.status, 'withdrawn')
    assert.equal(isBinding(withdrawn), false)
  })

  it('withdraw before promotion: cannot promote after', () => {
    const { statement, author, principal } = freshStatement()
    const sig = sign(withdrawalPayload(statement.id), author.privateKey)
    const withdrawn = withdrawProvisional(statement, sig)
    const p: PromotionPolicy = {
      id: 'p',
      required_signers: [principal.publicKey],
      threshold: 1,
      max_time_to_promote: 60_000,
    }
    const event = buildPromotionEvent({ statement: withdrawn, promoter: principal, policyId: p.id })
    assert.throws(() => promoteStatement(withdrawn, event, p), /withdrawn/)
  })

  it('cannot withdraw a promoted statement', () => {
    const { statement, principal } = freshStatement()
    const p: PromotionPolicy = {
      id: 'p',
      required_signers: [principal.publicKey],
      threshold: 1,
      max_time_to_promote: 60_000,
    }
    const event = buildPromotionEvent({ statement, promoter: principal, policyId: p.id })
    const promoted = promoteStatement(statement, event, p)
    const stranger = makeAuthor()
    const badSig = sign(withdrawalPayload(promoted.id), stranger.privateKey)
    assert.throws(() => withdrawProvisional(promoted, badSig), /promoted/)
  })

  it('withdrawal with invalid signature is rejected', () => {
    const { statement } = freshStatement()
    const stranger = makeAuthor()
    const badSig = sign(withdrawalPayload(statement.id), stranger.privateKey)
    assert.throws(() => withdrawProvisional(statement, badSig), /Invalid withdrawal signature/)
  })
})
