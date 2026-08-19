// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0
// ══════════════════════════════════════════════════════════════════
// APS write-policy admissibility corpus, TypeScript half
// ══════════════════════════════════════════════════════════════════
// The corpus is a SEPARATE fixture from the RFC 8785 canonical-bytes vectors on
// purpose: one vector must never carry two meanings. These five cases state
// admissibility only, and the identical file ships in the Python SDK so both
// languages are driven by the same bytes. The same five were run through the Go
// SDK's receiptcore validator and it agreed on all five, including the nested path.
// ══════════════════════════════════════════════════════════════════

import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { createHash } from 'node:crypto'
import { fileURLToPath } from 'node:url'
import { dirname, join } from 'node:path'

import { canonicalize, canonicalizeForWrite } from '../src/core/canonical.js'
import { canonicalizeJCS, canonicalizeJCSForWrite } from '../src/core/canonical-jcs.js'
import { UnsafeIntegerError } from '../src/core/write-policy.js'

const HERE = dirname(fileURLToPath(import.meta.url))
const FIXTURE_PATH = join(HERE, 'fixtures', 'write-policy-admissibility-v1.json')
/** Recorded so a drift in the corpus is a visible failure, not a silent reinterpretation. */
const FIXTURE_SHA256 = '97db9ed8bfeab81ac50187c161ea80953f5878092530ff3fa1912d7eeb985f67'

interface Case {
  name: string
  value: unknown
  verdict: 'ACCEPT' | 'REJECT'
  path: string | null
}

const rawBytes = readFileSync(FIXTURE_PATH)
const cases: Case[] = (JSON.parse(rawBytes.toString('utf8')) as { cases: Case[] }).cases

describe('APS write-policy admissibility corpus', () => {
  it('fixture bytes are pinned', () => {
    const digest = createHash('sha256').update(rawBytes).digest('hex')
    assert.strictEqual(
      digest, FIXTURE_SHA256,
      'the admissibility corpus changed; the Python copy and the recorded Go run must be ' +
      'updated together or the three languages stop meaning the same thing',
    )
  })

  for (const writer of [
    { label: 'legacy write', fn: canonicalizeForWrite },
    { label: 'JCS write', fn: canonicalizeJCSForWrite },
  ]) {
    for (const c of cases) {
      it(`${writer.label}: ${c.name} -> ${c.verdict}`, () => {
        if (c.verdict === 'ACCEPT') {
          assert.doesNotThrow(() => writer.fn(c.value))
          return
        }
        assert.throws(() => writer.fn(c.value), (err: unknown) => {
          assert.ok(err instanceof UnsafeIntegerError, `expected UnsafeIntegerError, got ${String(err)}`)
          assert.ok(
            (err as Error).message.startsWith(`${c.path}:`),
            `expected path ${c.path}, got ${(err as Error).message}`,
          )
          assert.strictEqual((err as UnsafeIntegerError).category, 'invalid_number')
          assert.strictEqual((err as UnsafeIntegerError).reason, 'integer_exceeds_interoperable_range')
          return true
        })
      })
    }
  }

  // The rule is a WRITE rule. Both unrestricted canonicalizers must keep serializing
  // every case, including the rejected ones, because that is what lets a verifier
  // rebuild the preimage of an artifact signed before the rule existed.
  for (const reader of [
    { label: 'legacy read', fn: canonicalize },
    { label: 'JCS read', fn: canonicalizeJCS },
  ]) {
    for (const c of cases) {
      it(`${reader.label}: ${c.name} stays admissible`, () => {
        assert.doesNotThrow(() => reader.fn(c.value))
      })
    }
  }

  for (const c of cases.filter(x => x.verdict === 'ACCEPT')) {
    it(`${c.name}: accepted input is byte-identical across read and write`, () => {
      assert.strictEqual(canonicalizeForWrite(c.value), canonicalize(c.value))
      assert.strictEqual(canonicalizeJCSForWrite(c.value), canonicalizeJCS(c.value))
    })
  }
})

// ── Verification regression, permanent ────────────────────────────────────
//
// The highest-risk failure mode in this whole change is guarding a verification
// path, which would refuse artifacts that were signed before the rule existed and
// that verify today. These tests reconstruct such an artifact the way the pre-rule
// code did, by signing through the UNRESTRICTED canonicalizer, then assert the
// shipped verifier still accepts it.
//
// verifyEndorsement and verifyDisclosure are named explicitly because an earlier
// classification pass wrongly listed both as signing paths. Guarding them would
// have broken every endorsement and disclosure already published.

import { createPrincipalIdentity, endorseAgent, verifyEndorsement } from '../src/core/principal.js'
import { generateKeyPair, sign } from '../src/crypto/keys.js'
import type { PrincipalEndorsement } from '../src/types/principal.js'

const UNSAFE = 9007199254740992

function preRuleEndorsement(): PrincipalEndorsement {
  const created = createPrincipalIdentity({ displayName: 'Pre Rule Principal', domain: 'individual' })
  const principal = created.principal
  const keyPair = created.keyPair
  const agent = generateKeyPair()
  const payload = {
    endorsementId: 'endorsement-prerule',
    principalId: principal.principalId,
    principalPublicKey: principal.publicKey,
    agentId: 'did:aps:agent-prerule',
    agentPublicKey: agent.publicKey,
    // An out-of-range integer that the rule refuses on a NEW write today.
    scope: ['read', UNSAFE] as unknown as string[],
    relationship: 'employee' as const,
    endorsedAt: '2026-01-01T00:00:00.000Z',
    expiresAt: '2099-01-01T00:00:00.000Z',
  }
  // Signed through the UNRESTRICTED canonicalizer, exactly as pre-rule code did.
  const signature = sign(canonicalize(payload), keyPair.privateKey)
  return { ...payload, revoked: false, signature } as unknown as PrincipalEndorsement
}

describe('Verification regression: pre-rule artifacts keep verifying', () => {
  it('verifyEndorsement accepts an endorsement signed before the rule existed', () => {
    const result = verifyEndorsement(preRuleEndorsement())
    assert.strictEqual(result.valid, true, JSON.stringify(result))
  })

  it('verifyEndorsement never throws on the number rule, it returns a verdict', () => {
    // If verifyEndorsement were ever switched to the write canonicalizer, this would
    // throw UnsafeIntegerError instead of reporting an invalid signature.
    const tampered = preRuleEndorsement()
    ;(tampered as unknown as { scope: unknown }).scope = ['read', UNSAFE, { nested: UNSAFE }]
    let result: ReturnType<typeof verifyEndorsement> | undefined
    assert.doesNotThrow(() => { result = verifyEndorsement(tampered) })
    assert.strictEqual(result?.valid, false)
  })

  it('the endorsement PRODUCER refuses the same value', () => {
    const created = createPrincipalIdentity({ displayName: 'P', domain: 'individual' })
    assert.throws(() => endorseAgent({
      principal: created.principal,
      principalPrivateKey: created.keyPair.privateKey,
      agentId: 'did:aps:a',
      agentPublicKey: generateKeyPair().publicKey,
      scope: ['read', UNSAFE] as unknown as string[],
      relationship: 'employee',
    }), UnsafeIntegerError)
  })
})
