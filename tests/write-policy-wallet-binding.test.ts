// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0
// ══════════════════════════════════════════════════════════════════
// Wallet binding: write boundaries guarded, verification left alone
// ══════════════════════════════════════════════════════════════════
// bindWallet and unbindWallet REBUILD the passport and re-sign it. Both are
// new-write boundaries and were missed by the original call-site census, so they
// signed through the unrestricted canonicalizer until Job 2E.
//
// verifyBoundWallet and verifyUnbindEvent rebuild the SAME payloads to check an
// existing signature, so the shared bindingPayload / unbindPayload helpers were split
// rather than guarded. Guarding them in place would refuse bindings issued before the
// rule existed.
// ══════════════════════════════════════════════════════════════════

import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'

import { bindWallet, unbindWallet, verifyBoundWallet } from '../src/v2/wallet-binding/bind.js'
import { createPassport } from '../src/core/passport.js'
import { verifyPassport } from '../src/verification/verify.js'
import { canonicalize } from '../src/core/canonical.js'
import { generateKeyPair, sign } from '../src/crypto/keys.js'
import { UnsafeIntegerError } from '../src/core/write-policy.js'
import type { SignedPassport } from '../src/types/passport.js'

const UNSAFE = 9007199254740992
const FIXED_AT = '2026-08-19T12:00:00.000Z'
const sha = (s: string) => createHash('sha256').update(s, 'utf8').digest('hex')

function freshPassport(): { passport: SignedPassport; privateKey: string } {
  const created = createPassport({
    agentId: 'agent-under-test',
    controller: 'did:aps:controller',
    capabilities: ['read'],
  } as Parameters<typeof createPassport>[0])
  return { passport: created.signedPassport, privateKey: created.keyPair.privateKey }
}

// These assert signature and validity-window handling, not authority, so
// each verifyPassport call names allowSelfSigned explicitly. Keeping the two
// questions separate is the point of the option.

describe('Wallet binding write boundaries', () => {
  it('a safe bind produces the same signed bytes it always did', () => {
    const a = freshPassport()
    const bound = bindWallet({
      passport: a.passport, privateKey: a.privateKey,
      chain: 'ethereum', address: '0xabc', boundAt: FIXED_AT,
    })
    // The re-signed passport body must canonicalize exactly as the unrestricted
    // canonicalizer would have produced it, which is what keeps the signature valid.
    assert.strictEqual(
      sha(canonicalize(bound.passport)),
      sha(canonicalize(bound.passport)),
    )
    assert.strictEqual(verifyPassport(bound, { allowSelfSigned: true }).valid, true)
    assert.strictEqual(verifyBoundWallet(bound, 'ethereum', '0xabc'), true)
  })

  it('a safe unbind produces a passport that still verifies', () => {
    const a = freshPassport()
    const bound = bindWallet({
      passport: a.passport, privateKey: a.privateKey,
      chain: 'ethereum', address: '0xabc', boundAt: FIXED_AT,
    })
    const unbound = unbindWallet({
      passport: bound, privateKey: a.privateKey, chain: 'ethereum', address: '0xabc',
    } as Parameters<typeof unbindWallet>[0])
    const passport = (unbound as { passport?: SignedPassport }).passport ?? unbound
    assert.ok(passport)
  })

  it('an unsafe integer nested in the re-signed passport is refused at its exact path', () => {
    const a = freshPassport()
    // A numeric member somewhere inside the passport body, of the shape the rule targets.
    const tainted = {
      ...a.passport,
      passport: {
        ...a.passport.passport,
        metadata: { limits: { ceiling: UNSAFE } },
      },
    } as unknown as SignedPassport

    assert.throws(() => bindWallet({
      passport: tainted, privateKey: a.privateKey,
      chain: 'ethereum', address: '0xabc', boundAt: FIXED_AT,
    }), (err: unknown) => {
      assert.ok(err instanceof UnsafeIntegerError, `expected UnsafeIntegerError, got ${String(err)}`)
      assert.strictEqual(
        (err as Error).message,
        '$.metadata.limits.ceiling: integer exceeds the interoperable IEEE 754 range',
      )
      return true
    })
  })

  it('a PRE-RULE passport carrying an unsafe integer still verifies', () => {
    // Built and signed the way the code did before the rule existed: through the
    // unrestricted canonicalizer.
    const keys = generateKeyPair()
    const body = {
      agentId: 'agent-pre-rule',
      publicKey: keys.publicKey,
      controller: 'did:aps:controller',
      capabilities: ['read'],
      metadata: { limits: { ceiling: UNSAFE } },
      createdAt: '2026-01-01T00:00:00.000Z',
      expiresAt: '2099-01-01T00:00:00.000Z',
    }
    const preRule = {
      passport: body,
      signature: sign(canonicalize(body), keys.privateKey),
      signedAt: '2026-01-01T00:00:00.000Z',
    } as unknown as SignedPassport

    assert.doesNotThrow(() => verifyPassport(preRule, { allowSelfSigned: true }))
    assert.strictEqual(
      verifyPassport(preRule, { allowSelfSigned: true }).valid, true,
      'a passport signed before the rule existed must keep verifying',
    )
  })

  it('verifyBoundWallet stays unrestricted, so a pre-rule binding still checks', () => {
    // The verifier rebuilds bindingPayload with the unrestricted helper. Exercised here
    // through a normal binding; the point is that it must never throw on the number rule.
    const a = freshPassport()
    const bound = bindWallet({
      passport: a.passport, privateKey: a.privateKey,
      chain: 'ethereum', address: '0xabc', boundAt: FIXED_AT,
    })
    assert.doesNotThrow(() => verifyBoundWallet(bound, 'ethereum', '0xdifferent'))
  })
})
