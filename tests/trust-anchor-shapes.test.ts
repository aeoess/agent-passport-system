// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0
// ══════════════════════════════════════════════════════════════════
// N1: a malformed trust-anchor list must fail closed, everywhere.
// ══════════════════════════════════════════════════════════════════
// Two guards read the same option with OPPOSITE tests, one positive
// (`.length > 0`) and one equality (`.length === 0`). Any value whose
// `.length` is neither exactly 0 nor greater than 0 failed both and composed
// into an admit:
//
//   value                      .length      >0      ===0
//   []                         0            false   true     (deliberate: no anchors)
//   ['k']                      1            true    false    (deliberate: anchors)
//   {}                         undefined    false   false    ADMITTED
//   NaN                        undefined    false   false    ADMITTED
//   new Map()                  undefined    false   false    ADMITTED
//   new Set(['trusted-key'])   undefined    false   false    ADMITTED
//
// The Set decides the severity: holding trust anchors in a Set is a natural
// thing to do, and an operator who did it got a gate that admitted everyone
// and was told nothing. Driven end to end, `governMCPToolCall` with
// `trustedIssuers: {}` executed the tool and returned {"pwned":true}, through
// all six gates.
//
// Pre-existing, not introduced by the consolidation; `anchors.length === 0`
// was in middleware.ts before the gates were merged. What the consolidation
// changed is that the repair is one normalization instead of six guards.
//
// No test anywhere exercised a malformed trustedIssuers. This is that test.

import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import {
  generateKeyPair, createDelegation, createPassport, signPassport,
  verifyPassport, checkPassportTrustPosture, normalizeTrustAnchors,
  verifySocialContract,
} from '../src/index.js'
import { governMCPToolCall } from '../src/adapters/mcp.js'
import { governLangChainTool } from '../src/adapters/langchain.js'
import { verifyCrewMember } from '../src/adapters/crewai.js'
import { verifyGonkaHost } from '../src/adapters/gonka.js'
import { verifyA2AIdentity } from '../src/adapters/a2a.js'
import { evaluateRequest } from '../src/v2/offline-verifier/middleware.js'
import { createMinimalEnvelope, verifyExecutionEnvelope } from '../src/core/execution-envelope.js'
import type { ExecutionEnvelope } from '../src/types/execution-envelope.js'

function attacker() {
  const { signedPassport, keyPair } = createPassport({
    agentId: 'attacker', agentName: 'attacker', ownerAlias: 'nobody',
    mission: 'take over', capabilities: ['admin:everything'],
    runtime: { platform: 'node', models: ['gpt'], toolsCount: 0, memoryType: 'none' },
    expiresInDays: 30,
  })
  const passport = signPassport(signedPassport.passport, keyPair.privateKey)
  const delegation = createDelegation({
    delegatedTo: keyPair.publicKey, delegatedBy: keyPair.publicKey,
    scope: ['*'], privateKey: keyPair.privateKey,
  })
  return { passport, delegation, privateKey: keyPair.privateKey }
}

/** Every shape whose `.length` is neither exactly 0 nor greater than 0, plus
 *  the shapes that merely look like a list. None may admit. */
const MALFORMED: Array<[string, unknown]> = [
  ['{}', {}],
  ['NaN', NaN],
  ['new Map()', new Map()],
  ["new Set(['trusted-key'])", new Set(['trusted-key'])],
  ['0', 0],
  ['1', 1],
  ['true', true],
  ['false', false],
  ['a bare key string', 'a'.repeat(64)],
  ['an array holding a non-string', ['a'.repeat(64), 42]],
  ['an array holding an empty string', ['']],
  ['an array holding null', [null]],
]

describe('N1: normalizeTrustAnchors grades every shape', () => {
  it('undefined and null are "no anchors configured", not malformed', () => {
    for (const v of [undefined, null]) {
      const n = normalizeTrustAnchors(v)
      assert.equal(n.malformed, false)
      assert.deepEqual(n.anchors, [])
    }
  })

  it('an empty array is a deliberate empty list, not malformed', () => {
    const n = normalizeTrustAnchors([])
    assert.equal(n.malformed, false)
    assert.deepEqual(n.anchors, [])
  })

  it('an array of key strings passes through unchanged', () => {
    const keys = ['a'.repeat(64), 'b'.repeat(64)]
    const n = normalizeTrustAnchors(keys)
    assert.equal(n.malformed, false)
    assert.deepEqual(n.anchors, keys)
  })

  for (const [label, value] of MALFORMED) {
    it(`${label} is malformed and yields no anchors`, () => {
      const n = normalizeTrustAnchors(value)
      assert.equal(n.malformed, true, `${label} was accepted as a trust-anchor list`)
      assert.deepEqual(n.anchors, [], 'a malformed value must never contribute anchors')
      assert.ok(n.reason && n.reason.length > 0, 'a refusal must state its reason')
    })
  }
})

describe('N1: the posture check refuses every malformed shape', () => {
  for (const [label, value] of MALFORMED) {
    it(`denies trustedIssuers = ${label}`, () => {
      const { passport } = attacker()
      const r = checkPassportTrustPosture(passport, { trustedIssuers: value as never })
      assert.equal(r.ok, false, `${label} admitted a self-signed admin passport`)
      assert.equal(r.failure, 'UNTRUSTED_ISSUER')
      assert.ok(r.detail && r.detail.length > 0, 'the denial must say why')
    })
  }

  it('a malformed list is not rescued by allowSelfSigned being absent or present', () => {
    const { passport } = attacker()
    for (const allowSelfSigned of [undefined, true, false]) {
      const r = checkPassportTrustPosture(passport, { trustedIssuers: {} as never, allowSelfSigned })
      assert.equal(r.ok, false, `allowSelfSigned=${String(allowSelfSigned)} rescued a malformed anchor list`)
    }
  })

  it('the denial is attributed to the configuration, not to the passport', () => {
    const { passport } = attacker()
    const r = checkPassportTrustPosture(passport, { trustedIssuers: new Set(['k']) as never })
    assert.equal(r.failure, 'UNTRUSTED_ISSUER')
    assert.ok(/trustedIssuers/.test(r.detail ?? ''), r.detail)
  })
})

describe('N1: verifyPassport refuses a malformed anchor list rather than ignoring it', () => {
  for (const [label, value] of MALFORMED) {
    it(`rejects trustedIssuers = ${label}`, () => {
      const { passport } = attacker()
      const r = verifyPassport(passport, { trustedIssuers: value as never })
      assert.equal(r.valid, false, `${label} was silently treated as "no anchors"`)
      assert.equal(r.selfSignedAccepted, false)
      assert.ok(r.errors.some(e => e.includes('trustedIssuers')), JSON.stringify(r.errors))
    })
  }

  it('a bare key string cannot substring-match an issuer key', () => {
    // A 64-char string has a numeric length, so it passed the old `> 0` test,
    // and the membership test downstream was String.prototype.includes, i.e.
    // substring matching against the issuer key.
    const issuer = generateKeyPair()
    const { passport } = attacker()
    const r = verifyPassport(passport, { trustedIssuers: issuer.publicKey as never })
    assert.equal(r.valid, false)
  })
})

describe('N1: all six gates deny a malformed anchor list end to end', () => {
  const BAD = {} as never

  it('the MCP gate does not execute the tool', async () => {
    const c = attacker()
    let executed = 0
    const r = await governMCPToolCall({ name: 'read_file', arguments: {} },
      async () => { executed++; return { pwned: true } },
      { ...c, trustedIssuers: BAD })
    assert.ok('denied' in r, 'the tool ran under a malformed trust-anchor list')
    assert.equal(executed, 0)
  })

  it('the LangChain gate does not execute the tool', async () => {
    const c = attacker()
    let executed = 0
    const r = await governLangChainTool({ name: 'search', arguments: {} },
      async () => { executed++; return 'x' },
      { ...c, trustedIssuers: BAD })
    assert.ok('denied' in r)
    assert.equal(executed, 0)
  })

  it('the CrewAI gate does not authorize', () => {
    const c = attacker()
    const r = verifyCrewMember('a', { description: 'd', expectedOutput: 'o', tools: [] } as never,
      { ...c, trustedIssuers: BAD })
    assert.equal(r.authorized, false)
  })

  it('the Gonka gate does not authorize', () => {
    const c = attacker()
    const r = verifyGonkaHost('h', 'm', { ...c, trustedIssuers: BAD })
    assert.equal(r.authorized, false)
  })

  it('the A2A gate does not report a verified identity', () => {
    const c = attacker()
    const r = verifyA2AIdentity({ name: 'attacker' } as never, c.passport, { trustedIssuers: BAD })
    assert.equal(r.valid, false)
  })

  it('the relying-party middleware does not admit', () => {
    const c = attacker()
    const d = evaluateRequest(c.passport, { trustedIssuers: BAD, requiredScopes: ['admin:everything'] })
    assert.equal(d.admit, false)
    assert.equal(d.reason, 'UNTRUSTED_ISSUER')
  })

  it('a Set of real trust anchors denies rather than silently admitting everyone', () => {
    // The shape an operator most plausibly reaches for. Denial is correct;
    // silent admission was the bug.
    const issuer = generateKeyPair()
    const c = attacker()
    const r = verifyCrewMember('a', { description: 'd', expectedOutput: 'o', tools: [] } as never,
      { ...c, trustedIssuers: new Set([issuer.publicKey]) as never })
    assert.equal(r.authorized, false)
    assert.ok(/trustedIssuers/.test(r.reason), r.reason)
  })
})

// ══════════════════════════════════════════════════════════════════
// N2: allowSelfSigned is compared against the literal true.
// ══════════════════════════════════════════════════════════════════
// Mutant R4: loosening `opts.allowSelfSigned !== true` to
// `!opts.allowSelfSigned` produced zero failures. The shipped code is
// correct and nothing pinned it. Under the loosened form
// `allowSelfSigned: "false"`, which is what an unparsed config value looks
// like, would ADMIT.

describe('N2: only the literal true is wildcard trust', () => {
  const TRUTHY_BUT_NOT_TRUE: Array<[string, unknown]> = [
    ['1', 1],
    ['"true"', 'true'],
    ['"false"', 'false'],
    ['"yes"', 'yes'],
    ['{}', {}],
    ['[]', []],
    ['a non-empty string', 'enabled'],
  ]

  for (const [label, value] of TRUTHY_BUT_NOT_TRUE) {
    it(`allowSelfSigned = ${label} does NOT admit a self-signed passport`, () => {
      const { passport } = attacker()
      const r = checkPassportTrustPosture(passport, { allowSelfSigned: value as never })
      assert.equal(r.ok, false, `${label} was accepted as wildcard trust`)
      assert.equal(r.failure, 'UNTRUSTED_ISSUER')
    })
  }

  it('falsy non-false values do not admit either', () => {
    for (const value of [0, '', null, undefined, NaN]) {
      const { passport } = attacker()
      assert.equal(checkPassportTrustPosture(passport, { allowSelfSigned: value as never }).ok, false)
    }
  })

  it('the literal true admits', () => {
    const { passport } = attacker()
    assert.equal(checkPassportTrustPosture(passport, { allowSelfSigned: true }).ok, true)
  })

  it('the MCP gate agrees: "false" is not permission', async () => {
    const c = attacker()
    let executed = 0
    const r = await governMCPToolCall({ name: 'read_file', arguments: {} },
      async () => { executed++; return 'x' },
      { ...c, allowSelfSigned: 'false' as never })
    assert.ok('denied' in r, 'the string "false" was read as permission')
    assert.equal(executed, 0)
  })
})

// ══════════════════════════════════════════════════════════════════
// N3: verifySocialContract is the THIRD reader of the same option.
// ══════════════════════════════════════════════════════════════════
// RETRO-AUDIT C1. Phase 2 enumerated the known CALL SITES of the guard
// (verify.ts, trust-posture.ts) and stopped there. It never enumerated the
// READERS of the option. `verifySocialContract` — exported at
// src/index.ts:18, driven by the CLI — read `opts?.trustedIssuers ?? []` and
// tested `.length > 0` on whatever arrived. `??` replaces only null and
// undefined, so every other malformed shape reached `.length > 0`, evaluated
// `undefined > 0` -> false, and the caller's trust configuration was
// discarded in silence. Worse, a bare 64-character key STRING has a numeric
// `.length`, so it passed `> 0` and was read as a configured anchor list.
//
// Three public entry points, three different answers for one input:
//
//   trustedIssuers: {}   verifyPassport            valid: false
//                        checkPassportTrustPosture ok: false
//                        verifySocialContract      overall: true, issuerErrors: []
//
// These tests assert the property the enumeration should have had: for any
// value of the option, no public entry point admits where another refuses.

describe('N3: verifySocialContract normalizes the same option the other readers do', () => {
  it('a deliberate empty list still means "no trust root consulted"', () => {
    const { passport } = attacker()
    const r = verifySocialContract(passport, null, { trustedIssuers: [] })
    assert.equal(r.issuerChecked, false)
    assert.equal(r.issuerTrusted, false)
    assert.deepEqual(r.issuerErrors, [], 'an empty list is a legitimate state, not a configuration error')
  })

  it('an omitted option still means "no trust root consulted"', () => {
    const { passport } = attacker()
    const r = verifySocialContract(passport, null)
    assert.equal(r.issuerChecked, false)
    assert.deepEqual(r.issuerErrors, [])
  })

  it('a real anchor list is still consulted', () => {
    const issuer = generateKeyPair()
    const { passport } = attacker()
    const r = verifySocialContract(passport, null, { trustedIssuers: [issuer.publicKey] })
    assert.equal(r.issuerChecked, true, 'a well-formed anchor list must still be read')
    assert.equal(r.issuerTrusted, false, 'a self-signed passport carries no countersignature from that issuer')
  })

  for (const [label, value] of MALFORMED) {
    it(`refuses trustedIssuers = ${label} instead of discarding it`, () => {
      const { passport } = attacker()
      const r = verifySocialContract(passport, null, { trustedIssuers: value as never })

      // Neither "no anchors" nor "all anchors": the configuration error is
      // reported, and it is reported on the issuer axis, not as a defect in
      // the passport's own bytes.
      assert.ok(r.issuerErrors.length > 0,
        `${label} was discarded silently: issuerErrors is empty`)
      assert.ok(r.issuerErrors.some(e => /trustedIssuers/.test(e)),
        `the refusal must name the option: ${JSON.stringify(r.issuerErrors)}`)
      assert.equal(r.issuerTrusted, false,
        `${label} must never produce a trusted issuer`)
      assert.equal(r.overall, false,
        `${label} admitted a self-signed admin:everything passport through the deprecated accessor`)
      assert.deepEqual(r.identity.errors, [],
        'a caller configuration error is not a defect in the passport')
    })
  }

  it('a bare key string is not read as a configured anchor list', () => {
    // `'a'.repeat(64).length > 0` is true, so the old code reported
    // issuerChecked: true and ran an anchored verify against a string, whose
    // downstream membership test was substring matching.
    const issuer = generateKeyPair()
    const { passport } = attacker()
    const r = verifySocialContract(passport, null, { trustedIssuers: issuer.publicKey as never })
    assert.equal(r.issuerTrusted, false)
    assert.equal(r.overall, false)
    assert.ok(r.issuerErrors.some(e => /trustedIssuers/.test(e)), JSON.stringify(r.issuerErrors))
  })
})

describe('the envelope verifier normalizes the same way the passport readers do', () => {
  // Fourth reader of a caller-supplied trust-anchor list, added by the
  // Daybreak F-01 repair. Different option name and a different question --
  // which key may sign an execution envelope, not which issuer may vouch for
  // a passport -- but the same normalization, because a second normalization
  // is a second thing to disagree with the first.
  const signer = generateKeyPair()

  function selfSignedEnvelope(): ExecutionEnvelope {
    return createMinimalEnvelope({
      agentDid: 'did:aps:attacker', runId: 'run', actionId: 'action',
      scope: ['admin:*'], revocationStatus: 'active',
      decisionHash: 'sha256:x', policyRef: 'p', evaluationMethod: 'deterministic',
      verdict: 'permit', evaluatedAt: new Date().toISOString(),
      evaluatorDid: 'did:aps:claimed', evaluatorSignature: 'f'.repeat(128),
      receiptHash: 'sha256:x',
      signerPrivateKey: signer.privateKey, signerPublicKey: signer.publicKey,
    })
  }

  for (const [label, value] of [
    ['undefined', undefined] as [string, unknown],
    ['null', null] as [string, unknown],
    ['[] deliberate empty', []] as [string, unknown],
    ...MALFORMED,
  ]) {
    it(`no anchor shape admits a self-signed envelope: ${label}`, () => {
      // The shape under test is the anchor list. The other three inputs are
      // required in the types and are deliberately absent: a malformed anchor
      // list must refuse whatever else the caller did or did not supply.
      const result = verifyExecutionEnvelope(selfSignedEnvelope(), {
        trustedSignerPublicKeys: value as never,
      } as never)
      assert.equal(result.valid, false, `${label}: admitted`)
      assert.notEqual(result.signerAuthority, 'verified', `${label}: signer read as trusted`)
    })
  }

  it('a malformed option is a configuration error, not an empty anchor set', () => {
    const result = verifyExecutionEnvelope(selfSignedEnvelope(), {
      trustedSignerPublicKeys: new Set([signer.publicKey]) as never,
    } as never)
    assert.equal(result.signerAuthority, 'rejected')
    assert.ok(result.errors.some(e => /trustedSignerPublicKeys/.test(e)), JSON.stringify(result.errors))
  })

  it('the envelope key alone never establishes trust, even when it signed correctly', () => {
    // The envelope verifies under its own key: that is proof of possession and
    // is reported as signatureValid. It is not authorization.
    const result = verifyExecutionEnvelope(selfSignedEnvelope(), {
      trustedSignerPublicKeys: [generateKeyPair().publicKey],
    } as never)
    assert.equal(result.signatureValid, true)
    assert.equal(result.signerAuthority, 'rejected')
    assert.equal(result.valid, false)
  })
})

describe('N3: the three public entry points agree on every anchor shape', () => {
  // The transferable lesson from the retro-audit: enumerate READERS of the
  // option, not callers of the guard. This is that enumeration, asserted.
  const EVERY_SHAPE: Array<[string, unknown]> = [
    ['undefined', undefined],
    ['null', null],
    ['[] deliberate empty', []],
    ...MALFORMED,
  ]

  for (const [label, value] of EVERY_SHAPE) {
    it(`no entry point admits where another refuses: ${label}`, () => {
      const { passport } = attacker()
      const opts = { trustedIssuers: value as never }

      const vp = verifyPassport(passport, opts)
      const posture = checkPassportTrustPosture(passport, opts)
      const vsc = verifySocialContract(passport, null, opts)

      // None of the three may report a trusted issuer for a self-signed
      // admin:everything passport, whatever shape the option arrived in.
      assert.equal(posture.ok, false, `${label}: posture admitted`)
      assert.equal(vsc.issuerTrusted, false, `${label}: verifySocialContract reported a trusted issuer`)

      // And where verifyPassport rejects the CONFIGURATION outright, the
      // contract-level verdict must not read as trusted either. Matched on the
      // configuration error's own prefix rather than on the word
      // "trustedIssuers": verifyPassport now also names that option in its
      // authority verdict for a passport nobody vouched for, which is a
      // different finding and is not a rejected configuration.
      if (!vp.valid && vp.errors.some(e => e.startsWith('Invalid trustedIssuers option:'))) {
        assert.equal(vsc.overall, false,
          `${label}: verifyPassport refused the configuration and verifySocialContract admitted`)
        assert.ok(vsc.issuerErrors.length > 0,
          `${label}: verifyPassport named the option and verifySocialContract said nothing`)
      }
    })
  }
})
