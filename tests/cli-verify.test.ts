// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0
//
// The `passport verify` trust-root report, driven as an operator drives it.
//
// This command is what renders a verification verdict to a human, and before
// this work it printed "✅ TRUSTED" over any self-signed passport, because
// verifySocialContract returned a structural conjunction under the name
// `overall` and the CLI printed that. The review then found the opposite
// failure in the first fix: with anchors supplied, a passport whose signature
// was fine printed as a failure.
//
// The whole CLI change shipped with no test. These drive the real binary and
// assert on the OPERATOR-VISIBLE OUTPUT, which is the artifact that carries
// the claim. Asserting on verifySocialContract's return value instead would
// not close this: the defect was in what the operator was told.
import { describe, it, before, after } from 'node:test'
import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
import { mkdtempSync, rmSync, readFileSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { generateKeyPair } from '../src/crypto/keys.js'
import { countersignPassport } from '../src/core/passport.js'
import type { SignedPassport } from '../src/types/passport.js'

const REPO = fileURLToPath(new URL('..', import.meta.url))
const CLI = join(REPO, 'src', 'cli', 'index.ts')
const TSX = join(REPO, 'node_modules', '.bin', 'tsx')

let dir: string
let selfSigned: SignedPassport

function cli(argv: string[]) {
  const r = spawnSync(TSX, [CLI, ...argv], { cwd: dir, encoding: 'utf8', input: 'n\n' })
  return { exit: r.status, out: (r.stdout || '') + (r.stderr || '') }
}

// The CLI reads `data.passport || data`, so a file whose TOP LEVEL is a
// SignedPassport has its inner AgentPassport picked out and reports
// "Missing passport or signature". Fixtures therefore use the agent-file
// shape, which is the shape `passport join` writes and the one the command
// is actually exercised through. (The passport-only shape that comment
// promises is broken, but it fails CLOSED and is not in scope here; it is
// reported to the coordinator rather than fixed in a security branch.)
function writePassport(name: string, p: SignedPassport): string {
  const file = join(dir, name)
  writeFileSync(file, JSON.stringify({ passport: p }, null, 2))
  return name
}

describe('CLI verify: the trust-root report', () => {
  before(() => {
    dir = mkdtempSync(join(tmpdir(), 'aps-cli-verify-'))
    const j = cli(['join', '--name', 'verify-test', '--mission', 'cli verify test', '--owner', 'tima'])
    assert.equal(j.exit, 0, `join failed: ${j.out}`)
    const agent = JSON.parse(readFileSync(join(dir, '.passport', 'agent.json'), 'utf8'))
    selfSigned = agent.passport
  })

  after(() => {
    if (dir) rmSync(dir, { recursive: true, force: true })
  })

  it('a self-signed passport is reported as SELF-SIGNED, never as TRUSTED', () => {
    const r = cli(['verify', '.passport/agent.json'])
    assert.match(r.out, /SELF-SIGNED/)
    assert.doesNotMatch(r.out, /✅ TRUSTED/, 'a passport that vouches for itself is not TRUSTED')
    assert.match(r.out, /Identity: ✓ valid/)
    assert.match(r.out, /no trust root supplied/)
  })

  it('the self-signed report tells the operator how to supply a trust root', () => {
    const r = cli(['verify', '.passport/agent.json'])
    assert.match(r.out, /--trusted-issuer/)
  })

  it('a tampered passport is reported as DOES NOT VERIFY', () => {
    const tampered: SignedPassport = {
      ...selfSigned,
      passport: { ...selfSigned.passport, mission: 'rewritten after signing' },
    }
    const r = cli(['verify', writePassport('tampered.json', tampered)])
    assert.match(r.out, /DOES NOT VERIFY/)
    // Pin the REASON, not just the verdict. A malformed fixture also prints
    // DOES NOT VERIFY, so without this the test would pass while proving
    // nothing about tamper detection.
    assert.match(r.out, /Invalid signature/)
    assert.doesNotMatch(r.out, /SELF-SIGNED/)
  })

  it('a passport countersigned by a supplied trusted issuer is reported TRUSTED', () => {
    const issuer = generateKeyPair()
    const countersigned = countersignPassport(selfSigned, issuer.privateKey, 'test-ca')
    const r = cli(['verify', writePassport('countersigned.json', countersigned), '--trusted-issuer', issuer.publicKey])
    assert.match(r.out, /✅ TRUSTED/)
    assert.match(r.out, /Issuer:   ✓ trusted/)
  })

  it('INVARIANT 5: a sound passport with anchors supplied is NOT reported as a verification failure', () => {
    // The passport's bytes are fine; only the trust root is absent. The first
    // fix printed DOES NOT VERIFY here, which told the operator the passport
    // was broken when it was not.
    const issuer = generateKeyPair()
    const r = cli(['verify', '.passport/agent.json', '--trusted-issuer', issuer.publicKey])
    assert.doesNotMatch(r.out, /DOES NOT VERIFY/, 'a passport that verifies must not print as a verification failure')
    assert.match(r.out, /NOT TRUSTED/)
    assert.match(r.out, /Identity: ✓ valid/, 'the passport itself still reports as valid')
  })

  it('a countersignature from an issuer outside the allowlist is NOT TRUSTED, and says why', () => {
    const trusted = generateKeyPair()
    const rogue = generateKeyPair()
    const countersigned = countersignPassport(selfSigned, rogue.privateKey, 'rogue-ca')
    const r = cli(['verify', writePassport('rogue.json', countersigned), '--trusted-issuer', trusted.publicKey])
    assert.match(r.out, /NOT TRUSTED/)
    assert.doesNotMatch(r.out, /✅ TRUSTED/)
    assert.match(r.out, /not in trusted issuers list/)
  })

  it('--trusted-issuer is repeatable and every value counts', () => {
    // getFlag returns only the FIRST value for a flag, so a second anchor used
    // to be silently dropped. An operator listing two CAs and being verified
    // against only the first is a silent narrowing they were not told about.
    const first = generateKeyPair()
    const second = generateKeyPair()
    const countersigned = countersignPassport(selfSigned, second.privateKey, 'second-ca')
    const file = writePassport('second.json', countersigned)
    const r = cli(['verify', file, '--trusted-issuer', first.publicKey, '--trusted-issuer', second.publicKey])
    assert.match(r.out, /✅ TRUSTED/, 'the second --trusted-issuer was dropped')
  })

  it('--trusted-issuer accepts a comma-separated list', () => {
    const first = generateKeyPair()
    const second = generateKeyPair()
    const countersigned = countersignPassport(selfSigned, second.privateKey, 'second-ca')
    const file = writePassport('second-csv.json', countersigned)
    const r = cli(['verify', file, '--trusted-issuer', `${first.publicKey},${second.publicKey}`])
    assert.match(r.out, /✅ TRUSTED/)
  })

  it('the usage line documents the trust-root flag', () => {
    const r = cli(['verify'])
    assert.notEqual(r.exit, 0)
    assert.match(r.out, /--trusted-issuer/)
    assert.match(r.out, /SELF-SIGNED rather than TRUSTED/)
  })
})
