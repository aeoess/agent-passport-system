// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0
//
// D1: `passport delegate --limit 0` must sign a delegation whose spendLimit is 0.
//
// Before the fix, cmdDelegate parsed the flag as
//     Number(getFlag('--limit') || '0') || undefined
// The trailing `|| undefined` discards every falsy result, and both 0 and NaN are
// falsy. So `--limit 0`, `--limit abc`, `--limit ""` and a bare `--limit` all became
// `undefined`, which means NO spend cap. An operator asking for a budget of nothing
// received unbounded authority, at exit code 0, with no warning: the `Limit:` line in
// the success output is itself guarded by `if (limit)`, so the omission was invisible.
//
// These tests drive the real CLI as an operator does and assert on the SIGNED
// ARTIFACT the CLI writes to disk, not on an intermediate variable. A test that
// checks a parsed local and never reaches a signed delegation would not close this
// defect.
import { describe, it, before, after } from 'node:test'
import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
import { mkdtempSync, rmSync, existsSync, readdirSync, readFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'

const REPO = fileURLToPath(new URL('..', import.meta.url))
const CLI = join(REPO, 'src', 'cli', 'index.ts')
const TSX = join(REPO, 'node_modules', '.bin', 'tsx')

let dir: string
let toKey: string

// Run the CLI in an isolated cwd. `DIR = '.passport'` in src/cli/index.ts is a
// RELATIVE path, so the CLI reads and writes only under the working directory.
function cli(argv: string[]) {
  return spawnSync(TSX, [CLI, ...argv], { cwd: dir, encoding: 'utf8', input: 'n\n' })
}

function delegateWith(extra: string[]) {
  const delDir = join(dir, '.passport', 'delegations')
  if (existsSync(delDir)) rmSync(delDir, { recursive: true, force: true })
  const r = cli(['delegate', '--to', toKey, '--scope', 'commerce:checkout', ...extra])
  let artifact: Record<string, unknown> | null = null
  if (existsSync(delDir)) {
    const files = readdirSync(delDir).filter(f => f.endsWith('.json'))
    if (files.length > 0) artifact = JSON.parse(readFileSync(join(delDir, files[0]), 'utf8'))
  }
  return { exit: r.status, out: (r.stdout || '') + (r.stderr || ''), artifact }
}

describe('CLI delegate --limit (D1)', () => {
  before(() => {
    dir = mkdtempSync(join(tmpdir(), 'aps-cli-limit-'))
    const j = cli(['join', '--name', 'limit-test', '--mission', 'd1 test', '--owner', 'tima'])
    assert.equal(j.status, 0, `join failed: ${(j.stdout || '') + (j.stderr || '')}`)
    toKey = JSON.parse(readFileSync(join(dir, '.passport', 'agent.json'), 'utf8')).publicKey
    assert.ok(toKey, 'agent public key missing')
  })

  after(() => {
    if (dir && existsSync(dir)) rmSync(dir, { recursive: true, force: true })
  })

  // ── The decisive assertion. This is the reason the fix exists. ──
  it('--limit 0 signs a delegation whose spendLimit is 0, not undefined and not absent', () => {
    const { exit, artifact } = delegateWith(['--limit', '0'])
    assert.equal(exit, 0, 'an explicit zero limit is a valid delegation and must succeed')
    assert.ok(artifact, 'a delegation artifact must be written')
    assert.ok(
      Object.prototype.hasOwnProperty.call(artifact, 'spendLimit'),
      'spendLimit must be PRESENT on the signed artifact, not omitted',
    )
    assert.notEqual(artifact!.spendLimit, undefined, 'spendLimit must not be undefined')
    assert.strictEqual(artifact!.spendLimit, 0, 'spendLimit must be exactly 0')
  })

  it('flag absent leaves the delegation unbounded', () => {
    const { exit, artifact } = delegateWith([])
    assert.equal(exit, 0)
    assert.ok(artifact, 'a delegation artifact must be written')
    assert.equal(
      Object.prototype.hasOwnProperty.call(artifact, 'spendLimit'), false,
      'omitting --limit must leave spendLimit absent, meaning no cap',
    )
  })

  it('a positive limit is carried through to the artifact', () => {
    const { exit, artifact } = delegateWith(['--limit', '500'])
    assert.equal(exit, 0)
    assert.strictEqual(artifact!.spendLimit, 500)
  })

  it('rejects a non-numeric value instead of silently producing an uncapped delegation', () => {
    const { exit, artifact } = delegateWith(['--limit', 'abc'])
    assert.notEqual(exit, 0, 'garbage input must exit non-zero')
    assert.equal(artifact, null, 'no delegation may be written for a rejected limit')
  })

  it('rejects the flag supplied with no value instead of silently producing an uncapped delegation', () => {
    // `--limit` is the LAST argument, so getFlag returns undefined exactly as it does
    // for an absent flag. The two cases must not be conflated.
    const { exit, artifact } = delegateWith(['--limit'])
    assert.notEqual(exit, 0, 'a valueless --limit must exit non-zero')
    assert.equal(artifact, null, 'no delegation may be written for a rejected limit')
  })

  // ── CONTROL ──
  // Drives the PRE-FIX expression directly. If this ever stops holding, the
  // description of the defect above is wrong and these tests are testing nothing.
  it('CONTROL: the pre-fix expression discarded an explicit zero', () => {
    const preFix = (raw: string | undefined): number | undefined =>
      Number(raw || '0') || undefined

    assert.equal(preFix('0'), undefined,
      'pre-fix: an explicit 0 collapsed to undefined, which signed an UNCAPPED delegation')
    assert.equal(preFix('abc'), undefined, 'pre-fix: NaN is falsy, so garbage also became uncapped')
    assert.equal(preFix(''), undefined, 'pre-fix: an empty value also became uncapped')
    assert.equal(preFix(undefined), undefined, 'pre-fix: absent and valueless were indistinguishable')
    assert.equal(preFix('500'), 500, 'pre-fix: only truthy numbers survived')
  })
})
