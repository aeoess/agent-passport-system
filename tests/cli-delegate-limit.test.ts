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

describe('CLI delegate numeric flags (--limit, --depth, --hours)', () => {
  before(() => {
    dir = mkdtempSync(join(tmpdir(), 'aps-cli-numeric-'))
    const j = cli(['join', '--name', 'numeric-test', '--mission', 'numeric flag test', '--owner', 'tima'])
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

  // ── --depth ──
  // maxDepth has NO downstream validation in createDelegation, unlike spendLimit, so
  // the CLI is the only gate.

  // The decisive new case. `Number('abc')` is NaN, NaN reached createDelegation
  // unvalidated, and JSON.stringify(NaN) emits null. Chain verifiers guard the depth
  // rule on the ceiling being present, so a signed `maxDepth: null` REMOVED the depth
  // bound rather than tightening it. A typo widened authority.
  it('--depth abc exits non-zero and writes no artifact', () => {
    const { exit, artifact } = delegateWith(['--depth', 'abc'])
    assert.notEqual(exit, 0, 'a non-numeric depth must exit non-zero')
    assert.equal(artifact, null, 'no delegation may be written for a rejected depth')
  })

  it('a valid --depth is carried through to maxDepth', () => {
    const { exit, artifact } = delegateWith(['--depth', '5'])
    assert.equal(exit, 0)
    assert.ok(artifact, 'a delegation artifact must be written')
    assert.strictEqual(artifact!.maxDepth, 5)
  })

  it('--depth 0 is a valid ceiling and is carried through', () => {
    const { exit, artifact } = delegateWith(['--depth', '0'])
    assert.equal(exit, 0, 'a zero depth ceiling is meaningful: no sub-delegation')
    assert.strictEqual(artifact!.maxDepth, 0)
  })

  it('--depth absent keeps the default ceiling', () => {
    const { exit, artifact } = delegateWith([])
    assert.equal(exit, 0)
    assert.strictEqual(artifact!.maxDepth, 1, 'omitting --depth must keep the documented default')
  })

  it('--depth never signs a null ceiling for any rejected input', () => {
    for (const bad of ['abc', '1.5', '-1', '0x10', '1e3']) {
      const { exit, artifact } = delegateWith(['--depth', bad])
      assert.notEqual(exit, 0, `--depth ${bad} must exit non-zero`)
      assert.equal(artifact, null, `--depth ${bad} must write no artifact`)
    }
  })

  // ── --hours ──

  it('--hours abc exits non-zero and writes no artifact', () => {
    const { exit, artifact } = delegateWith(['--hours', 'abc'])
    assert.notEqual(exit, 0, 'a non-numeric hours value must exit non-zero')
    assert.equal(artifact, null, 'no delegation may be written for a rejected hours value')
  })

  it('--hours accepts a fractional value, which createDelegation supports exactly', () => {
    const { exit, artifact } = delegateWith(['--hours', '0.5'])
    assert.equal(exit, 0, 'fractional hours are deliberately supported downstream')
    assert.ok(artifact, 'a delegation artifact must be written')
    assert.ok(typeof artifact!.expiresAt === 'string' && artifact!.expiresAt.length > 0)
  })

  // ── decimal grammar, shared by all three flags ──
  // `0x64` reads as sixty-four to a human and to every base-10 parser while Number()
  // evaluates it to one hundred. On a spend cap that ambiguity is not acceptable.

  it('--limit 0x64 exits non-zero and writes no artifact', () => {
    const { exit, artifact } = delegateWith(['--limit', '0x64'])
    assert.notEqual(exit, 0, 'a hexadecimal literal must be rejected, not read as 100')
    assert.equal(artifact, null, 'no delegation may be written for a rejected limit')
  })

  it('non-decimal lexical forms are rejected on --limit', () => {
    for (const bad of ['0x64', '1e3', '+5', '5.', '.5', ' 5 ']) {
      const { exit, artifact } = delegateWith(['--limit', bad])
      assert.notEqual(exit, 0, `--limit ${JSON.stringify(bad)} must exit non-zero`)
      assert.equal(artifact, null, `--limit ${JSON.stringify(bad)} must write no artifact`)
    }
  })

  it('canonical decimal values still work on --limit', () => {
    for (const [raw, want] of [['0', 0], ['500', 500], ['0.5', 0.5], ['007', 7]] as const) {
      const { exit, artifact } = delegateWith(['--limit', raw])
      assert.equal(exit, 0, `--limit ${raw} must succeed`)
      assert.strictEqual(artifact!.spendLimit, want, `--limit ${raw} must sign ${want}`)
    }
  })

  // ── CONTROL for the depth defect ──
  // If this ever stops holding, the description of the depth defect is wrong.
  it('CONTROL: NaN depth serializes to a null ceiling', () => {
    assert.ok(Number.isNaN(Number('abc')), "Number('abc') must be NaN")
    assert.equal(
      JSON.stringify({ maxDepth: Number('abc') }), '{"maxDepth":null}',
      'JSON.stringify emits null for NaN, which is how a typo removed the depth ceiling',
    )
    // `??` is nullish, so NaN is NOT replaced by the default. This is why the NaN
    // survived `maxDepth: opts.maxDepth ?? 1` in createDelegation.
    const viaNullish = Number('abc') ?? 1
    assert.ok(Number.isNaN(viaNullish), 'NaN survives ?? because NaN is not nullish')
  })
})
