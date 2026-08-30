// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0
// ══════════════════════════════════════════════════════════════════
// A test may not resolve anything through the user's home directory.
// ══════════════════════════════════════════════════════════════════
// RETRO-AUDIT C7. tests/reversibility-profile-parity.test.ts resolved two
// sibling SDK checkouts as `join(homedir(), 'agent-passport-python')` and
// `join(homedir(), 'agent-passport-go')`, unconditionally and with no env
// override. On the machine that produced this branch's green evidence both
// paths existed and both sat at their PRE-REMEDIATION base commits, so four
// assertions ran against trees nobody had reviewed; under a hermetic runner
// the same four convert to skips. Measured: `npm test` reports 4785 total
// either way, and pass moves 4780 -> 4776 while skipped moves 5 -> 9. The
// exit code is 0 in both runs and says nothing about which one you have.
//
// The instance is fixed. This closes the class. It is a source-level
// assertion on purpose: the branch it guards does not execute under the very
// conditions that would make it observable.

import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import { readdirSync, readFileSync, statSync } from 'node:fs'
import { join, dirname, relative } from 'node:path'
import { fileURLToPath } from 'node:url'

const TESTS_DIR = dirname(fileURLToPath(import.meta.url))

function walk(dir: string, out: string[] = []): string[] {
  for (const entry of readdirSync(dir)) {
    if (entry === 'node_modules' || entry === 'fixtures' || entry === '.git') continue
    const p = join(dir, entry)
    if (statSync(p).isDirectory()) walk(p, out)
    else if (/\.(test\.ts|test\.tsx|ts)$/.test(entry)) out.push(p)
  }
  return out
}

/** Strip line and block comments so a comment explaining the ban does not
 *  trip the ban — the failure mode the equivalent Go guard hit first. */
function stripComments(src: string): string {
  return src.replace(/\/\*[\s\S]*?\*\//g, '').replace(/^\s*\/\/.*$/gm, '')
}

describe('hermeticity: no test resolves a path through the user home directory', () => {
  const files = walk(TESTS_DIR)

  it('scans a non-empty set of test sources', () => {
    assert.ok(files.length > 100,
      `the guard scanned only ${files.length} files; it is not looking where it thinks it is`)
  })

  it('no test calls homedir(), os.homedir() or reads $HOME directly', () => {
    const offenders: string[] = []
    for (const f of files) {
      if (f === fileURLToPath(import.meta.url)) continue
      const src = stripComments(readFileSync(f, 'utf8'))
      for (const pattern of [/\bhomedir\s*\(/, /\bos\.homedir\s*\(/, /process\.env\.HOME\b/, /process\.env\.USERPROFILE\b/]) {
        if (pattern.test(src)) offenders.push(`${relative(TESTS_DIR, f)}: ${pattern.source}`)
      }
    }
    assert.deepEqual(offenders, [],
      'a test resolves a path through the user home directory, so it reads a tree it does not own ' +
      'and its result depends on what happens to be checked out there. Name the checkout with an ' +
      'APS_*_REPO environment variable and skip when it is unset:\n  ' + offenders.join('\n  '))
  })

  it('the reversibility parity test names its sibling checkouts explicitly', () => {
    const src = readFileSync(join(TESTS_DIR, 'reversibility-profile-parity.test.ts'), 'utf8')
    assert.ok(/process\.env\.APS_PY_REPO/.test(src), 'the Python parity check no longer reads APS_PY_REPO')
    assert.ok(/process\.env\.APS_GO_REPO/.test(src), 'the Go parity check no longer reads APS_GO_REPO')
    assert.ok(!/homedir\s*\(/.test(stripComments(src)), 'the homedir fallback is back')
  })
})
