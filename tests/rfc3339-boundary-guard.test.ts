// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0
// ══════════════════════════════════════════════════════════════════
// A boundary file may not turn text into a time.
// ══════════════════════════════════════════════════════════════════
// F-04 was not one bug, it was a habit. `new Date(x)` and `Date.parse(x)`
// accept a string as readily as a number and report failure only as NaN,
// which compares false in both directions — so an expiry check written the
// obvious way answers "not expired" for a value that is not a date. The
// individual sites are fixed; this test closes the class, because the next
// person to add an expiry check to one of these files will reach for the
// same two constructs.
//
// THE RULE. Under the roots below, a file may read the clock (`new Date()`,
// `Date.now()`), and may turn an instant it already holds into text
// (`formatRfc3339(ms)`, which takes a `number`, so the compiler refuses an
// artifact's field). It may not construct a Date from a value, and it may
// not call `Date.parse`. Interpreting text as a time goes through
// `parseRfc3339`, which returns a reason instead of NaN.
//
// WHAT THIS GUARD DOES NOT CATCH. It is syntactic. It cannot tell whose
// value reaches `parseRfc3339`, and it does not look outside these roots —
// `src/v2/` has its own strict gates and is not swept here. What it does
// guarantee is that no file under these roots can silently reacquire the
// lenient parse, including a file that does not exist yet.
// ══════════════════════════════════════════════════════════════════

import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import { readdirSync, readFileSync, statSync } from 'node:fs'
import { join, dirname, relative } from 'node:path'
import { fileURLToPath } from 'node:url'

const REPO_ROOT = join(dirname(fileURLToPath(import.meta.url)), '..')

/** Directories swept. These are the artifact-verifying surfaces the audit
 *  covered plus the two that share their verifiers. */
const ROOTS = ['src/core', 'src/verification', 'src/adapters']

/** No file under a swept root may construct a Date from a value.
 *
 *  This map was non-empty: `normalizeTimestamp` (src/core/canonical.ts) was
 *  exempted because tightening what it ACCEPTS changes which inputs produce
 *  which content address, which is wire-visible and was deferred. That
 *  decision has since been taken and the function now parses through
 *  parseRfc3339, so the exemption is gone and the guard covers the file. The
 *  map stays, with its emptiness asserted below, so that reintroducing an
 *  exemption is a visible edit rather than a quiet one. */
const EXEMPT = new Map<string, string>([])

const BANNED = [
  { name: 'new Date(<argument>)', pattern: /new\s+Date\s*\(\s*[^)]/ },
  { name: 'Date.parse(', pattern: /Date\s*\.\s*parse\s*\(/ },
]

/** Strip line comments, block comments and quoted strings, so prose that
 *  names a banned construct — including this file's own header, and the
 *  comments the repair added explaining each conversion — does not trip the
 *  ban. Template literals are left alone: they can contain real code inside
 *  `${…}`, and a guard that blinded itself to that would be weaker than the
 *  one it replaces. */
function strip(src: string): string {
  return src
    .replace(/\/\*[\s\S]*?\*\//g, ' ')
    .replace(/(^|[^:])\/\/.*$/gm, '$1')
    .replace(/'(?:[^'\\\n]|\\.)*'/g, "''")
    .replace(/"(?:[^"\\\n]|\\.)*"/g, '""')
}

function walk(dir: string, out: string[] = []): string[] {
  for (const entry of readdirSync(dir)) {
    if (entry === 'node_modules' || entry === '__tests__') continue
    const p = join(dir, entry)
    if (statSync(p).isDirectory()) walk(p, out)
    else if (entry.endsWith('.ts') && !entry.endsWith('.d.ts')) out.push(p)
  }
  return out
}

const files = ROOTS.flatMap(r => walk(join(REPO_ROOT, r)))
  .map(f => relative(REPO_ROOT, f))
  .sort()

describe('boundary files interpret time only through parseRfc3339', () => {
  it('scans a non-empty set of sources under every declared root', () => {
    assert.ok(files.length > 100,
      `the guard scanned only ${files.length} files; it is not looking where it thinks it is`)
    for (const root of ROOTS) {
      assert.ok(files.some(f => f.startsWith(root + '/')),
        `no files found under ${root}; the guard is silently covering nothing there`)
    }
  })

  it('no boundary file constructs a Date from a value or calls Date.parse', () => {
    const offenders: string[] = []
    for (const file of files) {
      if (EXEMPT.has(file)) continue
      const src = strip(readFileSync(join(REPO_ROOT, file), 'utf8'))
      src.split('\n').forEach((line, i) => {
        for (const { name, pattern } of BANNED) {
          if (pattern.test(line)) offenders.push(`${file}:${i + 1}  ${name}  ${line.trim().slice(0, 100)}`)
        }
      })
    }
    assert.deepEqual(offenders, [],
      `these sites interpret a value as a time outside the primitive:\n${offenders.join('\n')}\n` +
      'Use parseRfc3339 to read a timestamp and formatRfc3339 to emit one; ' +
      'a zero-argument new Date() to read the clock is fine.')
  })

  it('the exemption list is empty, and adding to it is a visible edit', () => {
    // It held src/core/canonical.ts until normalizeTimestamp was routed
    // through parseRfc3339. Asserting emptiness means a future exemption
    // cannot be added without also editing this expectation.
    assert.equal(EXEMPT.size, 0,
      `unexpected exemptions: ${[...EXEMPT.keys()].join(', ')}`)
  })

  it('every exemption still exists, so the list cannot rot into a blanket', () => {
    for (const [file, reason] of EXEMPT) {
      assert.ok(files.includes(file),
        `${file} is exempted (${reason}) but no longer exists under a swept root; drop the exemption`)
      const src = strip(readFileSync(join(REPO_ROOT, file), 'utf8'))
      assert.ok(BANNED.some(b => b.pattern.test(src)),
        `${file} is exempted but no longer contains a banned construct; drop the exemption`)
    }
  })

  it('the primitive itself never constructs a Date', () => {
    // parseRfc3339 computes its instant arithmetically. If it ever reached for
    // a Date it would inherit the two-digit-year and day-overflow behaviours it
    // exists to refuse, and this guard's whole premise would be circular.
    const src = strip(readFileSync(join(REPO_ROOT, 'src/core/rfc3339.ts'), 'utf8'))
    for (const { name, pattern } of BANNED) {
      assert.equal(pattern.test(src), false, `src/core/rfc3339.ts uses ${name}`)
    }
    assert.equal(/new\s+Date\s*\(/.test(src), false, 'src/core/rfc3339.ts constructs a Date')
  })
})
