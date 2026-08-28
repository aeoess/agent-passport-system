// Copyright (c) 2026 Insight (oracleinsight.xyz)
// SPDX-License-Identifier: Apache-2.0
//
// Determinism gate for the oracle-safety-check generator.
//
// The generator must be reproducible: running it twice from a clean checkout
// has to produce byte-identical output, otherwise the vectors committed in the
// conformance suite are not tied to their source. This runs it twice in the
// same process and compares the bytes, so it works from a clean checkout with
// no committed output to diff against.
//
// Run: npm run test:fixtures-determinism   (wired into npm test)

import { readFileSync, readdirSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

import { generateAllFixtures } from './generate-fixtures.js'

const __dirname = dirname(fileURLToPath(import.meta.url))

interface Snapshot {
  files: string[]
  bytes: Map<string, Buffer>
}

async function runOnce(): Promise<Snapshot> {
  const dir = await generateAllFixtures()
  const files = readdirSync(dir).filter((f) => f.endsWith('.json')).sort()
  const bytes = new Map<string, Buffer>()
  for (const f of files) bytes.set(f, readFileSync(join(dir, f)))
  return { files, bytes }
}

function compare(a: Snapshot, b: Snapshot): string[] {
  const problems: string[] = []
  if (a.files.length !== b.files.length) {
    problems.push(`file count differs: ${a.files.length} then ${b.files.length}`)
  }
  const names = [...new Set([...a.files, ...b.files])].sort()
  for (const name of names) {
    const left = a.bytes.get(name)
    const right = b.bytes.get(name)
    if (!left) {
      problems.push(`${name}: missing on the first run`)
      continue
    }
    if (!right) {
      problems.push(`${name}: missing on the second run`)
      continue
    }
    if (!left.equals(right)) {
      problems.push(`${name}: bytes differ between runs (${left.length} vs ${right.length})`)
    }
  }
  return problems
}

const first = await runOnce()
const second = await runOnce()
const problems = compare(first, second)

if (problems.length > 0) {
  for (const p of problems) console.log(`[FAIL] ${p}`)
  console.log(`\n${problems.length} problem(s): the generator is not deterministic`)
  process.exit(1)
}

console.log(`${first.files.length} fixtures, two runs, byte-identical`)
