// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0
// ══════════════════════════════════════════════════════════════════
// Materialize the conformance golden fixtures to JSON on disk.
// ══════════════════════════════════════════════════════════════════
// Run with: npx tsx tests/conformance/write-fixtures.ts
//
// The on-disk JSON files are the cross-implementation anchor: a Go,
// Rust, or Python verifier validates against THESE bytes. The TypeScript
// test suite re-derives the same fixtures from the generator and asserts
// the on-disk copies match, so the JSON can never silently drift from
// the code path that produced it.
// ══════════════════════════════════════════════════════════════════

import { writeFileSync, mkdirSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { buildGoldenValid, buildNegatives } from './generate.js'

const __dirname = dirname(fileURLToPath(import.meta.url))
const OUT_DIR = join(__dirname, 'golden-fixtures')

// Stable JSON serialization: 2-space indent, trailing newline. bigint in
// the context layer is serialized as a decimal string so the JSON stays
// portable. The generator re-reads these as bigint via the test's own
// reviver, so no precision is lost.
function stable(value: unknown): string {
  return (
    JSON.stringify(
      value,
      (_k, v) => (typeof v === 'bigint' ? v.toString() : v),
      2,
    ) + '\n'
  )
}

export function writeAll(): string[] {
  mkdirSync(OUT_DIR, { recursive: true })
  const written: string[] = []

  const golden = buildGoldenValid()
  const goldenPath = join(OUT_DIR, `${golden.id}.json`)
  writeFileSync(goldenPath, stable(golden), 'utf8')
  written.push(goldenPath)

  for (const neg of buildNegatives()) {
    const p = join(OUT_DIR, `${neg.id}.json`)
    writeFileSync(p, stable(neg), 'utf8')
    written.push(p)
  }

  // Index file enumerating the package contents and the rejection reason
  // each negative carries. This is the manifest a cross-implementation
  // harness reads first.
  const index = {
    package: 'aps-conformance-golden-negatives',
    version: 1,
    description:
      'Golden valid and negative fixtures for APS receipt verification. Each negative must be rejected for the stated reason by a conformant verifier.',
    fixed_now: '2026-05-01T12:00:00.000Z',
    golden_valid: [golden.id],
    negatives: buildNegatives().map((n) => ({
      id: n.id,
      reason: n.expected_reject_reason,
      layer: n.layer,
      description: n.description,
    })),
  }
  const indexPath = join(OUT_DIR, 'INDEX.json')
  writeFileSync(indexPath, stable(index), 'utf8')
  written.push(indexPath)

  return written
}

// Direct invocation materializes the files.
if (import.meta.url === `file://${process.argv[1]}`) {
  const files = writeAll()
  for (const f of files) {
    process.stdout.write(`wrote ${f}\n`)
  }
}
