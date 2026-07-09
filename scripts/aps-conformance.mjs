#!/usr/bin/env node
// Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// ══════════════════════════════════════════════════════════════════
// aps-conformance.mjs
// ══════════════════════════════════════════════════════════════════
// Run the APS canonicalization conformance vectors against this
// implementation's canonicalizers and fail on a single-byte divergence.
// The pinned vector corpus is the cross-implementation byte anchor at
// specs/test-vectors-canonicalization.json; the runner also asserts that
// corpus is byte-identical to the code mirror getTestVectors(), so a
// drift between the two surfaces is itself a conformance failure.
//
// Usage:
//   node      scripts/aps-conformance.mjs [--json] [--quiet] [--vectors <path>]
//   npx tsx   scripts/aps-conformance.mjs [--json] [--quiet] [--vectors <path>]
//
// Flags:
//   --json            Emit a JSON-only report on stdout (no human formatting).
//   --quiet           Suppress per-check lines; print the summary only.
//   --vectors <path>  Override the canonicalization vectors JSON corpus.
//                     Defaults to specs/test-vectors-canonicalization.json.
//
// Exit code: 0 when every check passes; 1 on any divergence or load error.
// ══════════════════════════════════════════════════════════════════

import { readFileSync } from 'node:fs'
import { resolve as resolvePath, dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { runCanonicalizationConformance } from '../src/v2/offline-verifier/conformance-runner.js'

const __dirname = dirname(fileURLToPath(import.meta.url))
const REPO_ROOT = resolvePath(__dirname, '..')

const argv = process.argv.slice(2)
const flags = new Set(argv.filter((a) => a.startsWith('--') && !a.includes('=') && a !== '--vectors'))
const wantJson = flags.has('--json')
const quiet = flags.has('--quiet')

// --vectors <path> | --vectors=<path>
function readFlagValue(name) {
  const eq = argv.find((a) => a.startsWith(`${name}=`))
  if (eq) return eq.slice(name.length + 1)
  const idx = argv.indexOf(name)
  if (idx !== -1 && argv[idx + 1] && !argv[idx + 1].startsWith('--')) return argv[idx + 1]
  return undefined
}

const vectorsPath =
  readFlagValue('--vectors') ?? join(REPO_ROOT, 'specs', 'test-vectors-canonicalization.json')

let externalVectors
try {
  const raw = readFileSync(resolvePath(process.cwd(), vectorsPath), 'utf-8')
  externalVectors = JSON.parse(raw)
  if (!Array.isArray(externalVectors)) {
    throw new Error('vectors corpus is not a JSON array')
  }
} catch (e) {
  console.error(`failed to load canonicalization vectors '${vectorsPath}': ${e?.message ?? e}`)
  process.exit(1)
}

const report = runCanonicalizationConformance(externalVectors)

if (wantJson) {
  console.log(JSON.stringify(report, null, 2))
  process.exit(report.allPass ? 0 : 1)
}

const GREEN = '\x1b[32m'
const RED = '\x1b[31m'
const DIM = '\x1b[2m'
const RESET = '\x1b[0m'

if (!quiet) {
  console.log('\nAPS canonicalization conformance')
  console.log(`vectors: ${vectorsPath}`)
  console.log('-'.repeat(72))
  for (const c of report.tests) {
    const tag = c.passed ? `${GREEN}PASS${RESET}` : `${RED}FAIL${RESET}`
    const dur = `${DIM}${c.durationMs}ms${RESET}`
    console.log(`  ${tag}  ${c.id}  ${c.name}  ${dur}`)
    if (!c.passed && c.detail) {
      console.log(`         ${RED}> ${c.detail}${RESET}`)
    }
  }
  console.log('-'.repeat(72))
}

const tag = report.allPass ? `${GREEN}ALL PASS${RESET}` : `${RED}FAIL${RESET}`
console.log(`${tag}  ${report.passed}/${report.total} checks passed  (${report.failed} failed)`)
process.exit(report.allPass ? 0 : 1)
