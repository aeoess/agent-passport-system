#!/usr/bin/env node
// Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// ══════════════════════════════════════════════════════════════════
// verify-payment-rail-conformance.mjs
// ══════════════════════════════════════════════════════════════════
// Run the standard payment-rails conformance scenarios against any
// adapter module that exports a PaymentRail-shaped object.
//
// Usage:
//   node  scripts/verify-payment-rail-conformance.mjs <rail-module-path>
//   npx tsx scripts/verify-payment-rail-conformance.mjs <rail-module-path>   # TS adapter
//
// Flags:
//   --json       Emit a JSON-only report on stdout (no human formatting).
//   --quiet      Suppress per-scenario lines; print summary only.
//
// Module shape (any one of the following, checked in this order):
//   1. default export `{ rail, hooks? }`
//   2. default export async/sync function returning `{ rail, hooks? }`
//   3. named exports `rail` (+ optional `hooks`)
//   4. named export `setup` (async function returning `{ rail, hooks? }`)
//   5. named export `createRail` (factory) — hooks default to
//      createDefaultGovernanceHooks()
//
// When `hooks` is omitted, the script falls back to
// createDefaultGovernanceHooks() from this SDK.
//
// Exit code: 0 when all scenarios pass; 1 on any failure or load error.
// ══════════════════════════════════════════════════════════════════

import { resolve as resolvePath } from 'node:path'
import { pathToFileURL } from 'node:url'
import { createDefaultGovernanceHooks } from '../src/v2/payment-rails/hooks.js'
import { runConformance } from '../src/v2/payment-rails/conformance/index.js'

const argv = process.argv.slice(2)
const flags = new Set(argv.filter((a) => a.startsWith('--')))
const positional = argv.filter((a) => !a.startsWith('--'))

if (positional.length !== 1) {
  console.error(
    'usage: verify-payment-rail-conformance.mjs <rail-module-path> [--json] [--quiet]',
  )
  process.exit(1)
}

const modulePath = positional[0]
const wantJson = flags.has('--json')
const quiet = flags.has('--quiet')

let mod
try {
  const abs = resolvePath(process.cwd(), modulePath)
  mod = await import(pathToFileURL(abs).href)
} catch (e) {
  console.error(`failed to load rail module '${modulePath}': ${e?.message ?? e}`)
  process.exit(1)
}

// Resolve { rail, hooks } from the module's exports.
async function _resolveRailAndHooks(m) {
  // 1. default export
  if (m.default !== undefined) {
    const d = typeof m.default === 'function' ? await m.default() : m.default
    if (d && typeof d === 'object' && d.rail) {
      return { rail: d.rail, hooks: d.hooks }
    }
  }
  // 2. named rail / hooks
  if (m.rail) return { rail: m.rail, hooks: m.hooks }
  // 3. setup()
  if (typeof m.setup === 'function') {
    const s = await m.setup()
    if (s && s.rail) return { rail: s.rail, hooks: s.hooks }
  }
  // 4. createRail factory
  if (typeof m.createRail === 'function') {
    const r = await m.createRail()
    return { rail: r, hooks: undefined }
  }
  return null
}

const resolved = await _resolveRailAndHooks(mod)
if (!resolved || !resolved.rail) {
  console.error(
    `module '${modulePath}' did not export a PaymentRail-shaped object.\n` +
      'Expected one of: default = { rail, hooks? }, named rail/hooks, ' +
      'setup(), or createRail().',
  )
  process.exit(1)
}

const rail = resolved.rail
const hooks = resolved.hooks ?? createDefaultGovernanceHooks()

// Light shape check before running scenarios — clearer error than a
// scenario failure when the module exports the wrong thing.
const REQUIRED = [
  'name',
  'currency',
  'createInvoice',
  'checkStatus',
  'verifyTransaction',
  'revokeWallet',
  'isWalletRevoked',
]
for (const k of REQUIRED) {
  if (rail[k] === undefined) {
    console.error(`rail module is missing required PaymentRail property: ${k}`)
    process.exit(1)
  }
}

const report = await runConformance(rail, hooks)

if (wantJson) {
  console.log(JSON.stringify(report, null, 2))
  process.exit(report.all_pass ? 0 : 1)
}

const GREEN = '\x1b[32m'
const RED = '\x1b[31m'
const DIM = '\x1b[2m'
const RESET = '\x1b[0m'

if (!quiet) {
  console.log(
    `\nPaymentRail conformance — rail=${report.rail_name} currency=${report.rail_currency}`,
  )
  console.log(`Run started ${report.started_at}`)
  console.log('─'.repeat(72))
  for (const s of report.scenarios) {
    const tag = s.pass ? `${GREEN}PASS${RESET}` : `${RED}FAIL${RESET}`
    const dur = `${DIM}${s.duration_ms}ms${RESET}`
    console.log(`  ${tag}  ${s.id}  ${s.description}  ${dur}`)
    if (!s.pass && s.reason) {
      console.log(`         ${RED}↳ ${s.reason}${RESET}`)
    }
  }
  console.log('─'.repeat(72))
}

const tag = report.all_pass ? `${GREEN}ALL PASS${RESET}` : `${RED}FAIL${RESET}`
console.log(
  `${tag}  ${report.passed}/${report.total} scenarios passed  ` +
    `(${report.failed} failed)`,
)
process.exit(report.all_pass ? 0 : 1)
