#!/usr/bin/env node
// Conformance verifier for action_ref v1 (action-ref-v1-jcs-sha256), pinned
// to shipping code: it imports computeExternalActionRefV1 from the SDK build
// (run `npm run build` first), so the vectors are checked against the real
// implementation, not a reimplementation. The independent recomputation
// lives in verify.py.
//
// Exit 0 on full pass. Nonzero with a per-vector diff on any failure.

import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { dirname, join } from 'node:path'
import { computeExternalActionRefV1 } from '../../dist/src/core/external-action-ref.js'

const here = dirname(fileURLToPath(import.meta.url))
const suite = JSON.parse(readFileSync(join(here, 'vectors.json'), 'utf-8'))

const toApiInput = (inp) => ({
  agentId: inp.agent_id,
  actionType: inp.action_type,
  scope: inp.scope,
  timestamp: inp.timestamp,
})

const failures = []
let accepted = 0
let rejected = 0

for (const vec of suite.vectors) {
  if (vec.reject) {
    let threw = false
    try {
      computeExternalActionRefV1(toApiInput(vec.input))
    } catch {
      threw = true
    }
    if (threw) rejected += 1
    else failures.push(`${vec.id}: implementation ACCEPTED invalid timestamp ${JSON.stringify(vec.input.timestamp)} (${vec.reason})`)
    continue
  }

  const got = computeExternalActionRefV1(toApiInput(vec.input))
  if (got !== vec.expected) {
    failures.push(`${vec.id}: hash mismatch\n  expected: ${vec.expected}\n  computed: ${got}`)
    continue
  }
  let ok = true
  for (const [i, raw] of (vec.input_json_variants ?? []).entries()) {
    const variant = JSON.parse(raw)
    const vgot = computeExternalActionRefV1(toApiInput(variant))
    if (vgot !== vec.expected) {
      failures.push(`${vec.id}: key-order variant ${i} hash mismatch\n  expected: ${vec.expected}\n  computed: ${vgot}\n  variant: ${raw}`)
      ok = false
    }
  }
  if (ok) accepted += 1
}

const total = suite.vectors.length
// Surface the conformance verification_mode tally (enforced vs asserted).
// Default to enforced when a vector omits the field (backward compatible).
const modeCounts = suite.vectors.reduce((acc, v) => {
  const m = v.verification_mode ?? 'enforced'
  acc[m] = (acc[m] ?? 0) + 1
  return acc
}, {})
const modeSummary = Object.entries(modeCounts).map(([m, c]) => `${m}=${c}`).join(', ')
if (failures.length > 0) {
  console.log(`FAIL: ${failures.length} failure(s) across ${total} vectors\n`)
  for (const f of failures) console.log(`- ${f}`)
  process.exit(1)
}
console.log(`PASS: ${total} vectors (${accepted} accept match the SDK implementation, ${rejected} reject correctly refused) | verification_mode: ${modeSummary}`)
