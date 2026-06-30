// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// Standalone conformance runner for APS Composition Check Receipt v0. Loads vectors.json,
// runs the SDK anchor verifier, and checks each hand-specified expectation. Run from repo:
//   npx tsx conformance/composition-check/v0/verify.mjs
import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { CompositionCheckV0 } from '../../../src/index.js'

const { verifyCompositionCheck } = CompositionCheckV0
const doc = JSON.parse(readFileSync(join(process.cwd(), 'conformance/composition-check/v0/vectors.json'), 'utf8'))

let pass = 0
let fail = 0
for (const v of doc.vectors) {
  const r = verifyCompositionCheck(v.input_receipt, v.verification_context)
  const errs = []
  if (r.anchor_verified !== v.expected.anchor_verified) errs.push(`anchor_verified ${r.anchor_verified} != ${v.expected.anchor_verified}`)
  for (const need of v.expected.violations_include) if (!r.violations.includes(need)) errs.push(`missing violation '${need}'`)
  if (typeof v.expected.independence_is_second_anchor === 'boolean' && r.independence_is_second_anchor !== v.expected.independence_is_second_anchor)
    errs.push(`second_anchor ${r.independence_is_second_anchor} != ${v.expected.independence_is_second_anchor}`)
  if (Object.keys(r).some((k) => /safe/i.test(k))) errs.push('output carries a /safe/ field')
  if (errs.length) {
    fail++
    console.log(`FAIL ${v.id}: ${errs.join('; ')}`)
  } else {
    pass++
    console.log(`PASS ${v.id}: ${v.scenario}`)
  }
}
console.log(`\n${pass}/${doc.vectors.length} pass, ${fail} fail`)
process.exit(fail === 0 ? 0 : 1)
