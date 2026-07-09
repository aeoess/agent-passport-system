// Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// Conformance runner for the APS Regulated Action Profile v0 vectors, against the BUILT SDK.
// Build first (npm run build), then: node conformance/regulated-action/v0/verify.mjs
import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { dirname, join } from 'node:path'
import { RegulatedActionV0 } from '../../../dist/src/index.js'

const here = dirname(fileURLToPath(import.meta.url))
const doc = JSON.parse(readFileSync(join(here, 'vectors.json'), 'utf8'))

let pass = 0
let fail = 0
for (const v of doc.vectors) {
  if (v.surface !== 'verifier') continue
  const r = RegulatedActionV0.verifyRegulatedAction(v.input_receipt, v.verification_context)
  const ok =
    r.disposition === v.expected.disposition &&
    (!v.expected.incomplete_reason || r.incomplete_reason === v.expected.incomplete_reason) &&
    (!v.expected.authority_basis || r.authority_basis === v.expected.authority_basis) &&
    r.judgment_correctness === 'not_claimed'
  if (ok) {
    pass++
  } else {
    fail++
    console.error(`FAIL ${v.id}: got ${r.disposition}:${r.incomplete_reason ?? '-'} basis=${r.authority_basis ?? '-'} want ${v.expected.disposition}:${v.expected.incomplete_reason ?? '-'} basis=${v.expected.authority_basis ?? '-'}`)
  }
}
const completeness = doc.vectors.filter((v) => v.surface === 'completeness').length
console.log(`verify.mjs: ${pass}/${pass + fail} verifier vectors pass. ${completeness} completeness-surface vectors (V20/V21) are validated by the private gateway completeness layer.`)
process.exit(fail ? 1 : 0)
