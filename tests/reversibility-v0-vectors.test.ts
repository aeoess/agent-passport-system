// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0
// Reversibility v0 profile conformance vectors: TS runner + three-language
// parity (v4 section 4). Each fixture is raw effect facts plus expected
// realized_class, enforcement_class, label, and reason code. TS, Python, and Go
// must produce byte-identical realized/enforcement/label/reason on every
// fixture. Stale/conflicted/revoked-evidence fixtures are deferred (v4 s10).
import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import { execFileSync } from 'node:child_process'
import { mkdtempSync, writeFileSync, readFileSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'
import {
  classifyV0,
  enforcementFrom,
  recomputeEffect,
  REVERSIBILITY_MAPPING_V0_ID,
  REVERSIBILITY_MAPPING_V0_DIGEST,
  type EffectFacts,
  type EffectInstantiationElement,
} from '../src/core/reversibility-fold.js'

const VECTORS_PATH = fileURLToPath(new URL('./fixtures/reversibility-v0-vectors.json', import.meta.url))
const VECTORS = JSON.parse(readFileSync(VECTORS_PATH, 'utf8')) as {
  vectors: Array<{ name: string; input: Record<string, unknown>; expected: Record<string, unknown> }>
}

function have(cmd: string, args: string[]): boolean {
  try {
    execFileSync(cmd, args, { stdio: 'ignore' })
    return true
  } catch {
    return false
  }
}

// TS classification of one fixture input, shaped exactly like the expected value.
function tsClassify(input: Record<string, unknown>): Record<string, unknown> {
  const pid = input.classification_profile_id
  if (pid !== undefined && pid !== REVERSIBILITY_MAPPING_V0_ID) {
    // A registry concern; recompute over an element carrying the unknown id.
    const el: EffectInstantiationElement = {
      effect_scope: 'internal',
      effect_target_ref: 'urn:t',
      finality_state: 'pending',
      recovery_mechanism_ref: null,
      recovery_controller: null,
      recovery_deadline: null,
      evidence_status: 'resolved',
      classification_profile_id: String(pid),
      classification_profile_digest: REVERSIBILITY_MAPPING_V0_DIGEST,
      action_ref: 'a',
      action_instance_id: 'i',
      effect_id: 'e',
      predecessor_effect_state_hash: null,
      sequence: 0,
    }
    const out = recomputeEffect(el)
    return { failure: out.status === 'unknown_profile' ? 'unknown_profile' : out.status }
  }
  const facts: EffectFacts = {
    externality: input.externality as EffectFacts['externality'],
    recoveryMechanismRef: (input.recovery_mechanism_ref ?? undefined) as string | null | undefined,
    finalityState: input.finality_state as EffectFacts['finalityState'],
    targetBindingVerified: input.target_binding_verified as boolean | undefined,
  }
  const r = classifyV0(facts)
  const shaped: Record<string, unknown> = { realized: r.realized, enforcement: enforcementFrom(r.realized), reason: r.reason }
  if (r.label !== undefined) shaped.label = r.label
  return shaped
}

describe('reversibility v0 vectors - TS conformance runner (v4 s4)', () => {
  for (const v of VECTORS.vectors) {
    it(`TS matches expected for ${v.name}`, () => {
      assert.deepEqual(tsClassify(v.input), v.expected)
    })
  }
})

// A self-contained reference classifier of the v0 rules, in Python and Go. It
// consumes the vectors and emits the result vector; parity holds when its output
// equals the expected values (hence equals the TS output) on every fixture.
const PY_REF = `
import sys, json
KNOWN = "reversibility-mapping-v0"
def classify(inp):
    pid = inp.get("classification_profile_id")
    if pid is not None and pid != KNOWN:
        return {"failure": "unknown_profile"}
    ext = inp.get("externality")
    label = None
    if ext is None:
        realized, reason = "unresolved", "RM_V0_UNBOUND"
    elif ext in ("external-irreversible", "external-reversible"):
        definitive = inp.get("finality_state") == "settled" and inp.get("target_binding_verified") is True
        if definitive:
            realized, reason = "irreversible", "RM_V0_EXTERNAL_DEFINITIVE"
        else:
            realized, reason, label = "irreversible", "RM_V0_EXTERNAL_UPPER_BOUND", "upper_bound"
    elif ext == "internal":
        rec = inp.get("recovery_mechanism_ref")
        if rec is not None and rec != "":
            realized, reason = "compensable", "RM_V0_INTERNAL_RECOVERABLE"
        else:
            realized, reason = "irreversible", "RM_V0_INTERNAL_NO_RECOVERY"
    else:
        realized, reason = "unresolved", "RM_V0_UNBOUND"
    enforcement = "irreversible" if realized == "unresolved" else realized
    out = {"realized": realized, "enforcement": enforcement, "reason": reason}
    if label is not None:
        out["label"] = label
    return out
data = json.load(open(sys.argv[1]))
print(json.dumps([classify(v["input"]) for v in data["vectors"]]))
`

const GO_REF = `package main
import ( "encoding/json"; "fmt"; "os" )
const known = "reversibility-mapping-v0"
func classify(inp map[string]interface{}) map[string]interface{} {
  if pid, ok := inp["classification_profile_id"]; ok && pid != known {
    return map[string]interface{}{"failure": "unknown_profile"}
  }
  ext, hasExt := inp["externality"]
  var realized, reason, label string
  if !hasExt {
    realized, reason = "unresolved", "RM_V0_UNBOUND"
  } else if ext == "external-irreversible" || ext == "external-reversible" {
    definitive := inp["finality_state"] == "settled" && inp["target_binding_verified"] == true
    if definitive {
      realized, reason = "irreversible", "RM_V0_EXTERNAL_DEFINITIVE"
    } else {
      realized, reason, label = "irreversible", "RM_V0_EXTERNAL_UPPER_BOUND", "upper_bound"
    }
  } else if ext == "internal" {
    rec, ok := inp["recovery_mechanism_ref"]
    if ok && rec != nil && rec != "" {
      realized, reason = "compensable", "RM_V0_INTERNAL_RECOVERABLE"
    } else {
      realized, reason = "irreversible", "RM_V0_INTERNAL_NO_RECOVERY"
    }
  } else {
    realized, reason = "unresolved", "RM_V0_UNBOUND"
  }
  enforcement := realized
  if realized == "unresolved" { enforcement = "irreversible" }
  out := map[string]interface{}{"realized": realized, "enforcement": enforcement, "reason": reason}
  if label != "" { out["label"] = label }
  return out
}
func main() {
  b, _ := os.ReadFile(os.Args[1])
  var data struct{ Vectors []struct{ Input map[string]interface{} } }
  json.Unmarshal(b, &data)
  results := make([]map[string]interface{}, 0, len(data.Vectors))
  for _, v := range data.Vectors { results = append(results, classify(v.Input)) }
  o, _ := json.Marshal(results)
  fmt.Println(string(o))
}
`

describe('reversibility v0 vectors - three-language parity (v4 s4)', () => {
  it('Python reference matches expected on every fixture (or skips if absent)', (t) => {
    if (!have('python3', ['--version'])) return t.skip('python3 is not available')
    const dir = mkdtempSync(join(tmpdir(), 'rvvec-py-'))
    try {
      writeFileSync(join(dir, 'ref.py'), PY_REF)
      const out = execFileSync('python3', [join(dir, 'ref.py'), VECTORS_PATH], { encoding: 'utf8' })
      const results = JSON.parse(out) as Array<Record<string, unknown>>
      assert.equal(results.length, VECTORS.vectors.length)
      VECTORS.vectors.forEach((v, i) => assert.deepEqual(results[i], v.expected, v.name))
    } finally {
      rmSync(dir, { recursive: true, force: true })
    }
  })

  it('Go reference matches expected on every fixture (or skips if absent)', (t) => {
    if (!have('go', ['version'])) return t.skip('go is not available')
    const dir = mkdtempSync(join(tmpdir(), 'rvvec-go-'))
    try {
      writeFileSync(join(dir, 'main.go'), GO_REF)
      writeFileSync(join(dir, 'go.mod'), 'module rvvec\ngo 1.22\n')
      const out = execFileSync('go', ['run', '.', VECTORS_PATH], { cwd: dir, encoding: 'utf8' })
      const results = JSON.parse(out) as Array<Record<string, unknown>>
      assert.equal(results.length, VECTORS.vectors.length)
      VECTORS.vectors.forEach((v, i) => assert.deepEqual(results[i], v.expected, v.name))
    } finally {
      rmSync(dir, { recursive: true, force: true })
    }
  })
})
