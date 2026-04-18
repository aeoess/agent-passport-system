// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// AgentNexus Track A fixture round-trip verifier.
// Loads the two fixtures contributed by kevinkaylie in PR #17, re-canonicalizes
// each token with our JCS implementation, verifies the declared Ed25519
// signatures, walks the delegation chain, and evaluates monotonic narrowing.
// Outputs a machine-readable JSON report on stdout and exits non-zero on any
// expectation mismatch (for CI use). A human-readable markdown report is
// produced by the companion invocation path.

import { readFileSync, statSync } from 'node:fs'
import { createPublicKey, verify as nodeVerify } from 'node:crypto'
import { canonicalizeJCS } from '../src/core/canonical-jcs.js'

type CheckStatus = 'pass' | 'fail' | 'n/a'

interface CheckResult {
  name: string
  status: CheckStatus
  detail?: string
}

interface FixtureReport {
  fixture: string
  bytes: number
  parent_token_id: string
  child_token_id: string
  canonicalization_parent_matches: boolean
  canonicalization_child_matches: boolean
  canonicalization_parent_diff?: { expected: string; actual: string }
  canonicalization_child_diff?: { expected: string; actual: string }
  checks: CheckResult[]
  expected_valid: boolean
  observed_valid: boolean
  pass: boolean
}

const ED25519_DER_PREFIX = Buffer.from('302a300506032b6570032100', 'hex')

function b64urlToBytes(s: string): Buffer {
  const pad = s.length % 4 === 0 ? '' : '='.repeat(4 - (s.length % 4))
  const b64 = s.replace(/-/g, '+').replace(/_/g, '/') + pad
  return Buffer.from(b64, 'base64')
}

function verifyEd25519(canonical: string, signatureB64Url: string, publicKeyHex: string): boolean {
  try {
    const pub = Buffer.from(publicKeyHex, 'hex')
    if (pub.length !== 32) return false
    const der = Buffer.concat([ED25519_DER_PREFIX, pub])
    const key = createPublicKey({ key: der, format: 'der', type: 'spki' })
    const sig = b64urlToBytes(signatureB64Url)
    if (sig.length !== 64) return false
    return nodeVerify(null, Buffer.from(canonical, 'utf8'), key, sig)
  } catch {
    return false
  }
}

function isScopeSubset(
  child: { permissions: string[]; resource_pattern: string; role: string },
  parent: { permissions: string[]; resource_pattern: string; role: string },
): { subset: boolean; reason?: string } {
  const parentPerms = new Set(parent.permissions)
  for (const p of child.permissions) {
    if (!parentPerms.has(p)) {
      return { subset: false, reason: `permission "${p}" not in parent [${parent.permissions.join(', ')}]` }
    }
  }
  return { subset: true }
}

function isConstraintNarrowed(
  child: { spend_limit: number; max_delegation_depth: number },
  parent: { spend_limit: number; max_delegation_depth: number },
): { ok: boolean; reason?: string } {
  if (child.spend_limit > parent.spend_limit) {
    return { ok: false, reason: `spend_limit ${child.spend_limit} > parent ${parent.spend_limit}` }
  }
  if (child.max_delegation_depth > parent.max_delegation_depth) {
    return { ok: false, reason: `max_delegation_depth ${child.max_delegation_depth} > parent ${parent.max_delegation_depth}` }
  }
  return { ok: true }
}

function evaluateFixture(path: string): FixtureReport {
  const raw = readFileSync(path, 'utf8')
  const bytes = statSync(path).size
  const fx = JSON.parse(raw)

  const parentObj = fx.objects.parent_token
  const childObj = fx.objects.child_token
  const parentCanon = fx.canonicalized.parent_token
  const childCanon = fx.canonicalized.child_token
  const principalPub = fx.keys.principal.public_key
  const agentPub = fx.keys.agent.public_key
  const expected = fx.expected

  // 1. Re-canonicalize the `input` halves and compare byte-for-byte.
  const actualParentCanonical = canonicalizeJCS(parentCanon.input)
  const actualChildCanonical = canonicalizeJCS(childCanon.input)
  const parentCanonMatch = actualParentCanonical === parentCanon.canonical_string
  const childCanonMatch = actualChildCanonical === childCanon.canonical_string

  // 2. Verify Ed25519 signatures against the declared canonical string.
  const parentSigOk = verifyEd25519(parentCanon.canonical_string, parentObj.signature, principalPub)
  const childSigOk = verifyEd25519(childCanon.canonical_string, childObj.signature, agentPub)

  // 3. Status.
  const parentActive = parentObj.status === 'active'
  const childActive = childObj.status === 'active'

  // 4. Validity window. Evaluated at the child's not_before — this is the
  //    moment at which the delegation was issued and so must fall inside
  //    both windows by construction. Real deployments check now().
  const checkAt = childObj.validity.not_before
  const inWindow = (v: { not_before: number; not_after: number }) =>
    checkAt >= v.not_before && checkAt <= v.not_after
  const parentInWindow = inWindow(parentObj.validity)
  const childInWindow = inWindow(childObj.validity)

  // 5. Chain completeness. Happy-path declares parent_token_id on the child.
  //    For scope-expansion we infer linkage from shared enclave_id + issuer.
  const declaredChain: Array<{ token_id: string; parent_token_id?: string }> = fx.delegation_chain ?? []
  const childLinked = declaredChain.length > 0
    ? declaredChain.some(e => e.token_id === childObj.token_id && e.parent_token_id === parentObj.token_id)
    : childObj.enclave_id === parentObj.enclave_id && childObj.issuer_did === parentObj.issuer_did

  // 6. Scope subset + constraint narrowing.
  const scopeCheck = isScopeSubset(childObj.scope, parentObj.scope)
  const constraintCheck = isConstraintNarrowed(childObj.constraints, parentObj.constraints)
  const narrowingOk = scopeCheck.subset && constraintCheck.ok

  const checks: CheckResult[] = [
    {
      name: 'canonicalization',
      status: (parentCanonMatch && childCanonMatch) ? 'pass' : 'fail',
      detail: (parentCanonMatch && childCanonMatch)
        ? 'JCS re-canonicalization matches fixture canonical_string for both tokens'
        : `parent_match=${parentCanonMatch}, child_match=${childCanonMatch}`,
    },
    {
      name: 'signature',
      status: (parentSigOk && childSigOk) ? 'pass' : 'fail',
      detail: `parent=${parentSigOk ? 'verified' : 'FAIL'}, child=${childSigOk ? 'verified' : 'FAIL'}`,
    },
    {
      name: 'validity',
      status: (parentInWindow && childInWindow) ? 'pass' : 'fail',
      detail: `evaluated at child.not_before; parent=${parentInWindow ? 'in_window' : 'OUT'}, child=${childInWindow ? 'in_window' : 'OUT'}`,
    },
    {
      name: 'chain',
      status: childLinked ? 'pass' : 'fail',
      detail: childLinked
        ? 'child references parent (or shares enclave+issuer)'
        : 'no parent linkage',
    },
    {
      name: 'scope_is_subset',
      status: narrowingOk ? 'pass' : 'fail',
      detail: narrowingOk
        ? 'child scope ⊆ parent, spend_limit and max_delegation_depth narrowed'
        : [scopeCheck.reason, constraintCheck.reason].filter(Boolean).join('; '),
    },
    {
      name: 'status',
      status: (parentActive && childActive) ? 'pass' : 'fail',
      detail: `parent=${parentObj.status}, child=${childObj.status}`,
    },
  ]

  // Observed validity = APS permission decision for the child token.
  // Require: canonicalization, signatures, validity, chain, scope subset, status.
  const observedValid =
    parentCanonMatch && childCanonMatch &&
    parentSigOk && childSigOk &&
    parentInWindow && childInWindow &&
    childLinked &&
    narrowingOk &&
    parentActive && childActive

  const expectedValid = !!(fx.verification_results?.child_token?.valid)
  const passed = observedValid === expectedValid

  const report: FixtureReport = {
    fixture: path.split('/').pop() ?? path,
    bytes,
    parent_token_id: parentObj.token_id,
    child_token_id: childObj.token_id,
    canonicalization_parent_matches: parentCanonMatch,
    canonicalization_child_matches: childCanonMatch,
    checks,
    expected_valid: expectedValid,
    observed_valid: observedValid,
    pass: passed,
  }
  if (!parentCanonMatch) {
    report.canonicalization_parent_diff = {
      expected: parentCanon.canonical_string,
      actual: actualParentCanonical,
    }
  }
  if (!childCanonMatch) {
    report.canonicalization_child_diff = {
      expected: childCanon.canonical_string,
      actual: actualChildCanonical,
    }
  }
  return report
}

const fixtures = [
  new URL('./fixtures/agentnexus/happy-path.json', import.meta.url).pathname,
  new URL('./fixtures/agentnexus/scope-expansion.json', import.meta.url).pathname,
]

const reports = fixtures.map(evaluateFixture)
const allPass = reports.every(r => r.pass)

console.log(JSON.stringify({ all_pass: allPass, reports }, null, 2))
process.exit(allPass ? 0 : 1)
