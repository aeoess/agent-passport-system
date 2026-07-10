// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0
// Evidence bundle (F5) + claim-boundary report (F6, SCHEMAS-DRAFT 3d)
// + CLI verify-bundle exit codes and JSON shape.
//
// NOTE (F8): registering this file in the package.json test script is
// a single-writer T9 item. Until then run it directly:
//   npx tsx --test tests/evidence-bundle.test.ts

import { test } from 'node:test'
import assert from 'node:assert'
import { spawnSync } from 'node:child_process'
import { mkdtempSync, writeFileSync, readFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'

import { generateKeyPair } from '../src/crypto/keys.js'
import { createPassport } from '../src/core/passport.js'
import {
  createEvidenceBundle, verifyEvidenceBundle,
  proveMemberInclusion, verifyMemberInclusion,
  computeClaimBoundaryReport, computeMemberDigest,
} from '../src/core/evidence-bundle.js'
import type { EvidenceBundle, EvidenceBundleMember } from '../src/types/evidence-bundle.js'

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..')
const FIXTURES = join(ROOT, 'tests', 'fixtures', 'evidence-bundle')
const NOW = new Date('2026-07-10T12:00:00Z')

const signer = generateKeyPair()

function makeBundle(members: EvidenceBundleMember[]): EvidenceBundle {
  return createEvidenceBundle({
    members,
    signerPrivateKey: signer.privateKey,
    signerPublicKey: signer.publicKey,
    createdAt: '2026-07-10T00:00:00Z',
  })
}

function runCli(cliArgs: string[]): { status: number | null, stdout: string, stderr: string } {
  const res = spawnSync('npx', ['tsx', join('src', 'cli', 'index.ts'), 'verify-bundle', ...cliArgs], {
    cwd: ROOT, encoding: 'utf8',
  })
  return { status: res.status, stdout: res.stdout, stderr: res.stderr }
}

// ── Bundle create + verify ──

test('createEvidenceBundle: manifest carries the frozen F5 field set and nothing else', () => {
  const bundle = makeBundle([{ member_id: 'a', member_type: 'other', payload: { x: 1 } }])
  assert.deepStrictEqual(
    Object.keys(bundle.manifest).sort(),
    ['created_at', 'members', 'merkle_root', 'profile', 'signature'],
  )
  assert.strictEqual(bundle.manifest.profile, 'aps:evidence-bundle:v1')
})

test('verifyEvidenceBundle: roundtrip on a multi-member bundle passes every check', () => {
  const bundle = makeBundle([
    { member_id: 'a', member_type: 'other', payload: { x: 1 } },
    { member_id: 'b', member_type: 'other', payload: { y: [1, 2, 3] } },
    { member_id: 'c', member_type: 'other', payload: 'plain string payload' },
  ])
  const v = verifyEvidenceBundle(bundle)
  assert.strictEqual(v.valid, true, v.errors.join('; '))
  assert.strictEqual(v.signatureValid, true)
  assert.strictEqual(v.rootValid, true)
  assert.ok(v.memberResults.every(r => r.digestValid && r.inclusionValid))
})

test('verifyEvidenceBundle: single-member bundle verifies (digest is the root)', () => {
  const bundle = makeBundle([{ member_id: 'only', member_type: 'other', payload: { z: true } }])
  assert.strictEqual(bundle.manifest.merkle_root, computeMemberDigest({ z: true }))
  const v = verifyEvidenceBundle(bundle)
  assert.strictEqual(v.valid, true, v.errors.join('; '))
})

test('verifyEvidenceBundle: tampered member payload fails its digest, root and signature stay valid', () => {
  const bundle = makeBundle([
    { member_id: 'a', member_type: 'other', payload: { x: 1 } },
    { member_id: 'b', member_type: 'other', payload: { y: 2 } },
  ])
  ;(bundle.members[1].payload as { y: number }).y = 999
  const v = verifyEvidenceBundle(bundle)
  assert.strictEqual(v.valid, false)
  assert.strictEqual(v.signatureValid, true)
  assert.strictEqual(v.rootValid, true)
  assert.strictEqual(v.memberResults.find(r => r.member_id === 'b')?.digestValid, false)
  assert.strictEqual(v.memberResults.find(r => r.member_id === 'a')?.digestValid, true)
})

test('verifyEvidenceBundle: tampered manifest field fails the signature', () => {
  const bundle = makeBundle([{ member_id: 'a', member_type: 'other', payload: { x: 1 } }])
  bundle.manifest.created_at = '2027-01-01T00:00:00Z'
  const v = verifyEvidenceBundle(bundle)
  assert.strictEqual(v.signatureValid, false)
  assert.strictEqual(v.valid, false)
})

test('inclusion proofs via the receipt-ledger primitives verify per member', () => {
  const bundle = makeBundle([
    { member_id: 'a', member_type: 'other', payload: { x: 1 } },
    { member_id: 'b', member_type: 'other', payload: { y: 2 } },
    { member_id: 'c', member_type: 'other', payload: { z: 3 } },
  ])
  for (const id of ['a', 'b', 'c']) {
    const proof = proveMemberInclusion(bundle.manifest, id)
    assert.strictEqual(verifyMemberInclusion(proof), true, `inclusion failed for ${id}`)
    assert.strictEqual(proof.merkleRoot, bundle.manifest.merkle_root)
  }
  assert.throws(() => proveMemberInclusion(bundle.manifest, 'nope'), /unknown member_id/)
})

// ── Claim-boundary report: axis mapping (SCHEMAS-DRAFT 3d) ──

test('empty axes report MISSING: no authority member, no action data, no revocation observation', () => {
  const bundle = makeBundle([{ member_id: 'n', member_type: 'other', payload: { note: 'x' } }])
  const report = computeClaimBoundaryReport(bundle, { now: NOW })
  assert.strictEqual(report.axes.authority.state, 'MISSING')
  assert.strictEqual(report.axes.action.state, 'MISSING')
  assert.strictEqual(report.axes.revocation.state, 'MISSING')
  assert.strictEqual(report.axes.evidence.state, 'EVALUATED')
})

test('authority: valid self-signed passport reports ASSERTED, garbage passport member reports UNKNOWN', () => {
  const { signedPassport } = createPassport({
    agentId: 't', agentName: 't', ownerAlias: 't', mission: 't',
    capabilities: ['code_execution'], runtime: { platform: 'node', models: ['x'] },
    validityWindow: { notAfter: '2036-01-01T00:00:00.000Z' },
  })
  const asserted = computeClaimBoundaryReport(
    makeBundle([{ member_id: 'p', member_type: 'passport', payload: signedPassport }]), { now: NOW })
  assert.strictEqual(asserted.axes.authority.state, 'ASSERTED')

  const unknown = computeClaimBoundaryReport(
    makeBundle([{ member_id: 'p', member_type: 'passport', payload: { not: 'a passport' } }]), { now: NOW })
  assert.strictEqual(unknown.axes.authority.state, 'UNKNOWN')
})

test('authority: passport with a broken signature reports INVALID', () => {
  const { signedPassport } = createPassport({
    agentId: 't', agentName: 't', ownerAlias: 't', mission: 't',
    capabilities: ['code_execution'], runtime: { platform: 'node', models: ['x'] },
    validityWindow: { notAfter: '2036-01-01T00:00:00.000Z' },
  })
  const broken = { ...signedPassport, signature: 'f'.repeat(128) }
  const report = computeClaimBoundaryReport(
    makeBundle([{ member_id: 'p', member_type: 'passport', payload: broken }]), { now: NOW })
  assert.strictEqual(report.axes.authority.state, 'INVALID')
})

test('action: matching refs VERIFIED, conflicting refs INVALID, lone ref UNKNOWN', () => {
  const receipt = (id: string, ref: string) => ({
    member_id: id, member_type: 'bilateral_receipt' as const,
    payload: { receiptId: id, requestingAgentId: 'a', servingAgentId: 'b', action_ref: ref },
  })
  const match = computeClaimBoundaryReport(makeBundle([receipt('r1', 'a'.repeat(64)), receipt('r2', 'a'.repeat(64))]), { now: NOW })
  assert.strictEqual(match.axes.action.state, 'VERIFIED')
  const clash = computeClaimBoundaryReport(makeBundle([receipt('r1', 'a'.repeat(64)), receipt('r2', 'b'.repeat(64))]), { now: NOW })
  assert.strictEqual(clash.axes.action.state, 'INVALID')
  const lone = computeClaimBoundaryReport(makeBundle([receipt('r1', 'a'.repeat(64))]), { now: NOW })
  assert.strictEqual(lone.axes.action.state, 'UNKNOWN')
})

test('action: pair verdict statuses map to RESOLVED / ASSERTED / INVALID', () => {
  const verdict = (status: string) => makeBundle([
    { member_id: 'v', member_type: 'bilateral_pair_verdict', payload: { status } },
  ])
  assert.strictEqual(computeClaimBoundaryReport(verdict('reconciled'), { now: NOW }).axes.action.state, 'RESOLVED')
  assert.strictEqual(computeClaimBoundaryReport(verdict('unilateral'), { now: NOW }).axes.action.state, 'ASSERTED')
  assert.strictEqual(computeClaimBoundaryReport(verdict('mismatch'), { now: NOW }).axes.action.state, 'INVALID')
})

test('revocation: observation states map per the 3d row, nothing is hardcoded', () => {
  const obs = (payload: Record<string, unknown>) => makeBundle([
    { member_id: 'o', member_type: 'revocation_observation', payload },
  ])
  const base = {
    authority_ref: 'del-1',
    status_source: { kind: 'source', id: 's1' },
    observed_at: '2026-07-10T11:59:00Z',
    maximum_staleness_ms: 300_000,
  }
  const rep = (p: Record<string, unknown>) => computeClaimBoundaryReport(obs(p), { now: NOW }).axes.revocation

  assert.strictEqual(rep({ ...base, revoked_at: '2026-07-10T11:58:00Z', decision: { effect: 'deny' } }).state, 'RESOLVED')
  assert.strictEqual(rep({ ...base, revoked_at: '2026-07-10T11:58:00Z', decision: { effect: 'allow' } }).state, 'INVALID')
  assert.strictEqual(rep({ ...base, revoked_at: '2026-07-10T11:58:00Z', decision: { effect: 'allow' }, workflow_response: { reissued: false, reason: 'revoked' } }).state, 'RESOLVED')
  // An allow decision is EVALUATED, not VERIFIED: the frozen F4 record does not
  // carry the freshness result, so a consulted-and-fresh source and an
  // unavailable source that failed open (decideFreshness fail_open, effect
  // allow, downgraded false) are indistinguishable. Reporting VERIFIED here was
  // a fail-open (audit 2026-07-10, evidence-bundle revocation axis).
  assert.strictEqual(rep({ ...base, decision: { effect: 'allow' } }).state, 'EVALUATED')
  assert.strictEqual(rep({ ...base, decision: { effect: 'allow', downgraded: true } }).state, 'EVALUATED')
  assert.strictEqual(rep({ ...base, observed_at: '2026-07-10T00:00:00Z', decision: { effect: 'allow' } }).state, 'STALE')
  // RefreshOutcome carries no `result`/`status`; a workflow_response with such a
  // field is ignored, so this is an ordinary allow decision -> EVALUATED.
  assert.strictEqual(rep({ ...base, decision: { effect: 'allow' }, workflow_response: { result: 'unavailable' } }).state, 'EVALUATED')
  assert.strictEqual(rep({ authority_ref: 'del-1', decision: { effect: 'allow' } }).state, 'INVALID')
})

test('evidence: tampered member turns the evidence axis INVALID and overall INVALID', () => {
  const bundle = makeBundle([
    { member_id: 'a', member_type: 'other', payload: { x: 1 } },
    { member_id: 'b', member_type: 'other', payload: { y: 2 } },
  ])
  ;(bundle.members[0].payload as { x: number }).x = 2
  const report = computeClaimBoundaryReport(bundle, { now: NOW })
  assert.strictEqual(report.axes.evidence.state, 'INVALID')
  assert.strictEqual(report.overall, 'INVALID')
})

// ── CLI: fixtures, exit codes, JSON shape ──

test('CLI: valid fixture exits 0 and the JSON object has the stable shape', () => {
  const res = runCli([join(FIXTURES, 'valid', 'bundle.json'), '--json'])
  assert.strictEqual(res.status, 0, res.stderr)
  const parsed = JSON.parse(res.stdout)
  assert.deepStrictEqual(Object.keys(parsed).sort(), ['axes', 'exit_reason', 'overall'])
  assert.deepStrictEqual(Object.keys(parsed.axes).sort(), ['action', 'authority', 'evidence', 'revocation'])
  assert.deepStrictEqual(parsed.axes, {
    authority: 'ASSERTED', action: 'VERIFIED', revocation: 'MISSING', evidence: 'EVALUATED',
  })
  assert.strictEqual(parsed.overall, 'MISSING')
  assert.strictEqual(parsed.exit_reason, 'ok')
})

test('CLI: tampered-member fixture exits 2 with evidence INVALID', () => {
  const res = runCli([join(FIXTURES, 'tampered-member', 'bundle.json'), '--json'])
  assert.strictEqual(res.status, 2)
  const parsed = JSON.parse(res.stdout)
  assert.strictEqual(parsed.axes.evidence, 'INVALID')
  assert.strictEqual(parsed.exit_reason, 'axis_invalid')
})

test('CLI: --strict turns MISSING authority into exit 2; without it exit 0', () => {
  const dir = mkdtempSync(join(tmpdir(), 't8-bundle-'))
  const bundle = makeBundle([{ member_id: 'n', member_type: 'other', payload: { note: 'no authority member' } }])
  const file = join(dir, 'bundle.json')
  writeFileSync(file, JSON.stringify(bundle))
  const loose = runCli([file, '--json'])
  assert.strictEqual(loose.status, 0, loose.stderr)
  const strict = runCli([file, '--json', '--strict'])
  assert.strictEqual(strict.status, 2)
  assert.strictEqual(JSON.parse(strict.stdout).exit_reason, 'strict_missing')
})

test('CLI: unreadable file and failed manifest signature both exit 3', () => {
  const unreadable = runCli(['/definitely/not/a/file.json', '--json'])
  assert.strictEqual(unreadable.status, 3)
  assert.strictEqual(JSON.parse(unreadable.stdout).exit_reason, 'bundle_unreadable')

  const dir = mkdtempSync(join(tmpdir(), 't8-badsig-'))
  const bundle: EvidenceBundle = JSON.parse(readFileSync(join(FIXTURES, 'valid', 'bundle.json'), 'utf8'))
  bundle.manifest.created_at = '2030-01-01T00:00:00Z'
  const file = join(dir, 'bundle.json')
  writeFileSync(file, JSON.stringify(bundle))
  const badsig = runCli([file, '--json'])
  assert.strictEqual(badsig.status, 3)
  assert.strictEqual(JSON.parse(badsig.stdout).exit_reason, 'manifest_signature_failed')
})
