#!/usr/bin/env node
// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0
//
// Packaging acceptance check for the draft-03 authority-delegation and chain-selection
// root exports.
//
// Builds the package, packs it with `npm pack`, installs the tarball into a fresh
// throwaway project outside the repo (so Node resolves it exactly as a real consumer
// would, through the published `exports` map rather than a workspace symlink or a
// relative `src/` import), then runs an ESM script that imports every symbol this
// fix made reachable from the package root and calls each one with a real input.
// A `typeof` check proves a name is present; it does not prove the name is bound to
// the working implementation. This script proves the latter for the fix's whole
// confirmed list: two records are issued, chained, and verified for real, and the
// scope, compare, budget and schema helpers are each exercised against those records.
//
// Exits nonzero if the build fails, the pack fails, the install fails, the runner
// script fails to import any symbol, or any exercised call does not produce the
// result a correct implementation must produce.

import { execFileSync } from 'node:child_process'
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')

function run(cmd, args, opts = {}) {
  console.log(`+ ${cmd} ${args.join(' ')}`)
  return execFileSync(cmd, args, { stdio: 'inherit', cwd: repoRoot, ...opts })
}

function runCapture(cmd, args, opts = {}) {
  return execFileSync(cmd, args, { cwd: repoRoot, encoding: 'utf8', ...opts }).trim()
}

const packDir = mkdtempSync(path.join(tmpdir(), 'aps-pack-'))
const installDir = mkdtempSync(path.join(tmpdir(), 'aps-install-'))

const RUNNER_SCRIPT = `
import assert from 'node:assert/strict'
import {
  generateKeyPair,
  issueAuthorityDelegation,
  issueSubAuthorityDelegation,
  verifyAuthorityDelegationChain,
  verifyAuthorityDelegation,
  compareAuthority,
  isValidScopeGrant,
  scopeGrantCovers,
  grantsAreCanonical,
  scopeNarrows,
  InMemoryAuthorityBudgetLedger,
  isAuthorityDelegationV1,
  validateAuthorityDelegationShape,
  selectChainForAction,
  selectWithFallback,
} from 'agent-passport-system'

let printed = 0
function ok(name, condition) {
  if (!condition) {
    console.error(\`FAIL \${name}\`)
    process.exitCode = 1
    return
  }
  console.log(\`OK   \${name}\`)
  printed++
}

// Not part of the confirmed export list (the audit found no doc/d.ts promise of a root
// export for these), so they are not importable from 'agent-passport-system'. Inlined
// here as the literal values src/v2/authority-delegation/types.ts defines them to be.
const AUTHORITY_DELEGATION_RECORD_TYPE = 'aps:authority-delegation:v1'
const AUTHORITY_DELEGATION_VERSION = '1.0'
const SCOPE_PROFILE_V1 = 'aps-hierarchical-v1'
const REPUTATION_PROFILE_V1 = 'aps-score-0-100-v1'
const VALUES_PROFILE_V1 = 'aps-values-identifiers-v1'
const REVERSIBILITY_PROFILE_V1 = 'aps-tci-v1'

const rootKeys = generateKeyPair()
const childKeys = generateKeyPair()

const rootBody = {
  record_type: AUTHORITY_DELEGATION_RECORD_TYPE,
  version: AUTHORITY_DELEGATION_VERSION,
  parent_delegation_id: null,
  issuer: 'did:example:root',
  subject: 'did:example:agent-a',
  verification_method: 'did:example:root#key-1',
  issued_at: '2026-07-18T22:00:00.000Z',
  nonce: '00112233445566778899aabbccddeeff',
  authority: {
    scope: { profile: SCOPE_PROFILE_V1, grants: ['commerce:*'] },
    spend: { mode: 'bounded', unit: 'iso4217:USD:minor', per_action: '100', cumulative: '100' },
    depth: { remaining: 3 },
    time: { not_before: '2026-07-18T22:00:00.000Z', not_after: '2026-07-18T23:00:00.000Z' },
    reputation: { profile: REPUTATION_PROFILE_V1, ceiling: 80 },
    values: { profile: VALUES_PROFILE_V1, required: ['F-001', 'F-003'] },
    reversibility: { profile: REVERSIBILITY_PROFILE_V1, ceiling: 'compensable' },
  },
}

// 1. issueAuthorityDelegation: mint the root.
const root = issueAuthorityDelegation(rootBody, rootKeys.privateKey)
ok('issueAuthorityDelegation', typeof root.delegation_id === 'string' && typeof root.signature === 'string')

const childBody = {
  record_type: AUTHORITY_DELEGATION_RECORD_TYPE,
  version: AUTHORITY_DELEGATION_VERSION,
  parent_delegation_id: root.delegation_id,
  issuer: root.subject,
  subject: 'did:example:agent-b',
  verification_method: \`\${root.subject}#key-1\`,
  issued_at: '2026-07-18T22:00:01.000Z',
  nonce: '102132435465768798a9bacbdcedfe0f',
  authority: {
    scope: { profile: SCOPE_PROFILE_V1, grants: ['commerce:checkout'] },
    spend: { mode: 'bounded', unit: 'iso4217:USD:minor', per_action: '80', cumulative: '80' },
    depth: { remaining: 2 },
    time: { not_before: '2026-07-18T22:00:01.000Z', not_after: '2026-07-18T22:50:00.000Z' },
    reputation: { profile: REPUTATION_PROFILE_V1, ceiling: 70 },
    values: { profile: VALUES_PROFILE_V1, required: ['F-001', 'F-003', 'F-004'] },
    reversibility: { profile: REVERSIBILITY_PROFILE_V1, ceiling: 'tentative' },
  },
}

// 2. issueSubAuthorityDelegation: mint a child under the root.
const child = issueSubAuthorityDelegation(root, childBody, childKeys.privateKey, {
  now: root.authority.time.not_before,
  resolveVerificationKey: (_issuer, method) => (method === root.verification_method ? rootKeys.publicKey : null),
  resolveRevocation: () => 'active',
})
ok('issueSubAuthorityDelegation', typeof child.delegation_id === 'string' && child.parent_delegation_id === root.delegation_id)

const keysByMethod = new Map([
  [root.verification_method, rootKeys.publicKey],
  [child.verification_method, childKeys.publicKey],
])

// 3. verifyAuthorityDelegationChain: verify the two-record chain.
const chainResult = verifyAuthorityDelegationChain([root, child], {
  now: '2026-07-18T22:10:00.000Z',
  resolveVerificationKey: (_issuer, method) => keysByMethod.get(method) ?? null,
  trustRoot: candidate => candidate.issuer === 'did:example:root',
  resolveRevocation: () => 'active',
})
ok('verifyAuthorityDelegationChain', chainResult.state === 'valid')

// 4. verifyAuthorityDelegation: verify the root alone as a one-record chain.
const singleResult = verifyAuthorityDelegation(root, {
  now: '2026-07-18T22:10:00.000Z',
  resolveVerificationKey: (_issuer, method) => keysByMethod.get(method) ?? null,
  trustRoot: candidate => candidate.issuer === 'did:example:root',
  resolveRevocation: () => 'active',
})
ok('verifyAuthorityDelegation', singleResult.state === 'valid')

// 5. compareAuthority: the child's authority attenuates the root's — no failures.
ok('compareAuthority', compareAuthority(root.authority, child.authority).length === 0)

// 6. scope module: isValidScopeGrant, scopeGrantCovers, grantsAreCanonical, scopeNarrows.
ok('isValidScopeGrant', isValidScopeGrant('commerce:*') === true)
ok('scopeGrantCovers', scopeGrantCovers('commerce:*', 'commerce:checkout') === true)
ok('grantsAreCanonical', grantsAreCanonical(['commerce:checkout']) === true)
ok('scopeNarrows', scopeNarrows(root.authority.scope.grants, child.authority.scope.grants) === true)

// 7. budget module: InMemoryAuthorityBudgetLedger.reserve against the chain just verified.
const ledger = new InMemoryAuthorityBudgetLedger()
const reservation = ledger.reserve([root, child], 'a'.repeat(64), 'iso4217:USD:minor', '25')
ok('InMemoryAuthorityBudgetLedger', reservation.ok === true && reservation.code === 'RESERVED')

// 8. schema module: isAuthorityDelegationV1, validateAuthorityDelegationShape.
ok('isAuthorityDelegationV1', isAuthorityDelegationV1(root) === true)
ok('validateAuthorityDelegationShape', validateAuthorityDelegationShape(root).length === 0)

// 9. chain selection: draft-03 section 3.3 is a STABLE root export, so the packaging
// acceptance check exercises it through the published exports map like every other
// stable symbol above. A second, independent chain is minted so the no-union rule has
// something to refuse.
const root2Keys = generateKeyPair()
const child2Keys = generateKeyPair()
const root2 = issueAuthorityDelegation({
  ...rootBody,
  issuer: 'did:example:root-2',
  subject: 'did:example:agent-c',
  verification_method: 'did:example:root-2#key-1',
  nonce: 'ffeeddccbbaa99887766554433221100',
  authority: { ...rootBody.authority, scope: { profile: SCOPE_PROFILE_V1, grants: ['support:*'] } },
}, root2Keys.privateKey)
const child2 = issueSubAuthorityDelegation(root2, {
  ...childBody,
  parent_delegation_id: root2.delegation_id,
  issuer: root2.subject,
  subject: 'did:example:agent-d',
  verification_method: root2.subject + '#key-1',
  nonce: '0ffedcbac9a8b7968574635241302010',
  authority: { ...childBody.authority, scope: { profile: SCOPE_PROFILE_V1, grants: ['support:refund'] } },
}, child2Keys.privateKey, {
  now: root2.authority.time.not_before,
  resolveVerificationKey: (_issuer, method) => (method === root2.verification_method ? root2Keys.publicKey : null),
  resolveRevocation: () => 'active',
})

const allKeys = new Map([
  ...keysByMethod,
  [root2.verification_method, root2Keys.publicKey],
  [child2.verification_method, child2Keys.publicKey],
])
const selectionOptions = {
  now: '2026-07-18T22:10:00.000Z',
  resolveVerificationKey: (_issuer, method) => allKeys.get(method) ?? null,
  trustRoot: candidate => candidate.issuer === 'did:example:root' || candidate.issuer === 'did:example:root-2',
  resolveRevocation: () => 'active',
}
const held = [
  { chain_id: 'chain-commerce', chain: [root, child] },
  { chain_id: 'chain-support', chain: [root2, child2] },
]

// One chain is selected per action, and the result names which one.
const picked = selectChainForAction({ held, requiredGrants: ['commerce:checkout'], options: selectionOptions })
ok('selectChainForAction', picked.selected === true && picked.chain_id === 'chain-commerce')

// The MUST NOT: a grant set that only the two chains together cover is refused, not
// satisfied by unioning their scopes.
const unioned = selectChainForAction({
  held,
  requiredGrants: ['commerce:checkout', 'support:refund'],
  options: selectionOptions,
})
ok('selectChainForAction refuses a union', unioned.selected === false && unioned.chain_id === null)

// The fallback half is PROPOSED, and its refusing default reads no other held chain.
const noFallback = selectWithFallback({
  held,
  preferred_chain_id: 'chain-support',
  requiredGrants: ['commerce:checkout'],
  fallback: null,
  options: selectionOptions,
})
ok(
  'selectWithFallback refuses to switch by default',
  noFallback.selected === false && noFallback.fallback_considered === false && noFallback.evaluations.length === 1,
)

// 15 = the 11 symbols the earlier root-export fix added, plus verifyAuthorityDelegationChain,
// which was already exported and is exercised here to verify the issued chain, plus the
// three chain-selection assertions that 7.2.0 makes part of the stable root surface.
assert.equal(printed, 15, 'expected 12 earlier OK lines plus the 3 chain-selection ones')
console.log('all confirmed root exports are the working runtime implementation')
`

try {
  // Build from source so the packed tarball reflects this worktree's fix, not a
  // stale dist/ from a previous build.
  run('npm', ['run', 'build'])

  const packOutput = runCapture('npm', ['pack', '--json', '--pack-destination', packDir])
  const [packInfo] = JSON.parse(packOutput)
  const tarballPath = path.join(packDir, packInfo.filename)

  writeFileSync(path.join(installDir, 'package.json'), JSON.stringify({
    name: 'aps-root-export-acceptance-check',
    private: true,
    type: 'module',
  }, null, 2))
  run('npm', ['install', tarballPath], { cwd: installDir })

  const runnerPath = path.join(installDir, 'verify-exports.mjs')
  writeFileSync(runnerPath, RUNNER_SCRIPT)
  run(process.execPath, [runnerPath], { cwd: installDir })

  console.log('\npackaging acceptance check passed')
} finally {
  rmSync(packDir, { recursive: true, force: true })
  rmSync(installDir, { recursive: true, force: true })
}
