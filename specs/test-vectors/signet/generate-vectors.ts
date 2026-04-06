/**
 * Generate Signet interop test vectors from real APS delegation data.
 * Run: npx tsx specs/test-vectors/signet/generate-vectors.ts
 */

import { writeFileSync } from 'fs'
import { createHash } from 'crypto'
import {
  generateKeyPair,
  createDelegation,
  verifyDelegation,
  canonicalize,
} from '../../../src/index.js'

const principalKeys = generateKeyPair()
const agentKeys = generateKeyPair()

const delegation = createDelegation({
  delegatedTo: agentKeys.publicKey,
  delegatedBy: principalKeys.publicKey,
  scope: ['tools:readFile', 'tools:writeFile'],
  privateKey: principalKeys.privateKey,
  spendLimit: 0,
})

function sha256(data: string): string {
  return createHash('sha256').update(data).digest('hex')
}

const delegationHash = `sha256:${sha256(canonicalize(delegation))}`

const dir = new URL('./', import.meta.url).pathname

// ── Vector 1: Issuance ──

const vector1 = {
  id: 'signet-aps-v1-issuance',
  title: 'Issuance: Signet link containing APS delegation',
  description: 'Create a combined credential. Verify from both APS and Signet sides.',
  signet_link: {
    linkId: 'signet-link-001',
    chain: 'signet-chain-abc',
    status: 'active',
    created_at: new Date().toISOString(),
    metadata: {
      aps_delegation: {
        delegationId: delegation.delegationId,
        delegatedTo: delegation.delegatedTo,
        delegatedBy: delegation.delegatedBy,
        scope: delegation.scope,
        spendLimit: delegation.spendLimit,
        expiresAt: delegation.expiresAt,
        maxDepth: delegation.maxDepth,
        currentDepth: delegation.currentDepth,
        createdAt: delegation.createdAt,
        signature: delegation.signature,
      },
      aps_delegation_hash: delegationHash,
    },
  },
  verification: {
    aps_only: {
      steps: [
        'Extract metadata.aps_delegation',
        'Verify Ed25519 signature against delegatedBy public key',
        'Check scope covers requested action',
        'Check expiresAt is in the future',
      ],
      expected: { valid: true },
      principal_public_key: principalKeys.publicKey,
    },
    signet_only: {
      steps: [
        'Verify chain integrity (Signet verification)',
        'Check link status is active',
      ],
      expected: { status: 'active' },
    },
    full: {
      steps: [
        'Signet verifies chain integrity',
        'APS verifies delegation signature',
        'Cross-check: aps_delegation_hash matches sha256(canonicalize(aps_delegation))',
      ],
      expected: { valid: true, hash_matches: true },
    },
  },
}

writeFileSync(`${dir}vector-1-issuance.json`, JSON.stringify(vector1, null, 2) + '\n')

// ── Vector 2: Presentation ──

const vector2 = {
  id: 'signet-aps-v2-presentation',
  title: 'Presentation: APS-only service verifies combined credential',
  description: 'Agent presents Signet link to an APS-only service. Service extracts and verifies delegation, ignores Signet wrapper.',
  input: {
    presented_credential: vector1.signet_link,
    requested_action: {
      tool: 'readFile',
      scope_required: 'tools:readFile',
    },
  },
  aps_verification: {
    delegation_extracted: {
      delegationId: delegation.delegationId,
      delegatedTo: delegation.delegatedTo,
      scope: delegation.scope,
    },
    signature_valid: true,
    scope_covers_action: true,
    expiry_valid: true,
    signet_wrapper_acknowledged: true,
    signet_wrapper_verified: false,
  },
  expected: {
    access_granted: true,
    reason: 'Delegation valid, scope tools:readFile covered, not expired',
  },
}

writeFileSync(`${dir}vector-2-presentation.json`, JSON.stringify(vector2, null, 2) + '\n')

// ── Vector 3: Revocation ──

const vector3 = {
  id: 'signet-aps-v3-revocation',
  title: 'Revocation: Signet revokes link, APS-only service rejects',
  description: 'Signet revokes the chain link. An APS-only service that cached the delegation queries the Signet status endpoint and rejects the credential.',
  sequence: [
    {
      step: 1,
      action: 'Initial state: link active, delegation valid',
      signet_link_status: 'active',
      aps_delegation_valid: true,
      access_decision: 'granted',
    },
    {
      step: 2,
      action: 'Signet revokes the chain link',
      signet_link_status: 'revoked',
      revoked_at: new Date().toISOString(),
      aps_delegation_valid: true,
      note: 'APS delegation signature still verifies, but Signet link is revoked',
    },
    {
      step: 3,
      action: 'APS-only service queries Signet status endpoint',
      cross_protocol_call: {
        method: 'GET',
        url: '/chain/signet-chain-abc/link/signet-link-001/status',
        response: { status: 'revoked', revokedAt: new Date().toISOString() },
      },
      access_decision: 'rejected',
      reason: 'Signet link revoked, credential no longer valid despite valid APS signature',
    },
  ],
  signet_link: {
    ...vector1.signet_link,
    status: 'revoked',
  },
  expected: {
    aps_signature_valid: true,
    signet_status: 'revoked',
    access_granted: false,
    reason: 'Cross-protocol revocation check: Signet link revoked',
  },
}

writeFileSync(`${dir}vector-3-revocation.json`, JSON.stringify(vector3, null, 2) + '\n')

console.log('Generated 3 Signet interop test vectors:')
console.log('  vector-1-issuance.json')
console.log('  vector-2-presentation.json')
console.log('  vector-3-revocation.json')
