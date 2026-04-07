#!/usr/bin/env node
// Generate interop verification fixtures for APS cross-implementation testing.
// Each fixture is self-contained: objects, canonicalized forms, signatures, public keys,
// and expected verification results. A verifier needs no APS SDK to check these.

import {
  createPassport, signPassport, verifyPassport,
  createDelegation, verifyDelegation, revokeDelegation,
  createReceipt, verifyReceipt,
  createCompletionReceipt, verifyCompletionReceipt, linkPermitAndCompletion,
  generateKeyPair, sign, verify, publicKeyFromPrivate,
  canonicalize,
  canonicalizeJCS,
} from 'agent-passport-system'
import { writeFileSync } from 'node:fs'
import { createHash } from 'node:crypto'

const FIXTURES_DIR = new URL('../interop/fixtures/', import.meta.url).pathname

function toHex(str) {
  return Buffer.from(str, 'utf8').toString('hex')
}

// ═══════════════════════════════════════════════════════════
// Fixture 1: Happy Path — full chain, all valid
// ═══════════════════════════════════════════════════════════

function generateHappyPath() {
  const principal = generateKeyPair()
  const agent = generateKeyPair()

  // 1. Create passport
  const { signedPassport, keyPair: passportKeys } = createPassport({
    agentId: 'fixture-agent-001',
    agentName: 'Fixture Agent',
    ownerAlias: 'fixture-owner',
    mission: 'Interop verification fixture',
    capabilities: ['data_access', 'api_calls'],
  })

  // 2. Create delegation from principal to agent
  const delegation = createDelegation({
    delegatedTo: agent.publicKey,
    delegatedBy: principal.publicKey,
    scope: ['data:read', 'api:get'],
    spendLimit: 10000,
    expiresInHours: 24,
    privateKey: principal.privateKey,
  })

  // 3. Create receipt
  const receipt = createReceipt({
    agentId: 'fixture-agent-001',
    delegationId: delegation.delegationId,
    delegation,
    action: {
      type: 'data:read',
      target: 'customer-db',
      scopeUsed: 'data:read',
      timestamp: new Date().toISOString(),
    },
    result: {
      success: true,
      output: 'Query returned 42 rows',
    },
    delegationChain: [principal.publicKey, agent.publicKey],
    privateKey: agent.privateKey,
  })

  // Canonicalize each signed object (for cross-implementation verification)
  const { signature: passportSig, ...passportUnsigned } = signedPassport
  const passportCanonical = canonicalize(passportUnsigned.passport)

  const { signature: delSig, ...delUnsigned } = delegation
  const delCanonical = canonicalize(delUnsigned)

  const { signature: rcptSig, ...rcptUnsigned } = receipt
  const rcptCanonical = canonicalize(rcptUnsigned)

  // Verify everything works
  const passportVerification = verifyPassport(signedPassport)
  const delegationVerification = verifyDelegation(delegation)
  const receiptVerification = verifyReceipt(receipt, agent.publicKey)

  const fixture = {
    description: 'Happy path: passport issued, delegation created (scope: [data:read, api:get], spendLimit: 10000, 24h expiry), action executed, receipt stored. Full chain, all signatures valid.',
    generated_at: new Date().toISOString(),
    protocol_version: '1.0.0',

    objects: {
      passport: signedPassport,
      delegation,
      receipt,
    },

    canonicalized: {
      passport: {
        input: signedPassport.passport,
        canonical_string: passportCanonical,
        canonical_hex: toHex(passportCanonical),
        method: 'APS canonical (sorted keys, null-stripped)',
      },
      delegation: {
        input: delUnsigned,
        canonical_string: delCanonical,
        canonical_hex: toHex(delCanonical),
        method: 'APS canonical (sorted keys, null-stripped)',
      },
      receipt: {
        input: rcptUnsigned,
        canonical_string: rcptCanonical,
        canonical_hex: toHex(rcptCanonical),
        method: 'APS canonical (sorted keys, null-stripped)',
      },
    },

    signatures: {
      passport: {
        signature: signedPassport.signature,
        signed_by: 'passport_owner (self-signed)',
        algorithm: 'Ed25519',
      },
      delegation: {
        signature: delegation.signature,
        signed_by: 'principal (delegatedBy)',
        algorithm: 'Ed25519',
      },
      receipt: {
        signature: receipt.signature,
        signed_by: 'agent (executing agent)',
        algorithm: 'Ed25519',
      },
    },

    keys: {
      passport_owner: {
        public_key: passportKeys.publicKey,
        role: 'Passport holder, self-signs passport',
      },
      principal: {
        public_key: principal.publicKey,
        role: 'Delegator, signs delegation',
      },
      agent: {
        public_key: agent.publicKey,
        role: 'Delegate, signs receipt',
      },
    },

    expected: {
      passport_signature_valid: true,
      delegation_signature_valid: true,
      delegation_not_expired: true,
      delegation_not_revoked: true,
      receipt_signature_valid: true,
      full_chain_valid: true,
      reasoning: 'All objects are freshly created, within validity windows, and properly signed. Every verification step should return true.',
    },

    verification_results: {
      passport: passportVerification,
      delegation: delegationVerification,
      receipt: receiptVerification,
    },
  }

  writeFileSync(FIXTURES_DIR + 'happy-path.json', JSON.stringify(fixture, null, 2))
  console.log('wrote happy-path.json')
}

// ═══════════════════════════════════════════════════════════
// Fixture 2: Revoked Ancestor — delegation revoked after receipt
// ═══════════════════════════════════════════════════════════

function generateRevokedAncestor() {
  const principal = generateKeyPair()
  const agent = generateKeyPair()

  // 1. Passport
  const { signedPassport, keyPair: passportKeys } = createPassport({
    agentId: 'fixture-agent-002',
    agentName: 'Revocation Test Agent',
    ownerAlias: 'fixture-owner',
    mission: 'Test revocation after receipt issuance',
    capabilities: ['data_access'],
  })

  // 2. Delegation
  const delegation = createDelegation({
    delegatedTo: agent.publicKey,
    delegatedBy: principal.publicKey,
    scope: ['data:read', 'api:get'],
    spendLimit: 10000,
    expiresInHours: 24,
    privateKey: principal.privateKey,
  })

  // 3. Receipt (created while delegation is still active)
  const receipt = createReceipt({
    agentId: 'fixture-agent-002',
    delegationId: delegation.delegationId,
    delegation,
    action: {
      type: 'data:read',
      target: 'customer-db',
      scopeUsed: 'data:read',
      timestamp: new Date().toISOString(),
    },
    result: { success: true, output: 'Read 10 records' },
    delegationChain: [principal.publicKey, agent.publicKey],
    privateKey: agent.privateKey,
  })

  // 4. Revoke the delegation AFTER receipt creation
  const revocation = revokeDelegation(
    delegation.delegationId,
    principal.publicKey,
    'Testing revocation after receipt issuance',
    principal.privateKey,
  )

  // Canonicalize
  const { signature: delSig, ...delUnsigned } = delegation
  const delCanonical = canonicalize(delUnsigned)

  const { signature: rcptSig, ...rcptUnsigned } = receipt
  const rcptCanonical = canonicalize(rcptUnsigned)

  const { signature: revSig, ...revUnsigned } = revocation
  const revCanonical = canonicalize(revUnsigned)

  // Post-revocation verification
  const delegationPostRevoke = verifyDelegation(delegation)
  const receiptVerification = verifyReceipt(receipt, agent.publicKey)

  const fixture = {
    description: 'Revoked ancestor: delegation is revoked after a valid receipt was created. Receipt signature remains valid (it was valid when issued), but chain verification fails because the delegation is now revoked.',
    generated_at: new Date().toISOString(),
    protocol_version: '1.0.0',

    objects: {
      passport: signedPassport,
      delegation,
      receipt,
      revocation,
    },

    canonicalized: {
      delegation: {
        input: delUnsigned,
        canonical_string: delCanonical,
        canonical_hex: toHex(delCanonical),
        method: 'APS canonical (sorted keys, null-stripped)',
      },
      receipt: {
        input: rcptUnsigned,
        canonical_string: rcptCanonical,
        canonical_hex: toHex(rcptCanonical),
        method: 'APS canonical (sorted keys, null-stripped)',
      },
      revocation: {
        input: revUnsigned,
        canonical_string: revCanonical,
        canonical_hex: toHex(revCanonical),
        method: 'APS canonical (sorted keys, null-stripped)',
      },
    },

    signatures: {
      delegation: { signature: delegation.signature, signed_by: 'principal', algorithm: 'Ed25519' },
      receipt: { signature: receipt.signature, signed_by: 'agent', algorithm: 'Ed25519' },
      revocation: { signature: revocation.signature, signed_by: 'principal (revoker)', algorithm: 'Ed25519' },
    },

    keys: {
      passport_owner: { public_key: passportKeys.publicKey, role: 'Passport holder' },
      principal: { public_key: principal.publicKey, role: 'Delegator and revoker' },
      agent: { public_key: agent.publicKey, role: 'Delegate, receipt signer' },
    },

    expected: {
      delegation_signature_valid: true,
      delegation_revoked: true,
      receipt_signature_valid: true,
      revocation_signature_valid: true,
      chain_valid_at_receipt_time: true,
      chain_valid_after_revocation: false,
      reasoning: 'The delegation was valid when the receipt was created, so the receipt signature is correct. However, the delegation was subsequently revoked. Verifiers should check revocation status: the receipt is cryptographically valid but the authority chain is broken.',
    },

    verification_results: {
      delegation_after_revocation: delegationPostRevoke,
      receipt: receiptVerification,
    },
  }

  writeFileSync(FIXTURES_DIR + 'revoked-ancestor.json', JSON.stringify(fixture, null, 2))
  console.log('wrote revoked-ancestor.json')
}

// ═══════════════════════════════════════════════════════════
// Fixture 3: Stale Replay — delegation expired before verification
// ═══════════════════════════════════════════════════════════

function generateStaleReplay() {
  const principal = generateKeyPair()
  const agent = generateKeyPair()

  // 1. Passport
  const { signedPassport, keyPair: passportKeys } = createPassport({
    agentId: 'fixture-agent-003',
    agentName: 'Stale Replay Test Agent',
    ownerAlias: 'fixture-owner',
    mission: 'Test temporal validation after expiry',
    capabilities: ['data_access'],
  })

  // 2. Create delegation with very short expiry
  // We fabricate timestamps to create the expired scenario deterministically
  const createdAt = '2026-01-01T00:00:00.000Z'
  const expiresAt = '2026-01-01T00:00:05.000Z' // 5 seconds
  const notBefore = createdAt

  // Manually build the delegation with fixed timestamps
  const delBody = {
    delegationId: 'del_stale-replay',
    delegatedTo: agent.publicKey,
    delegatedBy: principal.publicKey,
    scope: ['data:read', 'api:get'],
    expiresAt,
    spendLimit: 10000,
    spentAmount: 0,
    maxDepth: 1,
    currentDepth: 0,
    createdAt,
    notBefore,
  }

  const delCanonical = canonicalize(delBody)
  const delSignature = sign(delCanonical, principal.privateKey)
  const delegation = { ...delBody, signature: delSignature }

  // 3. Receipt created at T=0 (within validity)
  const receiptTimestamp = '2026-01-01T00:00:01.000Z' // 1 second in, valid
  const rcptBody = {
    receiptId: 'rcpt_stale-replay',
    version: '1.1',
    timestamp: receiptTimestamp,
    agentId: 'fixture-agent-003',
    delegationId: delegation.delegationId,
    action: {
      type: 'data:read',
      target: 'customer-db',
      scopeUsed: 'data:read',
      timestamp: receiptTimestamp,
    },
    result: { success: true, output: 'Read 5 records' },
    delegationChain: [principal.publicKey, agent.publicKey],
  }

  const rcptCanonical = canonicalize(rcptBody)
  const rcptSignature = sign(rcptCanonical, agent.privateKey)
  const receipt = { ...rcptBody, signature: rcptSignature }

  // Verification at T=10 (after expiry)
  const verifyAt = '2026-01-01T00:00:10.000Z'

  // Receipt signature should still verify (cryptographic validity is time-independent)
  const receiptSigValid = verify(rcptCanonical, rcptSignature, agent.publicKey)

  // Delegation should fail (expired)
  // verifyDelegation checks against Date.now(), and the delegation is in the past
  const delegationCheck = verifyDelegation(delegation)

  const fixture = {
    description: 'Stale replay: delegation has a 5-second validity window (2026-01-01T00:00:00Z to 2026-01-01T00:00:05Z). Receipt created at T=1s (valid). Fixture includes verify_at of T=10s (after expiry). Receipt signature is cryptographically valid, but temporal validation fails because the delegation expired before the verification time.',
    generated_at: new Date().toISOString(),
    protocol_version: '1.0.0',

    objects: {
      passport: signedPassport,
      delegation,
      receipt,
    },

    temporal: {
      delegation_created_at: createdAt,
      delegation_expires_at: expiresAt,
      receipt_created_at: receiptTimestamp,
      verify_at: verifyAt,
      delegation_valid_window_seconds: 5,
      receipt_within_window: true,
      verify_at_after_expiry: true,
    },

    canonicalized: {
      delegation: {
        input: delBody,
        canonical_string: delCanonical,
        canonical_hex: toHex(delCanonical),
        method: 'APS canonical (sorted keys, null-stripped)',
      },
      receipt: {
        input: rcptBody,
        canonical_string: rcptCanonical,
        canonical_hex: toHex(rcptCanonical),
        method: 'APS canonical (sorted keys, null-stripped)',
      },
    },

    signatures: {
      delegation: { signature: delSignature, signed_by: 'principal', algorithm: 'Ed25519' },
      receipt: { signature: rcptSignature, signed_by: 'agent', algorithm: 'Ed25519' },
    },

    keys: {
      passport_owner: { public_key: passportKeys.publicKey, role: 'Passport holder' },
      principal: { public_key: principal.publicKey, role: 'Delegator' },
      agent: { public_key: agent.publicKey, role: 'Delegate, receipt signer' },
    },

    expected: {
      receipt_signature_valid: true,
      delegation_signature_valid: true,
      delegation_expired_at_verify_time: true,
      temporal_validation_fails: true,
      reasoning: 'The receipt was created within the delegation validity window (T=1s < T=5s expiry), so the action was authorized at execution time. However, at verify_at (T=10s), the delegation has expired. A verifier checking "is this delegation currently valid?" should return false. The receipt signature itself is still cryptographically valid because Ed25519 signatures do not expire.',
    },

    verification_results: {
      receipt_signature_check: receiptSigValid,
      delegation_check_now: delegationCheck,
      note: 'delegation_check_now runs against Date.now(), which is after the 2026-01-01 expiry, so it correctly reports expired.',
    },
  }

  writeFileSync(FIXTURES_DIR + 'stale-replay.json', JSON.stringify(fixture, null, 2))
  console.log('wrote stale-replay.json')
}

// ═══════════════════════════════════════════════════════════
// Fixture 4: Completion Chain — full permit-execute-complete lifecycle
// ═══════════════════════════════════════════════════════════

function generateCompletionChain() {
  const principal = generateKeyPair()
  const agent = generateKeyPair()

  // 1. Passport
  const { signedPassport, keyPair: passportKeys } = createPassport({
    agentId: 'fixture-agent-004',
    agentName: 'Completion Chain Agent',
    ownerAlias: 'fixture-owner',
    mission: 'Test bilateral completion receipt lifecycle',
    capabilities: ['data_access', 'api_calls'],
  })

  // 2. Delegation
  const delegation = createDelegation({
    delegatedTo: agent.publicKey,
    delegatedBy: principal.publicKey,
    scope: ['data:read', 'api:get'],
    spendLimit: 5000,
    expiresInHours: 24,
    privateKey: principal.privateKey,
  })

  // 3. Permit receipt (action authorized and executed)
  const permitReceipt = createReceipt({
    agentId: 'fixture-agent-004',
    delegationId: delegation.delegationId,
    delegation,
    action: {
      type: 'data:read',
      target: 'analytics-db',
      scopeUsed: 'data:read',
      timestamp: new Date().toISOString(),
    },
    result: { success: true, output: 'Query completed' },
    delegationChain: [principal.publicKey, agent.publicKey],
    privateKey: agent.privateKey,
  })

  // 4. Hash the permit receipt for linking
  const { signature: _permitSig, ...permitUnsigned } = permitReceipt
  const permitCanonical = canonicalize(permitUnsigned)
  const permitHash = createHash('sha256').update(permitCanonical).digest('hex')

  // 5. Completion receipt — agent attests to execution outcome
  const completionReceipt = createCompletionReceipt({
    permitReceiptHash: permitHash,
    executionResult: 'success',
    resultSummary: 'Query returned 128 rows from analytics-db in 42ms',
    resultHash: createHash('sha256').update('Query returned 128 rows').digest('hex'),
    executedAt: new Date().toISOString(),
    durationMs: 42,
    privateKey: agent.privateKey,
  })

  // 6. Verify everything
  const permitVerification = verifyReceipt(permitReceipt, agent.publicKey)
  const completionVerification = verifyCompletionReceipt(completionReceipt, agent.publicKey)
  const linkResult = linkPermitAndCompletion(permitReceipt, completionReceipt)

  // Canonicalize for cross-impl verification
  const { signature: cmpSig, ...cmpUnsigned } = completionReceipt
  const cmpCanonical = canonicalize(cmpUnsigned)

  const fixture = {
    description: 'Completion chain: full permit-execute-complete lifecycle. Delegation authorizes action, permit receipt proves authorization, completion receipt proves execution outcome, linkPermitAndCompletion binds them cryptographically via SHA-256 hash of canonicalized permit receipt.',
    generated_at: new Date().toISOString(),
    protocol_version: '1.0.0',

    objects: {
      passport: signedPassport,
      delegation,
      permit_receipt: permitReceipt,
      completion_receipt: completionReceipt,
    },

    canonicalized: {
      delegation: {
        input: (() => { const { signature: _s, ...u } = delegation; return u })(),
        canonical_string: (() => { const { signature: _s, ...u } = delegation; return canonicalize(u) })(),
        canonical_hex: (() => { const { signature: _s, ...u } = delegation; return toHex(canonicalize(u)) })(),
        method: 'APS canonical (sorted keys, null-stripped)',
      },
      permit_receipt: {
        input: permitUnsigned,
        canonical_string: permitCanonical,
        canonical_hex: toHex(permitCanonical),
        sha256_hash: permitHash,
        method: 'APS canonical (sorted keys, null-stripped)',
      },
      completion_receipt: {
        input: cmpUnsigned,
        canonical_string: cmpCanonical,
        canonical_hex: toHex(cmpCanonical),
        method: 'APS canonical (sorted keys, null-stripped)',
      },
    },

    signatures: {
      delegation: { signature: delegation.signature, signed_by: 'principal', algorithm: 'Ed25519' },
      permit_receipt: { signature: permitReceipt.signature, signed_by: 'agent', algorithm: 'Ed25519' },
      completion_receipt: { signature: completionReceipt.signature, signed_by: 'agent', algorithm: 'Ed25519' },
    },

    keys: {
      passport_owner: { public_key: passportKeys.publicKey, role: 'Passport holder' },
      principal: { public_key: principal.publicKey, role: 'Delegator' },
      agent: { public_key: agent.publicKey, role: 'Delegate, signs both receipts' },
    },

    linking: {
      permit_receipt_hash: permitHash,
      completion_claims_hash: completionReceipt.permitReceiptHash,
      hashes_match: permitHash === completionReceipt.permitReceiptHash,
      method: 'SHA-256 of canonicalized permit receipt (signature stripped)',
    },

    expected: {
      permit_receipt_signature_valid: true,
      completion_receipt_signature_valid: true,
      permit_completion_linked: true,
      execution_result: 'success',
      reasoning: 'Both receipts are signed by the same agent. The completion receipt references the permit receipt by SHA-256 hash of its canonicalized form. linkPermitAndCompletion confirms the hash match. This proves the agent that was authorized (permit) is the same agent that attests to execution (completion).',
    },

    verification_results: {
      permit_receipt: permitVerification,
      completion_receipt: completionVerification,
      link: linkResult,
    },
  }

  writeFileSync(FIXTURES_DIR + 'completion-chain.json', JSON.stringify(fixture, null, 2))
  console.log('wrote completion-chain.json')
}

// ═══════════════════════════════════════════════════════════
// Generate all fixtures
// ═══════════════════════════════════════════════════════════

console.log('Generating interop fixtures...')
generateHappyPath()
generateRevokedAncestor()
generateStaleReplay()
generateCompletionChain()
console.log('Done. Files in interop/fixtures/')
