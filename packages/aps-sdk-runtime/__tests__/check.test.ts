import { test } from 'node:test';
import assert from 'node:assert/strict';

import {
  authorityInfo,
  check,
  closeAuthority,
  computeRegistryRoot,
  hashResourcePath,
  loadPassportUnverified,
} from '..';

const TOOL_DESCRIPTOR_HASH_HEX =
  'abcd000000000000000000000000000000000000000000000000000000000000';

/// Build a passport JSON with timestamps centered on `now` so the
/// `SystemClock`-backed verifier falls inside the validity window.
function buildPassport(rootHex: string): string {
  const now = Date.now();
  const issued = new Date(now - 30_000).toISOString();
  const expires = new Date(now + 30_000).toISOString();
  return JSON.stringify({
    type: 'aps.runtime_passport',
    version: '0.1',
    passport_id: 'rp_chunk2test0000000000000000',
    agent_id: 'ag_chunk2test0000000000000000',
    principal_id: 'pr_chunk2test0000000000000000',
    beneficiary_id: 'bn_chunk2test0000000000000000',
    issuer: 'https://gateway.example.test',
    issued_at: issued,
    expires_at: expires,
    max_clock_skew_ms: 1000,
    policy_epoch: 42,
    revocation_epoch: 1842,
    tool_registry_root: `blake3:${rootHex}`,
    delegation_chain_hash:
      'sha256:0000000000000000000000000000000000000000000000000000000000000000',
    effective_authority_hash:
      'blake3:0000000000000000000000000000000000000000000000000000000000000000',
    risk_class: 'R2',
    minimum_tier_required: 'T2',
    tier_attested: 'T2',
    verifier_instance_id: 'vi_chunk2test0000000000000000',
    verifier_build_hash:
      'blake3:1111111111111111111111111111111111111111111111111111111111111111',
    session_id: 'sn_chunk2test0000000000000000',
    sequence_start: 1000,
    sequence_end: 2000,
    budget_lease: {
      lease_id: 'bl_chunk2test0000000000000000',
      max_actions: 1000,
      max_cost_units: 50000,
      sublease_parent: null,
    },
    authority_blob_encoding: 'application/aps-authority+json',
    authority_blob: {
      allowed_tools: [`blake3:${TOOL_DESCRIPTOR_HASH_HEX}`],
      allowed_operations: ['read'],
      resource_scopes: ['customer/*'],
      approval_rules: [],
    },
    receipt_stream_id: 'rs_chunk2test0000000000000000',
    signature: 'ed25519:' + '0'.repeat(128),
  });
}

function freshHandle() {
  const tools = [
    { descriptorHashHex: TOOL_DESCRIPTOR_HASH_HEX, localId: 0 },
  ];
  const rootHex = computeRegistryRoot(tools);
  const passportJson = buildPassport(rootHex);
  return loadPassportUnverified(passportJson, tools, { mode: 'Null' });
}

function buildAllowAction(handle: ReturnType<typeof loadPassportUnverified>) {
  const info = authorityInfo(handle);
  return {
    version: 1,
    passportIdHashHex: info.passportIdHashHex,
    toolDescriptorHashHex: TOOL_DESCRIPTOR_HASH_HEX,
    localToolId: 0,
    operationId: 0, // "read"
    resourceType: 0,
    riskClass: 2, // R2
    resourcePathDepth: 2,
    costUnits: 1,
    sequenceId: 1000n,
    nonceHex: '00112233445566778899aabbccddeeff',
    resourcePathHashes: hashResourcePath(['customer', '12345']),
  };
}

// -----------------------------------------------------------------------
// Lifecycle
// -----------------------------------------------------------------------

test('load_passport returns a handle and exposes identity hashes', () => {
  const handle = freshHandle();
  const info = authorityInfo(handle);
  assert.equal(info.passportIdHashHex.length, 64);
  assert.equal(info.toolRegistryRootHex.length, 64);
});

test('close_authority is a no-op signal that does not throw', () => {
  const handle = freshHandle();
  closeAuthority(handle);
});

// -----------------------------------------------------------------------
// Allow path
// -----------------------------------------------------------------------

test('check returns Allow for a matching action', () => {
  const handle = freshHandle();
  const action = buildAllowAction(handle);
  const decision = check(handle, action);
  assert.equal(
    decision.decisionType,
    'Allow',
    `unexpected reason ${decision.reasonName} (0x${decision.reasonCode.toString(16)})`
  );
  assert.equal(decision.reasonCode, 0);
  assert.equal(decision.reasonName, 'OK');
  assert.equal(decision.sequenceId, 1000n);
  assert.equal(decision.decisionIdHex.length, 32);
  assert.equal(decision.eventMacHex.length, 64);
  // event_mac is computed even on Allow (chunk 7 finalize)
  assert.notEqual(decision.eventMacHex, '0'.repeat(64));
});

// -----------------------------------------------------------------------
// Deny paths
// -----------------------------------------------------------------------

// Note: spec §9 step 0 ACTION_HASH_INVALID is not reachable from the
// chunk-2 ActionInput surface. Rust .finalize() always recomputes
// action_hash from the current fields, so the stored and computed
// values agree by construction. A future chunk that accepts raw
// pre-finalized 204-byte ActionDescriptor bytes could surface this
// deny path; chunk 2 does not.

test('check returns Deny RESOURCE_OUT_OF_SCOPE for an off-scope path', () => {
  const handle = freshHandle();
  const action = {
    ...buildAllowAction(handle),
    resourcePathHashes: hashResourcePath(['unrelated', 'path']),
    resourcePathDepth: 2,
    sequenceId: 1000n,
  };
  const decision = check(handle, action);
  assert.equal(decision.decisionType, 'Deny');
  assert.equal(decision.reasonName, 'RESOURCE_OUT_OF_SCOPE');
});

test('check returns Deny OPERATION_NOT_ALLOWED for an off-spec op', () => {
  const handle = freshHandle();
  const action = {
    ...buildAllowAction(handle),
    operationId: 1, // "write" — passport only allows "read"
  };
  const decision = check(handle, action);
  assert.equal(decision.decisionType, 'Deny');
  assert.equal(decision.reasonName, 'OPERATION_NOT_ALLOWED');
});

test('check returns Deny SEQUENCE_REPLAY after the first Allow advances sequence', () => {
  const handle = freshHandle();
  const action = buildAllowAction(handle);
  const first = check(handle, action);
  assert.equal(first.decisionType, 'Allow');
  // Same action again: sequence_next is now 1001, action still claims 1000
  const second = check(handle, action);
  assert.equal(second.decisionType, 'Deny');
  assert.equal(second.reasonName, 'SEQUENCE_REPLAY');
});

test('load_passport rejects mismatched registry root', () => {
  const tools = [
    { descriptorHashHex: TOOL_DESCRIPTOR_HASH_HEX, localId: 0 },
  ];
  // Lie about the root: pass an all-zeros root in the passport while
  // the registry actually has the tool.
  const passportJson = buildPassport('0'.repeat(64));
  assert.throws(
    () => loadPassportUnverified(passportJson, tools, { mode: 'Null' }),
    /CompileFailed/
  );
});
