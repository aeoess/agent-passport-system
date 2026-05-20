import { test } from 'node:test';
import assert from 'node:assert/strict';

// napi-rs writes the native loader to ../index.js at the package
// root. The .d.ts beside it provides the typed surface.
import { parsePassportSummary } from '..';

const VALID_PASSPORT_JSON = JSON.stringify({
  type: 'aps.runtime_passport',
  version: '0.1',
  passport_id: 'rp_01HX0TESTROUNDTRIP000000000',
  agent_id: 'ag_01HX0TESTROUNDTRIP000000000',
  principal_id: 'pr_01HX0TESTROUNDTRIP000000000',
  beneficiary_id: 'bn_01HX0TESTROUNDTRIP000000000',
  issuer: 'https://gateway.example.test',
  issued_at: '2026-05-19T22:38:56.000Z',
  expires_at: '2026-05-19T22:39:56.000Z',
  max_clock_skew_ms: 1000,
  policy_epoch: 42,
  revocation_epoch: 1842,
  tool_registry_root:
    'blake3:0000000000000000000000000000000000000000000000000000000000000000',
  delegation_chain_hash:
    'sha256:0000000000000000000000000000000000000000000000000000000000000000',
  effective_authority_hash:
    'blake3:0000000000000000000000000000000000000000000000000000000000000000',
  risk_class: 'R2',
  minimum_tier_required: 'T2',
  tier_attested: 'T2',
  verifier_instance_id: 'vi_01HX0VI00000000000000000000',
  verifier_build_hash:
    'blake3:1111111111111111111111111111111111111111111111111111111111111111',
  session_id: 'sn_01HX0SESS00000000000000000000',
  sequence_start: 1000,
  sequence_end: 2000,
  budget_lease: {
    lease_id: 'bl_01HX0LEASE0000000000000000000',
    max_actions: 1000,
    max_cost_units: 50000,
    sublease_parent: null,
  },
  authority_blob_encoding: 'application/aps-authority+json',
  authority_blob: {
    allowed_tools: [
      'blake3:abcd000000000000000000000000000000000000000000000000000000000000',
    ],
    allowed_operations: ['read'],
    resource_scopes: ['customer/*'],
    approval_rules: [],
  },
  receipt_stream_id: 'rs_01HX0RS00000000000000000000',
  signature: 'ed25519:' + '0'.repeat(128),
});

test('FFI: parses a valid passport JSON and returns the summary', () => {
  const summary = parsePassportSummary(VALID_PASSPORT_JSON);
  assert.equal(summary.passportId, 'rp_01HX0TESTROUNDTRIP000000000');
  assert.equal(summary.agentId, 'ag_01HX0TESTROUNDTRIP000000000');
  assert.equal(summary.principalId, 'pr_01HX0TESTROUNDTRIP000000000');
  assert.equal(summary.beneficiaryId, 'bn_01HX0TESTROUNDTRIP000000000');
  assert.equal(summary.riskClass, 'R2');
  assert.equal(summary.minimumTierRequired, 'T2');
  assert.equal(summary.tierAttested, 'T2');
  assert.equal(summary.sequenceStart, 1000);
  assert.equal(summary.sequenceEnd, 2000);
});

test('FFI: rejects malformed JSON with a thrown Error', () => {
  assert.throws(() => parsePassportSummary('not json'), /parse failed/);
});

test('FFI: rejects structurally invalid passport (expires_at < issued_at)', () => {
  const bad = JSON.parse(VALID_PASSPORT_JSON);
  bad.expires_at = '2026-05-19T22:00:00.000Z';
  bad.issued_at = '2026-05-19T22:38:56.000Z';
  assert.throws(
    () => parsePassportSummary(JSON.stringify(bad)),
    /parse failed/
  );
});
