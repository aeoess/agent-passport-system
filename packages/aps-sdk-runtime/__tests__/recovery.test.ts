import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, statSync, rmSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import {
  authorityInfo,
  check,
  computeRegistryRoot,
  loadPassportUnverified,
  loadPassportWithRecovery,
  recoveryReport,
  shutdownAuthority,
  SinkMode,
} from '..';
import { buildAction } from '../src/action-builder.js';

const TOOL_DESCRIPTOR_HASH_HEX =
  'abcd000000000000000000000000000000000000000000000000000000000000';

function tmpLog(): { dir: string; logPath: string } {
  const dir = mkdtempSync(join(tmpdir(), 'aps-sdk-recovery-'));
  return { dir, logPath: join(dir, 'receipts.log') };
}

function passportJson(rootHex: string, sequenceStart = 1000, sequenceEnd = 2000): string {
  const now = Date.now();
  const issued = new Date(now - 30_000).toISOString();
  const expires = new Date(now + 30_000).toISOString();
  return JSON.stringify({
    type: 'aps.runtime_passport',
    version: '0.1',
    passport_id: 'rp_recover_test00000000000000',
    agent_id: 'ag_recover_test00000000000000',
    principal_id: 'pr_recover_test00000000000000',
    beneficiary_id: 'bn_recover_test00000000000000',
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
    verifier_instance_id: 'vi_recover_test00000000000000',
    verifier_build_hash:
      'blake3:1111111111111111111111111111111111111111111111111111111111111111',
    session_id: 'sn_recover_test00000000000000',
    sequence_start: sequenceStart,
    sequence_end: sequenceEnd,
    budget_lease: {
      lease_id: 'bl_recover_test00000000000000',
      max_actions: 1000,
      max_cost_units: 50_000,
      sublease_parent: null,
    },
    authority_blob_encoding: 'application/aps-authority+json',
    authority_blob: {
      allowed_tools: [`blake3:${TOOL_DESCRIPTOR_HASH_HEX}`],
      allowed_operations: ['read'],
      resource_scopes: ['customer/*'],
      approval_rules: [],
    },
    receipt_stream_id: 'rs_recover_test00000000000000',
    signature: 'ed25519:' + '0'.repeat(128),
  });
}

const tools = [{ descriptorHashHex: TOOL_DESCRIPTOR_HASH_HEX, localId: 0 }];

function actionFor(handle: any, seqId: bigint) {
  return buildAction({
    handle,
    toolDescriptorHashHex: TOOL_DESCRIPTOR_HASH_HEX,
    localToolId: 0,
    operationId: 0,
    riskClass: 2,
    resourcePath: ['customer', '12345'],
    costUnits: 1,
    sequenceId: seqId,
  });
}

// -----------------------------------------------------------------------
// FreshStart — no existing log
// -----------------------------------------------------------------------

test('recovery: FreshStart when log_path does not yet exist', () => {
  const { dir, logPath } = tmpLog();
  try {
    assert.ok(!existsSync(logPath));
    const rootHex = computeRegistryRoot(tools);
    const json = passportJson(rootHex);
    const handle = loadPassportWithRecovery(
      json,
      tools,
      null,
      { mode: SinkMode.ModeB1, logPath, bufferCapacity: 64, maxBatchSize: 64, maxBatchWindowMs: 25 },
      logPath
    );
    const report = recoveryReport(handle);
    assert.ok(report, 'recoveryReport should be populated');
    assert.equal(report!.status, 'FreshStart');
    assert.equal(report!.entriesRecovered, 0n);
    assert.ok(
      report!.truncationReason == null,
      `expected no truncationReason, got ${report!.truncationReason}`
    );
    // First check at sequence_start = 1000 should succeed.
    const dec = check(handle, actionFor(handle, 1000n));
    assert.equal(dec.decisionType, 'Allow');
    shutdownAuthority(handle);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

// -----------------------------------------------------------------------
// CleanRecovery — replay valid log
// -----------------------------------------------------------------------

test('recovery: CleanRecovery replays log and reports floor; next check at floor+1 succeeds', () => {
  const { dir, logPath } = tmpLog();
  try {
    const rootHex = computeRegistryRoot(tools);
    const json = passportJson(rootHex);
    // Phase 1: write 5 entries via ModeB1 then shutdown cleanly.
    {
      const handle = loadPassportUnverified(json, tools, {
        mode: SinkMode.ModeB1,
        logPath,
        bufferCapacity: 64,
        maxBatchSize: 8,
        maxBatchWindowMs: 25,
      });
      for (let i = 0; i < 5; i++) {
        const dec = check(handle, actionFor(handle, 1000n + BigInt(i)));
        assert.equal(dec.decisionType, 'Allow', `phase1 iter ${i}: ${dec.reasonName}`);
      }
      shutdownAuthority(handle);
      // 5 entries × 100 bytes = 500
      assert.equal(statSync(logPath).size, 500);
    }
    // Phase 2: reload with recovery.
    const handle2 = loadPassportWithRecovery(
      json,
      tools,
      null,
      { mode: SinkMode.ModeB1, logPath, bufferCapacity: 64, maxBatchSize: 8, maxBatchWindowMs: 25 },
      logPath
    );
    const report = recoveryReport(handle2);
    assert.ok(report, 'recoveryReport should be populated');
    assert.equal(report!.status, 'CleanRecovery');
    assert.equal(report!.entriesRecovered, 5n);
    assert.equal(report!.lastCommittedSequenceId, 1004n);
    assert.equal(report!.validThroughOffset, 500n);
    assert.ok(report!.truncationReason == null);

    // sequence floor advanced. Replay at 1000 must fail SEQUENCE_RECOVERY_INVALID.
    const replay = check(handle2, actionFor(handle2, 1000n));
    assert.equal(replay.decisionType, 'Deny');
    assert.equal(replay.reasonName, 'SEQUENCE_RECOVERY_INVALID');

    // Floor+1 = 1005 must succeed.
    const next = check(handle2, actionFor(handle2, 1005n));
    assert.equal(next.decisionType, 'Allow', `floor+1 check: ${next.reasonName}`);
    shutdownAuthority(handle2);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

// -----------------------------------------------------------------------
// End-to-end crash + resume
// -----------------------------------------------------------------------

test('recovery: end-to-end crash + resume preserves sequence chain across reload', () => {
  const { dir, logPath } = tmpLog();
  try {
    const rootHex = computeRegistryRoot(tools);
    const json = passportJson(rootHex);
    // Pre-crash: 3 Allows then shutdown (simulated graceful close).
    {
      const handle = loadPassportUnverified(json, tools, {
        mode: SinkMode.ModeB1,
        logPath,
        bufferCapacity: 64,
        maxBatchSize: 4,
        maxBatchWindowMs: 25,
      });
      for (let i = 0; i < 3; i++) {
        check(handle, actionFor(handle, 1000n + BigInt(i)));
      }
      shutdownAuthority(handle);
    }
    const sizeAfterCrash = statSync(logPath).size;
    assert.equal(sizeAfterCrash, 300, `expected 300 bytes, got ${sizeAfterCrash}`);

    // Resume.
    const resumed = loadPassportWithRecovery(
      json,
      tools,
      null,
      { mode: SinkMode.ModeB1, logPath, bufferCapacity: 64, maxBatchSize: 4, maxBatchWindowMs: 25 },
      logPath
    );
    const report = recoveryReport(resumed);
    assert.equal(report!.status, 'CleanRecovery');
    assert.equal(report!.entriesRecovered, 3n);
    assert.equal(report!.lastCommittedSequenceId, 1002n);

    // Continue emitting from 1003.
    for (let i = 3; i < 6; i++) {
      const dec = check(resumed, actionFor(resumed, 1000n + BigInt(i)));
      assert.equal(dec.decisionType, 'Allow', `post-recovery iter ${i}: ${dec.reasonName}`);
    }
    shutdownAuthority(resumed);
    // Log grew from 300 → 600.
    assert.equal(statSync(logPath).size, 600);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
