import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, statSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import {
  authorityInfo,
  check,
  computeRegistryRoot,
  hashResourcePath,
  loadPassportUnverified,
  shutdownAuthority,
  SinkMode,
} from '..';

const TOOL_DESCRIPTOR_HASH_HEX =
  'abcd000000000000000000000000000000000000000000000000000000000000';

function tmpLog(): { dir: string; logPath: string } {
  const dir = mkdtempSync(join(tmpdir(), 'aps-sdk-sink-'));
  return { dir, logPath: join(dir, 'receipts.log') };
}

function buildPassport(rootHex: string): string {
  const now = Date.now();
  const issued = new Date(now - 30_000).toISOString();
  const expires = new Date(now + 30_000).toISOString();
  return JSON.stringify({
    type: 'aps.runtime_passport',
    version: '0.1',
    passport_id: 'rp_sinks_test000000000000000',
    agent_id: 'ag_sinks_test000000000000000',
    principal_id: 'pr_sinks_test000000000000000',
    beneficiary_id: 'bn_sinks_test000000000000000',
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
    verifier_instance_id: 'vi_sinks_test000000000000000',
    verifier_build_hash:
      'blake3:1111111111111111111111111111111111111111111111111111111111111111',
    session_id: 'sn_sinks_test000000000000000',
    sequence_start: 1000,
    sequence_end: 2000,
    budget_lease: {
      lease_id: 'bl_sinks_test000000000000000',
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
    receipt_stream_id: 'rs_sinks_test000000000000000',
    signature: 'ed25519:' + '0'.repeat(128),
  });
}

function freshHandle(sinkConfig: Parameters<typeof loadPassportUnverified>[2]) {
  const tools = [
    { descriptorHashHex: TOOL_DESCRIPTOR_HASH_HEX, localId: 0 },
  ];
  const rootHex = computeRegistryRoot(tools);
  const passportJson = buildPassport(rootHex);
  return loadPassportUnverified(passportJson, tools, sinkConfig);
}

function buildAllowAction(handle: ReturnType<typeof loadPassportUnverified>, seqId: bigint) {
  const info = authorityInfo(handle);
  return {
    version: 1,
    passportIdHashHex: info.passportIdHashHex,
    toolDescriptorHashHex: TOOL_DESCRIPTOR_HASH_HEX,
    localToolId: 0,
    operationId: 0,
    resourceType: 0,
    riskClass: 2,
    resourcePathDepth: 2,
    costUnits: 1,
    sequenceId: seqId,
    nonceHex: '00112233445566778899aabbccddeeff',
    resourcePathHashes: hashResourcePath(['customer', '12345']),
  };
}

// -----------------------------------------------------------------------
// Mode A
// -----------------------------------------------------------------------

test('Mode A: load + check + shutdown writes the durable log', () => {
  const { dir, logPath } = tmpLog();
  try {
    const handle = freshHandle({
      mode: SinkMode.ModeA,
      logPath,
      bufferCapacity: 256,
      flushIntervalMs: 25,
    });
    const decision = check(handle, buildAllowAction(handle, 1000n));
    assert.equal(decision.decisionType, 'Allow');
    shutdownAuthority(handle);
    const size = statSync(logPath).size;
    // Spec §11.4 entry size: 4 bytes length + 64-byte Decision +
    // 32-byte rolling_mac = 100 bytes.
    assert.equal(size, 100, `expected one 100-byte entry, got ${size}`);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

// -----------------------------------------------------------------------
// Mode B1 — blocking group-commit
// -----------------------------------------------------------------------

test('Mode B1: check blocks until fsync (>= ~window ms)', () => {
  const { dir, logPath } = tmpLog();
  try {
    const handle = freshHandle({
      mode: SinkMode.ModeB1,
      logPath,
      bufferCapacity: 64,
      maxBatchSize: 1024,    // size threshold won't fire (single emit)
      maxBatchWindowMs: 25,  // window dominates; check must wait ~25ms
    });
    const t0 = process.hrtime.bigint();
    const decision = check(handle, buildAllowAction(handle, 1000n));
    const elapsedMs = Number(process.hrtime.bigint() - t0) / 1_000_000;
    assert.equal(decision.decisionType, 'Allow');
    assert.ok(
      elapsedMs >= 15,
      `expected check to block at least ~15ms (window=25ms), got ${elapsedMs.toFixed(2)}ms`
    );
    shutdownAuthority(handle);
    assert.equal(statSync(logPath).size, 100);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

// -----------------------------------------------------------------------
// Mode B2 — queued group-commit
// -----------------------------------------------------------------------

test('Mode B2: check returns immediately (does not wait for fsync)', () => {
  const { dir, logPath } = tmpLog();
  try {
    const handle = freshHandle({
      mode: SinkMode.ModeB2,
      logPath,
      bufferCapacity: 64,
      maxBatchSize: 64,
      maxBatchWindowMs: 50, // wide window: B2 should still return fast
    });
    const t0 = process.hrtime.bigint();
    const decision = check(handle, buildAllowAction(handle, 1000n));
    const elapsedMs = Number(process.hrtime.bigint() - t0) / 1_000_000;
    assert.equal(decision.decisionType, 'Allow');
    assert.ok(
      elapsedMs < 15,
      `expected B2 check to return fast (< 15ms vs 50ms window), got ${elapsedMs.toFixed(2)}ms`
    );
    shutdownAuthority(handle);
    assert.equal(statSync(logPath).size, 100);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

// -----------------------------------------------------------------------
// shutdown_authority drains pending writes (Mode A)
// -----------------------------------------------------------------------

test('Mode A: shutdown_authority drains buffered writes', () => {
  const { dir, logPath } = tmpLog();
  try {
    const handle = freshHandle({
      mode: SinkMode.ModeA,
      logPath,
      bufferCapacity: 256,
      flushIntervalMs: 60_000, // never fires during the test
    });
    // 10 Allows in a row (incrementing seq_id matches authority.sequence_next).
    for (let i = 0; i < 10; i++) {
      const decision = check(handle, buildAllowAction(handle, 1000n + BigInt(i)));
      assert.equal(decision.decisionType, 'Allow', `iter ${i}: ${decision.reasonName}`);
    }
    // Nothing on disk yet (flushIntervalMs=60s, no background tick).
    let size = statSync(logPath).size;
    assert.equal(size, 0, `expected empty log before shutdown, got ${size} bytes`);
    shutdownAuthority(handle);
    // After shutdown: 10 entries × 100 bytes = 1000 bytes.
    size = statSync(logPath).size;
    assert.equal(size, 1000, `expected 1000-byte log after shutdown drain, got ${size}`);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

// -----------------------------------------------------------------------
// Sink mode required when not Null
// -----------------------------------------------------------------------

test('load_passport rejects Mode A without log_path', () => {
  assert.throws(
    () => freshHandle({ mode: SinkMode.ModeA }),
    /log_path required for Mode A/
  );
});

test('load_passport rejects Mode B1 without log_path', () => {
  assert.throws(
    () => freshHandle({ mode: SinkMode.ModeB1 }),
    /log_path required for Mode B1/
  );
});

test('load_passport rejects Mode B2 without log_path', () => {
  assert.throws(
    () => freshHandle({ mode: SinkMode.ModeB2 }),
    /log_path required for Mode B2/
  );
});
