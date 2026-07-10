// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0
/**
 * delegation-temporal-narrowing.test.ts
 * Temporal narrowing at the delegation layer.
 *
 * The hard invariant: for any delegation D with parent P,
 *   Date.parse(D.expiresAt) <= Date.parse(P.expiresAt), to the millisecond,
 * at arbitrary depth. A child may never outlive its parent.
 *
 * Creation-time enforcement only (matching the current SDK narrowing model):
 * subDelegate caps the child's ABSOLUTE expiresAt at min(now + 24h, parent
 * expiry) and rejects sub-delegation from an expired or malformed-expiry parent.
 * createDelegation computes expiresAt with millisecond math (no setHours
 * truncation, no `|| 24` zero-coercion) and honors a direct expiresAt option.
 *
 * Run: npx tsx --test tests/delegation-temporal-narrowing.test.ts
 */
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPair, createDelegation, subDelegate } from '../src/index.js';
import type { KeyPair, Delegation } from '../src/index.js';

const HOUR_MS = 3600000;

/** Create a root delegation with an explicit window and depth headroom. */
function rootWithWindow(keyRoot: KeyPair, keyMid: KeyPair, expiresInHours: number, maxDepth = 5): Delegation {
  return createDelegation({
    delegatedTo: keyMid.publicKey,
    delegatedBy: keyRoot.publicKey,
    scope: ['commerce'],
    maxDepth,
    currentDepth: 0,
    expiresInHours,
    privateKey: keyRoot.privateKey,
  });
}

const ms = (iso: string) => Date.parse(iso);

describe('temporal narrowing: createDelegation expiry math', () => {
  // Vector 1: `|| 24` must not coerce 0 into 24h; 0 means immediate expiry.
  it('createDelegation({ expiresInHours: 0 }) yields immediate expiry, not 24h', () => {
    const r = generateKeyPair(), m = generateKeyPair();
    const d = createDelegation({
      delegatedTo: m.publicKey, delegatedBy: r.publicKey, scope: ['commerce'],
      maxDepth: 1, currentDepth: 0, expiresInHours: 0, privateKey: r.privateKey,
    });
    // Immediate: expiresAt equals createdAt (both derived from one creation instant).
    assert.equal(d.expiresAt, d.createdAt);
  });

  // Vector 2: fractional hours survive (no setHours integer truncation).
  it('createDelegation({ expiresInHours: 0.25 }) yields ~15 minutes (tight tolerance)', () => {
    const r = generateKeyPair(), m = generateKeyPair();
    const d = createDelegation({
      delegatedTo: m.publicKey, delegatedBy: r.publicKey, scope: ['commerce'],
      maxDepth: 1, currentDepth: 0, expiresInHours: 0.25, privateKey: r.privateKey,
    });
    const delta = ms(d.expiresAt) - ms(d.createdAt);
    assert.ok(Math.abs(delta - 900000) <= 2, `expected ~900000ms, got ${delta}`);
  });

  // Vector 9: the normal default path is intact.
  it('createDelegation with expiresInHours omitted yields the 24h default', () => {
    const r = generateKeyPair(), m = generateKeyPair();
    const d = createDelegation({
      delegatedTo: m.publicKey, delegatedBy: r.publicKey, scope: ['commerce'],
      maxDepth: 1, currentDepth: 0, privateKey: r.privateKey,
    });
    const delta = ms(d.expiresAt) - ms(d.createdAt);
    assert.ok(Math.abs(delta - 24 * HOUR_MS) < 60000, `expected ~24h, got ${delta}ms`);
  });
});

describe('temporal narrowing: subDelegate caps and rejects', () => {
  // Vector 3: an expired parent cannot sub-delegate (reject, do not emit a child).
  it('subDelegate from an expired parent throws', () => {
    const r = generateKeyPair(), m = generateKeyPair(), leaf = generateKeyPair();
    const parent = rootWithWindow(r, m, -1); // expired one hour ago
    assert.throws(
      () => subDelegate({ parentDelegation: parent, delegatedTo: leaf.publicKey, scope: ['commerce'], privateKey: m.privateKey }),
      /expired parent/,
    );
  });

  // Vector 4: a malformed parent expiry is caught by the finite guard, not a RangeError.
  it('subDelegate from a parent with garbage expiresAt throws the finite-guard error', () => {
    const r = generateKeyPair(), m = generateKeyPair(), leaf = generateKeyPair();
    const good = rootWithWindow(r, m, 24);
    const bad = { ...good, expiresAt: 'not-a-date' }; // spread defeats the freeze; other fields stay valid
    assert.throws(
      () => subDelegate({ parentDelegation: bad, delegatedTo: leaf.publicKey, scope: ['commerce'], privateKey: m.privateKey }),
      /invalid expiresAt/,
    );
  });

  // Vector 5: a sub-hour parent still narrows correctly (child never outlives parent).
  it('subDelegate from a parent with under one hour remaining yields child.expiresAt <= parent.expiresAt', () => {
    const r = generateKeyPair(), m = generateKeyPair(), leaf = generateKeyPair();
    const parent = rootWithWindow(r, m, 0.5); // 30 minutes
    const child = subDelegate({ parentDelegation: parent, delegatedTo: leaf.publicKey, scope: ['commerce'], privateKey: m.privateKey });
    assert.ok(ms(child.expiresAt) <= ms(parent.expiresAt), `child ${child.expiresAt} > parent ${parent.expiresAt}`);
  });

  // Vector 6: when the parent (< 24h) is the binding cap, child.expiresAt EQUALS parent.expiresAt exactly.
  // A fractional sub-hour window so the defect bites deterministically pre-fix: a whole-hour window is
  // only flaky-red (it passes whenever parent and child are minted in the same millisecond, which is
  // most of the time). 0.75h forces the setHours truncation, so the boundary is a non-vacuous vector.
  it('child.expiresAt equals parent.expiresAt exactly when the parent is the binding cap', () => {
    const r = generateKeyPair(), m = generateKeyPair(), leaf = generateKeyPair();
    const parent = rootWithWindow(r, m, 0.75); // 45 minutes remaining, well under the 24h ceiling
    const child = subDelegate({ parentDelegation: parent, delegatedTo: leaf.publicKey, scope: ['commerce'], privateKey: m.privateKey });
    assert.equal(child.expiresAt, parent.expiresAt);
  });

  // Vector 7: the compute-gap vector: every descendant <= its ancestor, to the ms, over 3 hops.
  it('a 3-hop sub-hour chain keeps every descendant expiresAt <= its ancestor (to the ms)', () => {
    const r = generateKeyPair(), m = generateKeyPair(), a = generateKeyPair(), b = generateKeyPair(), c = generateKeyPair();
    const root = rootWithWindow(r, m, 0.5, 5); // 30 minutes, depth headroom for 3 hops
    const h1 = subDelegate({ parentDelegation: root, delegatedTo: a.publicKey, scope: ['commerce'], privateKey: m.privateKey });
    const h2 = subDelegate({ parentDelegation: h1, delegatedTo: b.publicKey, scope: ['commerce'], privateKey: a.privateKey });
    const h3 = subDelegate({ parentDelegation: h2, delegatedTo: c.publicKey, scope: ['commerce'], privateKey: b.privateKey });
    // Each hop against its actual parent's expiresAt, never now+duration.
    assert.ok(ms(h1.expiresAt) <= ms(root.expiresAt), 'h1 > root');
    assert.ok(ms(h2.expiresAt) <= ms(h1.expiresAt), 'h2 > h1');
    assert.ok(ms(h3.expiresAt) <= ms(h2.expiresAt), 'h3 > h2');
    // Transitive invariant against the root.
    assert.ok(ms(h3.expiresAt) <= ms(root.expiresAt), 'h3 > root (transitive)');
  });

  // Vector 8: signed-payload consistency: expiresAt present, no relative-duration claim.
  it('a capped sub-delegated child carries expiresAt and no relative-duration field', () => {
    const r = generateKeyPair(), m = generateKeyPair(), leaf = generateKeyPair();
    const parent = rootWithWindow(r, m, 0.5);
    const child = subDelegate({ parentDelegation: parent, delegatedTo: leaf.publicKey, scope: ['commerce'], privateKey: m.privateKey });
    assert.ok('expiresAt' in child, 'signed child must carry expiresAt');
    assert.ok(!('expiresInHours' in child), 'signed child must not carry expiresInHours');
    // No other top-level relative-duration claim slipped into the signed object.
    const relative = Object.keys(child).filter(k => /^(expiresIn|ttl|maxAge|duration)$/i.test(k));
    assert.deepEqual(relative, [], `unexpected relative-duration field(s): ${relative}`);
  });

  // Vector 10: a healthy parent still sub-delegates (no BUILD-1-style over-rejection).
  it('a parent with positive remaining time still sub-delegates successfully', () => {
    const r = generateKeyPair(), m = generateKeyPair(), leaf = generateKeyPair();
    const parent = rootWithWindow(r, m, 24);
    const child = subDelegate({ parentDelegation: parent, delegatedTo: leaf.publicKey, scope: ['commerce'], privateKey: m.privateKey });
    assert.ok(ms(child.expiresAt) <= ms(parent.expiresAt), 'child outlived parent');
    assert.ok(ms(child.expiresAt) > Date.now(), 'child should have a positive remaining window');
  });
});
