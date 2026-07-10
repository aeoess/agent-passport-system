// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0
/**
 * delegation-currency-narrowing.test.ts
 * BUILD 1 (Track B candidate): currency narrowing at the delegation layer.
 * subDelegate rejects a child that changes spendLimitUnit (the spend "currency"
 * dimension). A declared conversion belongs at the payment-rails layer, not in
 * core subDelegate. These tests pin the new guard and confirm the existing
 * same-unit cap behavior is unchanged.
 * Run: npx tsx --test tests/delegation-currency-narrowing.test.ts
 */
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPair, createDelegation, subDelegate } from '../src/index.js';
import type { KeyPair, Delegation } from '../src/index.js';

function root(keyRoot: KeyPair, keyMid: KeyPair, unit: 'currency' | 'invocations' | undefined, limit: number): Delegation {
  return createDelegation({
    delegatedTo: keyMid.publicKey,
    delegatedBy: keyRoot.publicKey,
    scope: ['commerce'],
    spendLimit: limit,
    ...(unit ? { spendLimitUnit: unit } : {}),
    maxDepth: 2,
    currentDepth: 0,
    expiresInHours: 24,
    privateKey: keyRoot.privateKey,
  });
}

describe('BUILD 1: currency narrowing at subDelegate (locked Option A)', () => {
  it('rejects a child that changes the spend unit currency to invocations', () => {
    const r = generateKeyPair(), m = generateKeyPair(), leaf = generateKeyPair();
    const parent = root(r, m, 'currency', 500);
    assert.throws(
      () => subDelegate({ parentDelegation: parent, delegatedTo: leaf.publicKey, scope: ['commerce'], spendLimit: 100, spendLimitUnit: 'invocations', privateKey: m.privateKey }),
      /Spend unit change rejected at the narrowing layer/,
    );
  });

  it('rejects a child that changes the spend unit invocations to currency', () => {
    const r = generateKeyPair(), m = generateKeyPair(), leaf = generateKeyPair();
    const parent = root(r, m, 'invocations', 500);
    assert.throws(
      () => subDelegate({ parentDelegation: parent, delegatedTo: leaf.publicKey, scope: ['commerce'], spendLimit: 100, spendLimitUnit: 'currency', privateKey: m.privateKey }),
      /payment-rails layer \(v2 preAuthorize\)/,
    );
  });

  it('allows a same-unit child that tightens the cap (valid narrowing)', () => {
    const r = generateKeyPair(), m = generateKeyPair(), leaf = generateKeyPair();
    const parent = root(r, m, 'currency', 500);
    const child = subDelegate({ parentDelegation: parent, delegatedTo: leaf.publicKey, scope: ['commerce'], spendLimit: 300, spendLimitUnit: 'currency', privateKey: m.privateKey });
    assert.equal(child.spendLimit, 300);
    assert.equal(child.spendLimitUnit, 'currency');
  });

  it('preserves the existing same-unit cap rejection (child raises the cap)', () => {
    const r = generateKeyPair(), m = generateKeyPair(), leaf = generateKeyPair();
    const parent = root(r, m, 'currency', 500);
    assert.throws(
      () => subDelegate({ parentDelegation: parent, delegatedTo: leaf.publicKey, scope: ['commerce'], spendLimit: 1000, spendLimitUnit: 'currency', privateKey: m.privateKey }),
      /exceeds parent remaining/,
    );
  });

  it('does not fire when the child omits spendLimitUnit (inherits the parent unit)', () => {
    const r = generateKeyPair(), m = generateKeyPair(), leaf = generateKeyPair();
    const parent = root(r, m, 'currency', 500);
    const child = subDelegate({ parentDelegation: parent, delegatedTo: leaf.publicKey, scope: ['commerce'], spendLimit: 200, privateKey: m.privateKey });
    assert.equal(child.spendLimit, 200);
  });

  it('does not fire when the parent uses the default unit and the child sets the same unit explicitly', () => {
    const r = generateKeyPair(), m = generateKeyPair(), leaf = generateKeyPair();
    const parent = root(r, m, undefined, 500); // parent omits unit, defaults to currency
    const child = subDelegate({ parentDelegation: parent, delegatedTo: leaf.publicKey, scope: ['commerce'], spendLimit: 250, spendLimitUnit: 'currency', privateKey: m.privateKey });
    assert.equal(child.spendLimit, 250);
  });

  // Unitless-parent boundary cases (a child may introduce a unit only when the parent has no spend dimension).
  it('allows an unconstrained parent (no spend dimension) to receive a child that introduces a unit', () => {
    const r = generateKeyPair(), m = generateKeyPair(), leaf = generateKeyPair();
    const parent = createDelegation({
      delegatedTo: m.publicKey, delegatedBy: r.publicKey, scope: ['commerce'],
      maxDepth: 3, currentDepth: 0, expiresInHours: 24, privateKey: r.privateKey,
    });
    const child = subDelegate({ parentDelegation: parent, delegatedTo: leaf.publicKey, scope: ['commerce'], spendLimit: 100, spendLimitUnit: 'invocations', privateKey: m.privateKey });
    assert.equal(child.spendLimit, 100);
    assert.equal(child.spendLimitUnit, 'invocations');
  });

  it('rejects a unit change when the parent has a spend limit but omitted the unit (defaults to currency)', () => {
    const r = generateKeyPair(), m = generateKeyPair(), leaf = generateKeyPair();
    const parent = root(r, m, undefined, 500); // finite limit, no explicit unit, resolves to currency
    assert.throws(
      () => subDelegate({ parentDelegation: parent, delegatedTo: leaf.publicKey, scope: ['commerce'], spendLimit: 50, spendLimitUnit: 'invocations', privateKey: m.privateKey }),
      /Spend unit change rejected at the narrowing layer/,
    );
  });

  it('pins the spend unit once introduced: a 3-hop chain cannot switch units downstream', () => {
    const r = generateKeyPair(), m = generateKeyPair(), n = generateKeyPair(), leaf = generateKeyPair();
    const top = createDelegation({
      delegatedTo: m.publicKey, delegatedBy: r.publicKey, scope: ['commerce'],
      maxDepth: 5, currentDepth: 0, expiresInHours: 24, privateKey: r.privateKey,
    });
    const mid = subDelegate({ parentDelegation: top, delegatedTo: n.publicKey, scope: ['commerce'], spendLimit: 100, spendLimitUnit: 'invocations', privateKey: m.privateKey });
    assert.equal(mid.spendLimitUnit, 'invocations');
    assert.throws(
      () => subDelegate({ parentDelegation: mid, delegatedTo: leaf.publicKey, scope: ['commerce'], spendLimit: 50, spendLimitUnit: 'currency', privateKey: n.privateKey }),
      /Spend unit change rejected at the narrowing layer/,
    );
  });
});
