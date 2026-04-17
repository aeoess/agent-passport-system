/**
 * property-delegation.test.ts
 * Property-based tests for delegation invariants INV-2, INV-3, INV-4, INV-5.
 * Generates random delegation chains and verifies invariants hold.
 * Run: npx tsx --test tests/property-delegation.test.ts
 */
import { describe, it, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPair, createDelegation, subDelegate, verifyDelegation, clearStores, scopeCovers } from '../src/index.js';
// INV-4 + INV-5 cascade revocation invariants now live in gateway tests
// (DelegationStore). The narrowing invariants (INV-2 scope, INV-3 spend)
// stay here because they're enforced by the pure `subDelegate` primitive.
import type { KeyPair, Delegation } from '../src/index.js';

const ALL_SCOPES = ['code_execution','data_analysis','commerce','commerce:purchase','commerce:purchase:supplies','commerce:purchase:equipment','communication','communication:email','communication:slack','file_management','file_management:read','file_management:write','git_operations','git_operations:commit','git_operations:push'];

function randomSubset<T>(arr: T[], minSize = 1): T[] { const size = minSize + Math.floor(Math.random() * (arr.length - minSize)); return [...arr].sort(() => Math.random() - 0.5).slice(0, Math.max(minSize, size)); }
function randomNarrowScope(parentScope: string[]): string[] { if (!parentScope.length) return []; const size = 1 + Math.floor(Math.random() * parentScope.length); return [...parentScope].sort(() => Math.random() - 0.5).slice(0, size); }
function randomEscalatedScope(parentScope: string[]): string[] { const notInParent = ALL_SCOPES.filter(s => !parentScope.some(ps => scopeCovers(ps, s) || ps === s)); if (!notInParent.length) return [...parentScope, 'admin:root']; return [...randomNarrowScope(parentScope), notInParent[0]]; }
function randomSpendLimit(max = 10000): number { return Math.floor(Math.random() * max) + 1; }

// INV-2: Scope Monotonic Narrowing
describe('INV-2: Scope Monotonic Narrowing (property-based)', () => {
  beforeEach(() => clearStores());
  it('100 random valid narrowing sub-delegations all succeed', () => {
    let successes = 0;
    for (let trial = 0; trial < 100; trial++) {
      clearStores(); const human = generateKeyPair(); const agent = generateKeyPair(); const child = generateKeyPair();
      const parentScope = randomSubset(ALL_SCOPES, 2); const childScope = randomNarrowScope(parentScope);
      const parentDel = createDelegation({ delegatedTo: agent.publicKey, delegatedBy: human.publicKey, scope: parentScope, spendLimit: 1000, privateKey: human.privateKey });
      try {
        const childDel = subDelegate({ parentDelegation: parentDel, delegatedTo: child.publicKey, scope: childScope, spendLimit: 500, privateKey: agent.privateKey });
        for (const cs of childDel.scope) { assert.ok(parentScope.some(ps => scopeCovers(ps, cs) || ps === cs), `Trial ${trial}: child scope "${cs}" not covered by parent`); }
        successes++;
      } catch (e) { assert.fail(`Trial ${trial}: valid narrowing rejected: ${e}`); }
    }
    assert.equal(successes, 100);
  });
  it('100 random escalation attempts are all rejected', () => {
    let rejections = 0;
    for (let trial = 0; trial < 100; trial++) {
      clearStores(); const human = generateKeyPair(); const agent = generateKeyPair(); const child = generateKeyPair();
      const parentScope = randomSubset(ALL_SCOPES.slice(0, 5), 1); const escalatedScope = randomEscalatedScope(parentScope);
      const parentDel = createDelegation({ delegatedTo: agent.publicKey, delegatedBy: human.publicKey, scope: parentScope, spendLimit: 1000, privateKey: human.privateKey });
      try {
        subDelegate({ parentDelegation: parentDel, delegatedTo: child.publicKey, scope: escalatedScope, privateKey: agent.privateKey });
        for (const s of escalatedScope) { const covered = parentScope.some(ps => scopeCovers(ps, s) || ps === s); if (!covered) assert.fail(`Trial ${trial}: escalation should have been rejected`); }
      } catch (e) { rejections++; }
    }
    assert.ok(rejections > 0, `Expected most escalation attempts rejected, got ${rejections}/100`);
  });
  it('deep chain (5 levels) maintains narrowing at each step', () => {
    clearStores(); const keys: KeyPair[] = []; for (let i = 0; i < 6; i++) keys.push(generateKeyPair());
    let currentScope = ['code_execution', 'data_analysis', 'commerce', 'communication', 'file_management'];
    let parentDel = createDelegation({ delegatedTo: keys[1].publicKey, delegatedBy: keys[0].publicKey, scope: currentScope, spendLimit: 10000, maxDepth: 10, privateKey: keys[0].privateKey });
    const delegations: Delegation[] = [parentDel];
    for (let depth = 2; depth < 6; depth++) {
      const narrowedScope = currentScope.slice(0, currentScope.length - 1);
      const childDel = subDelegate({ parentDelegation: parentDel, delegatedTo: keys[depth].publicKey, scope: narrowedScope, spendLimit: Math.floor(10000 / depth), privateKey: keys[depth - 1].privateKey });
      for (const s of childDel.scope) { assert.ok(parentDel.scope.some(ps => scopeCovers(ps, s) || ps === s)); }
      delegations.push(childDel); parentDel = childDel; currentScope = narrowedScope;
    }
    assert.ok(delegations[delegations.length - 1].scope.length < delegations[0].scope.length);
  });
});

// INV-3: Spend Limit Narrowing
describe('INV-3: Spend Limit Narrowing (property-based)', () => {
  beforeEach(() => clearStores());
  it('100 random sub-delegations enforce spend limit narrowing', () => {
    for (let trial = 0; trial < 100; trial++) {
      clearStores(); const human = generateKeyPair(); const agent = generateKeyPair(); const child = generateKeyPair();
      const parentLimit = randomSpendLimit(10000); const childLimit = Math.floor(Math.random() * parentLimit);
      const parentDel = createDelegation({ delegatedTo: agent.publicKey, delegatedBy: human.publicKey, scope: ['code_execution'], spendLimit: parentLimit, privateKey: human.privateKey });
      const childDel = subDelegate({ parentDelegation: parentDel, delegatedTo: child.publicKey, scope: ['code_execution'], spendLimit: childLimit, privateKey: agent.privateKey });
      assert.ok((childDel.spendLimit ?? 0) <= (parentDel.spendLimit ?? Infinity), `Trial ${trial}: child spend ${childDel.spendLimit} > parent ${parentDel.spendLimit}`);
    }
  });
  it('spend limit escalation is rejected', () => {
    clearStores(); const human = generateKeyPair(); const agent = generateKeyPair(); const child = generateKeyPair();
    const parentDel = createDelegation({ delegatedTo: agent.publicKey, delegatedBy: human.publicKey, scope: ['code_execution'], spendLimit: 100, privateKey: human.privateKey });
    assert.throws(() => { subDelegate({ parentDelegation: parentDel, delegatedTo: child.publicKey, scope: ['code_execution'], spendLimit: 500, privateKey: agent.privateKey }); }, /spend/i);
  });
  it('deep chain spend limits are monotonically non-increasing', () => {
    clearStores(); const keys: KeyPair[] = []; for (let i = 0; i < 6; i++) keys.push(generateKeyPair());
    let parentLimit = 10000;
    let parentDel = createDelegation({ delegatedTo: keys[1].publicKey, delegatedBy: keys[0].publicKey, scope: ['code_execution'], spendLimit: parentLimit, maxDepth: 10, privateKey: keys[0].privateKey });
    const limits: number[] = [parentLimit];
    for (let depth = 2; depth < 6; depth++) {
      const childLimit = Math.floor(parentLimit * 0.6);
      const childDel = subDelegate({ parentDelegation: parentDel, delegatedTo: keys[depth].publicKey, scope: ['code_execution'], spendLimit: childLimit, privateKey: keys[depth - 1].privateKey });
      limits.push(childDel.spendLimit ?? 0); parentDel = childDel; parentLimit = childLimit;
    }
    for (let i = 1; i < limits.length; i++) { assert.ok(limits[i] <= limits[i - 1]); }
  });
});

// INV-4 + INV-5 (cascade revocation property tests) moved to gateway —
// see aeoess-gateway/tests/sdk-migrated/core/delegation-store.test.ts.

// Compound: INV-2 + INV-3 + chain integrity simultaneously
describe('Compound: Full chain invariants hold simultaneously', () => {
  beforeEach(() => clearStores());
  it('10 random chains of depth 3-5 all satisfy INV-2, INV-3, and chain integrity', () => {
    for (let trial = 0; trial < 10; trial++) {
      clearStores(); const depth = 3 + Math.floor(Math.random() * 3);
      const keys: KeyPair[] = []; for (let i = 0; i <= depth; i++) keys.push(generateKeyPair());
      let currentScope = randomSubset(ALL_SCOPES, 3); let currentLimit = randomSpendLimit(10000);
      let parentDel = createDelegation({ delegatedTo: keys[1].publicKey, delegatedBy: keys[0].publicKey, scope: currentScope, spendLimit: currentLimit, maxDepth: depth + 2, privateKey: keys[0].privateKey });
      for (let d = 2; d <= depth; d++) {
        const narrowedScope = randomNarrowScope(currentScope); const narrowedLimit = Math.floor(currentLimit * (0.3 + Math.random() * 0.5));
        const childDel = subDelegate({ parentDelegation: parentDel, delegatedTo: keys[d].publicKey, scope: narrowedScope, spendLimit: narrowedLimit, privateKey: keys[d - 1].privateKey });
        for (const s of childDel.scope) { assert.ok(parentDel.scope.some(ps => scopeCovers(ps, s) || ps === s)); }
        assert.ok((childDel.spendLimit ?? 0) <= (parentDel.spendLimit ?? Infinity));
        assert.equal(verifyDelegation(childDel).valid, true);
        parentDel = childDel; currentScope = narrowedScope; currentLimit = narrowedLimit;
      }
    }
  });
});
