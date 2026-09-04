// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { createPassport, signPassport, updatePassport, isExpired } from '../src/core/passport.js';
import { verifyPassport, createChallenge } from '../src/verification/verify.js';
import { generateKeyPair, sign, verify, publicKeyFromPrivate } from '../src/crypto/keys.js';
import { canonicalize } from '../src/core/canonical.js';
import { applyReputationEvent, calculateOverallScore } from '../src/verification/reputation.js';
import type { ReputationScore } from '../src/types/passport.js';

// These assert signature and validity-window handling, not authority, so
// each verifyPassport call names allowSelfSigned explicitly. Keeping the two
// questions separate is the point of the option.

describe('Crypto', () => {
  it('generates valid keypair', () => {
    const kp = generateKeyPair();
    assert.ok(kp.privateKey.length === 64);
    assert.ok(kp.publicKey.length === 64);
  });
  it('signs and verifies', () => {
    const kp = generateKeyPair();
    const sig = sign('test', kp.privateKey);
    assert.ok(verify('test', sig, kp.publicKey));
  });
  it('rejects tampered', () => {
    const kp = generateKeyPair();
    const sig = sign('original', kp.privateKey);
    assert.ok(!verify('tampered', sig, kp.publicKey));
  });
  it('rejects wrong key', () => {
    const k1 = generateKeyPair();
    const k2 = generateKeyPair();
    const sig = sign('test', k1.privateKey);
    assert.ok(!verify('test', sig, k2.publicKey));
  });
  it('derives pubkey', () => {
    const kp = generateKeyPair();
    assert.equal(publicKeyFromPrivate(kp.privateKey), kp.publicKey);
  });
});

describe('Canonical JSON', () => {
  it('sorts keys', () => {
    assert.equal(canonicalize({z:1,a:2}), canonicalize({a:2,z:1}));
  });
  it('omits null', () => {
    const r = canonicalize({a:1,b:null});
    assert.ok(!r.includes('null'));
  });
  it('nested', () => {
    assert.equal(
      canonicalize({b:{z:1,a:2},a:'first'}),
      '{"a":"first","b":{"a":2,"z":1}}'
    );
  });
});

describe('Passport', () => {
  it('creates valid', () => {
    const { signedPassport } = createPassport({
      agentId:'t-001', agentName:'T', ownerAlias:'o', mission:'m',
      capabilities:['code_execution'],
      runtime:{platform:'t',models:['m'],toolsCount:1,memoryType:'m'}
    });
    assert.ok(verifyPassport(signedPassport, { allowSelfSigned: true }).valid);
  });
  it('vote weight 1', () => {
    const { signedPassport } = createPassport({
      agentId:'t-002', agentName:'T', ownerAlias:'o', mission:'m',
      capabilities:['web_search'],
      runtime:{platform:'t',models:['m'],toolsCount:1,memoryType:'m'}
    });
    assert.equal(signedPassport.passport.voteWeight, 1);
  });
  it('rejects tampered', () => {
    const { signedPassport } = createPassport({
      agentId:'t-003', agentName:'T', ownerAlias:'o', mission:'m',
      capabilities:['web_search'],
      runtime:{platform:'t',models:['m'],toolsCount:1,memoryType:'m'}
    });
    signedPassport.passport.mission = 'HACKED';
    assert.ok(!verifyPassport(signedPassport, { allowSelfSigned: true }).valid);
  });
  it('updates and re-signs', () => {
    const { signedPassport, keyPair } = createPassport({
      agentId:'t-004', agentName:'T', ownerAlias:'o', mission:'orig',
      capabilities:['code_execution'],
      runtime:{platform:'t',models:['m'],toolsCount:1,memoryType:'m'}
    });
    const updated = updatePassport(signedPassport.passport, { mission:'new' }, keyPair.privateKey);
    assert.ok(verifyPassport(updated, { allowSelfSigned: true }).valid);
  });
});

describe('Reputation', () => {
  const base: ReputationScore = {
    overall:1, collaborationsCompleted:0, proposalsSubmitted:0,
    proposalsApproved:0, tokensContributed:0, tasksCompleted:0,
    lastUpdated:new Date().toISOString()
  };
  it('floor', () => {
    assert.ok(calculateOverallScore(base) >= 0.1);
  });
  it('increases', () => {
    let r = applyReputationEvent(base, {type:'collaboration_completed',quality:1});
    r = applyReputationEvent(r, {type:'task_completed',quality:1});
    assert.ok(calculateOverallScore(r) > calculateOverallScore(base));
  });
  it('caps at 10', () => {
    const max = {...base, collaborationsCompleted:100, proposalsApproved:50,
      tasksCompleted:200, tokensContributed:2e6};
    assert.ok(calculateOverallScore(max) <= 10);
  });
});
