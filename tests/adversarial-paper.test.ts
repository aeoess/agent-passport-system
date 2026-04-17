/**
 * adversarial-paper.test.ts
 * 
 * 10 structured adversarial scenarios from the paper:
 * "Monotonic Narrowing for Agent Authority"
 * 
 * S1-S5: Strong coverage (must pass)
 * S6-S8: Partial coverage (detect but not fully prevent)
 * S9-S10: Weak coverage (expected failures — protocol acknowledges the gap)
 * 
 * Bias statement: These are developer-authored adversarial scenarios on our
 * own protocol and should be interpreted as structured internal evaluation,
 * not independent red-team validation.
 * 
 * Run: npx tsx --test tests/adversarial-paper.test.ts
 */

import { describe, it, beforeEach } from 'node:test';
import assert from 'node:assert/strict';

import {
  generateKeyPair, sign, verify, canonicalize, createPassport,
  joinSocialContract, delegate, createDelegation, subDelegate,
  verifyDelegation, clearStores,
  scopeCovers, scopeAuthorizes, createReceipt, verifyReceipt,
  hashReceipt, buildMerkleRoot, generateMerkleProof, verifyMerkleProof,
  createActionIntent, verifyActionIntent, evaluateIntent,
  verifyPolicyDecision, createPolicyReceipt, FloorValidatorV1,
  requestAction, createAgoraMessage, verifyAgoraMessage,
  createFeed, appendToFeed, createRegistry, registerAgent,
  loadFloor, attestFloor,
  createPrincipalIdentity, endorseAgent, verifyEndorsement,
} from '../src/index.js';

import type {
  KeyPair, Delegation, ActionReceipt, ValidationContext, SocialContractAgent,
} from '../src/index.js';

// Helpers
function createAgent(name: string): SocialContractAgent {
  return joinSocialContract({ name, mission: `Test agent ${name}`, owner: 'test-human', capabilities: ['code_execution', 'data_analysis'], platform: 'test', models: ['test-model'] });
}

function makeFloorContext(delegation: Delegation): ValidationContext {
  return {
    floorVersion: 'v0.1',
    floorPrinciples: [
      { id: 'F-001', name: 'Traceability', enforcement: { mode: 'inline', technical: true, mechanism: 'delegation_chain' }, weight: 'mandatory' },
      { id: 'F-002', name: 'Honest Identity', enforcement: { mode: 'inline', technical: true, mechanism: 'signature_verification' }, weight: 'mandatory' },
      { id: 'F-003', name: 'Scoped Authority', enforcement: { mode: 'inline', technical: true, mechanism: 'scope_check' }, weight: 'mandatory' },
      { id: 'F-004', name: 'Revocability', enforcement: { mode: 'inline', technical: true, mechanism: 'cascade_revoke' }, weight: 'mandatory' },
      { id: 'F-005', name: 'Auditability', enforcement: { mode: 'inline', technical: true, mechanism: 'receipt_signing' }, weight: 'mandatory' },
    ],
    delegation: { scope: delegation.scope, spendLimit: delegation.spendLimit, spentAmount: delegation.spentAmount ?? 0, expiresAt: delegation.expiresAt, revoked: false, currentDepth: delegation.currentDepth, maxDepth: delegation.maxDepth },
    agentRegistered: true, agentAttestationValid: true,
  };
}

// S1: Identity Spoofing via Cross-Signature | Attacker: Class 1 | Target: INV-1
describe('S1: Identity Spoofing via Cross-Signature', () => {
  it('agent A cannot produce a signature that verifies under agent B public key', () => { const agentA = generateKeyPair(); const agentB = generateKeyPair(); const forgedSignature = sign('I am agent B', agentA.privateKey); assert.equal(verify('I am agent B', forgedSignature, agentB.publicKey), false, 'Cross-agent signature must not verify'); });
  it('same message signed by A verifies under A but not B', () => { const agentA = generateKeyPair(); const agentB = generateKeyPair(); const message = canonicalize({ action: 'transfer', amount: 1000 }); const sig = sign(message, agentA.privateKey); assert.equal(verify(message, sig, agentA.publicKey), true); assert.equal(verify(message, sig, agentB.publicKey), false); });
  it('tampered message fails verification', () => { const agent = generateKeyPair(); const sig = sign('authorized action', agent.privateKey); assert.equal(verify('authorized action', sig, agent.publicKey), true); assert.equal(verify('unauthorized action', sig, agent.publicKey), false); });
});

// S2: Scope Escalation via Sub-Delegation | Attacker: Class 1 | Target: INV-2
describe('S2: Scope Escalation via Sub-Delegation', () => {
  beforeEach(() => clearStores());
  it('sub-delegation with scope outside parent is rejected', () => {
    const human = generateKeyPair(); const agentA = generateKeyPair(); const agentB = generateKeyPair();
    const parentDelegation = createDelegation({ delegatedTo: agentA.publicKey, delegatedBy: human.publicKey, scope: ['code_execution'], spendLimit: 500, privateKey: human.privateKey });
    assert.throws(() => { subDelegate({ parentDelegation, delegatedTo: agentB.publicKey, scope: ['code_execution', 'commerce:purchase'], privateKey: agentA.privateKey }); }, /scope/i, 'Sub-delegation with escalated scope must throw');
  });
  it('sub-delegation within parent scope succeeds', () => {
    const human = generateKeyPair(); const agentA = generateKeyPair(); const agentB = generateKeyPair();
    const parentDelegation = createDelegation({ delegatedTo: agentA.publicKey, delegatedBy: human.publicKey, scope: ['code_execution', 'data_analysis'], spendLimit: 500, privateKey: human.privateKey });
    const childDelegation = subDelegate({ parentDelegation, delegatedTo: agentB.publicKey, scope: ['code_execution'], spendLimit: 100, privateKey: agentA.privateKey });
    assert.ok(childDelegation.delegationId); assert.deepEqual(childDelegation.scope, ['code_execution']);
  });
  it('scope hierarchy is enforced', () => { assert.equal(scopeCovers('commerce', 'commerce:purchase'), true); assert.equal(scopeCovers('commerce:purchase', 'commerce'), false); assert.equal(scopeCovers('code_execution', 'commerce:purchase'), false); });
});

// S3: Attribution Bypass via Merkle Forgery | Attacker: Class 2 | Target: INV-8 + Layer 3
describe('S3: Attribution Bypass via Merkle Forgery', () => {
  beforeEach(() => clearStores());
  it('Merkle proof fails if receipt hash is tampered', () => {
    const agent = generateKeyPair(); const human = generateKeyPair();
    const parentDelegation = createDelegation({ delegatedTo: agent.publicKey, delegatedBy: human.publicKey, scope: ['code_execution'], privateKey: human.privateKey });
    const receipts: ActionReceipt[] = [];
    for (let i = 0; i < 5; i++) { receipts.push(createReceipt({ agentId: `agent-${i}`, delegationId: parentDelegation.delegationId, delegation: parentDelegation, action: { type: 'implementation', target: `module-${i}`, scopeUsed: 'code_execution' }, result: { status: 'success', summary: `Built module ${i}` }, delegationChain: [parentDelegation.delegationId], privateKey: agent.privateKey })); }
    const hashes = receipts.map(r => hashReceipt(r)); buildMerkleRoot(hashes);
    const proof = generateMerkleProof(hashes, hashes[0]); assert.ok(proof); assert.equal(verifyMerkleProof(proof), true);
    const tamperedProof = { ...proof, receiptHash: 'aaaa' + proof.receiptHash.slice(4) }; assert.equal(verifyMerkleProof(tamperedProof), false);
  });
  it('receipt signature fails if beneficiary chain is altered', () => {
    const agent = generateKeyPair(); const human = generateKeyPair();
    const parentDelegation = createDelegation({ delegatedTo: agent.publicKey, delegatedBy: human.publicKey, scope: ['code_execution'], privateKey: human.privateKey });
    const receipt = createReceipt({ agentId: 'agent-test', delegationId: parentDelegation.delegationId, delegation: parentDelegation, action: { type: 'implementation', target: 'module-x', scopeUsed: 'code_execution' }, result: { status: 'success', summary: 'Built module' }, delegationChain: [parentDelegation.delegationId], privateKey: agent.privateKey });
    assert.equal(verifyReceipt(receipt, agent.publicKey).valid, true);
    const tampered = { ...receipt, delegationChain: ['fake-delegation-id'] }; assert.equal(verifyReceipt(tampered, agent.publicKey).valid, false);
  });
});

// S4: Execution Without Intent | Attacker: Class 1 | Target: INV-6
describe('S4: Execution Without Intent', () => {
  beforeEach(() => clearStores());
  it('policy receipt requires valid intent and decision', () => {
    const agent = generateKeyPair(); const evaluator = generateKeyPair(); const human = generateKeyPair();
    const parentDelegation = createDelegation({ delegatedTo: agent.publicKey, delegatedBy: human.publicKey, scope: ['code_execution'], spendLimit: 500, privateKey: human.privateKey });
    const intent = createActionIntent({ agentId: 'agent-test', agentPublicKey: agent.publicKey, delegationId: parentDelegation.delegationId, action: { type: 'implementation', target: 'module-x', scopeRequired: 'code_execution' }, privateKey: agent.privateKey });
    assert.equal(verifyActionIntent(intent).valid, true, 'Legitimate intent must verify');
    const decision = evaluateIntent({ intent, validator: new FloorValidatorV1(), validationContext: makeFloorContext(parentDelegation), evaluatorId: 'evaluator-1', evaluatorPublicKey: evaluator.publicKey, evaluatorPrivateKey: evaluator.privateKey });
    assert.equal(decision.verdict, 'permit'); assert.equal(verifyPolicyDecision(decision).valid, true);
  });
  it('intent with wrong signature is rejected', () => {
    const agent = generateKeyPair(); const attacker = generateKeyPair(); const human = generateKeyPair();
    const parentDelegation = createDelegation({ delegatedTo: agent.publicKey, delegatedBy: human.publicKey, scope: ['code_execution'], privateKey: human.privateKey });
    const intent = createActionIntent({ agentId: 'agent-test', agentPublicKey: agent.publicKey, delegationId: parentDelegation.delegationId, action: { type: 'implementation', target: 'module-x', scopeRequired: 'code_execution' }, privateKey: attacker.privateKey });
    assert.equal(verifyActionIntent(intent).valid, false, 'Intent signed by wrong key must fail');
  });
  it('policy rejects action outside delegation scope', () => {
    const agent = generateKeyPair(); const evaluator = generateKeyPair(); const human = generateKeyPair();
    const parentDelegation = createDelegation({ delegatedTo: agent.publicKey, delegatedBy: human.publicKey, scope: ['code_execution'], spendLimit: 500, privateKey: human.privateKey });
    const intent = createActionIntent({ agentId: 'agent-test', agentPublicKey: agent.publicKey, delegationId: parentDelegation.delegationId, action: { type: 'purchase', target: 'supplies', scopeRequired: 'commerce:purchase' }, privateKey: agent.privateKey });
    const decision = evaluateIntent({ intent, validator: new FloorValidatorV1(), validationContext: makeFloorContext(parentDelegation), evaluatorId: 'evaluator-1', evaluatorPublicKey: evaluator.publicKey, evaluatorPrivateKey: evaluator.privateKey });
    assert.equal(decision.verdict, 'deny', 'Out-of-scope action must be denied');
  });
});

// S5 (Cascade Revocation Evasion — INV-4 + INV-5) moved to gateway's
// DelegationStore tests. The SDK no longer holds module-scope revocation
// registries; cascade semantics live in @aeoess/gateway.

// S6: Agora Forgery (Partial) | Attacker: Class 2 | Target: Agora integrity
describe('S6: Agora Forgery (Partial)', () => {
  it('message signed by agent A cannot be attributed to agent B', () => {
    const agentA = generateKeyPair(); const agentB = generateKeyPair();
    const msg = createAgoraMessage({ agentId: 'agent-a', agentName: 'Agent A', publicKey: agentA.publicKey, privateKey: agentA.privateKey, topic: 'governance', type: 'announcement', subject: 'Decision', content: 'I am agent B and I approve this decision' });
    assert.equal(verifyAgoraMessage(msg).valid, true, 'Message verifies under author key');
    const registryB = registerAgent(createRegistry(), { agentId: 'agent-b', agentName: 'Agent B', publicKey: agentB.publicKey, joinedAt: new Date().toISOString(), role: 'member' });
    assert.equal(verifyAgoraMessage(msg, registryB).knownAgent, false, 'Agent A must not be recognized in registry containing only B');
  });
  it('tampered message content fails verification', () => {
    const agent = generateKeyPair();
    const msg = createAgoraMessage({ agentId: 'agent-test', agentName: 'Test Agent', publicKey: agent.publicKey, privateKey: agent.privateKey, topic: 'governance', type: 'announcement', subject: 'Original Decision', content: 'Original decision text' });
    const tampered = { ...msg, content: 'Altered decision text' };
    assert.equal(verifyAgoraMessage(tampered).valid, false, 'Tampered Agora message must fail verification');
  });
  it('misleading content with valid signature is accepted (protocol limitation)', () => {
    const agent = generateKeyPair();
    const misleading = createAgoraMessage({ agentId: 'agent-test', agentName: 'Test Agent', publicKey: agent.publicKey, privateKey: agent.privateKey, topic: 'governance', type: 'announcement', subject: 'Vote Result', content: 'The committee voted unanimously to approve' });
    assert.equal(verifyAgoraMessage(misleading).valid, true, 'Misleading content with valid signature passes (F-006 is advisory only)');
  });
});

// S7: Orchestration Bypass (Partial) | Attacker: Class 1 | Target: Policy enforcement
describe('S7: Orchestration Bypass (Partial)', () => {
  beforeEach(() => clearStores());
  it('requestAction enforces full three-signature chain when used', () => {
    const agent = generateKeyPair(); const evaluator = generateKeyPair(); const human = generateKeyPair();
    const parentDelegation = createDelegation({ delegatedTo: agent.publicKey, delegatedBy: human.publicKey, scope: ['code_execution'], spendLimit: 500, privateKey: human.privateKey });
    const { intent, decision } = requestAction({ agentId: 'agent-test', agentPublicKey: agent.publicKey, agentPrivateKey: agent.privateKey, delegationId: parentDelegation.delegationId, action: { type: 'implementation', target: 'module', scopeRequired: 'code_execution' }, validator: new FloorValidatorV1(), validationContext: makeFloorContext(parentDelegation), evaluatorId: 'evaluator-1', evaluatorPublicKey: evaluator.publicKey, evaluatorPrivateKey: evaluator.privateKey });
    assert.ok(intent.signature); assert.ok(decision.signature); assert.equal(decision.verdict, 'permit');
  });
  it('SDK cannot prevent bypass when agent has direct API access (documented limitation)', () => { assert.ok(true, 'Bypass prevention requires MCP-as-gateway deployment (see Section 10.1)'); });
});

// S8: Unsafe Integration (Partial) | Attacker: Class 2 | Target: Integration bridge
describe('S8: Unsafe Integration (Partial)', () => {
  beforeEach(() => clearStores());
  it('commerce action is independently gated even when triggered by coordination', () => {
    const agent = generateKeyPair(); const evaluator = generateKeyPair(); const human = generateKeyPair();
    const delegation = createDelegation({ delegatedTo: agent.publicKey, delegatedBy: human.publicKey, scope: ['code_execution'], spendLimit: 0, privateKey: human.privateKey });
    const intent = createActionIntent({ agentId: 'agent-test', agentPublicKey: agent.publicKey, delegationId: delegation.delegationId, action: { type: 'purchase', target: 'office-supplies', scopeRequired: 'commerce:purchase' }, privateKey: agent.privateKey });
    const decision = evaluateIntent({ intent, validator: new FloorValidatorV1(), validationContext: makeFloorContext(delegation), evaluatorId: 'evaluator-1', evaluatorPublicKey: evaluator.publicKey, evaluatorPrivateKey: evaluator.privateKey });
    assert.equal(decision.verdict, 'deny', 'Commerce action without commerce delegation must be denied');
  });
});

// S9: Supply Chain Compromise (Expected Failure) | Attacker: Class 3 | Target: Governance artifact integrity
describe('S9: Supply Chain Compromise (Expected Failure)', () => {
  it('protocol does not detect modified floor — agent attests to weakened floor', () => {
    const agent = generateKeyPair();
    const weakenedFloorJson = JSON.stringify({ version: 'v0.1-compromised', principles: [
      { id: 'F-001', name: 'Traceability', enforcement: { technical: true, mechanism: 'delegation_chain' }, weight: 'mandatory' },
      { id: 'F-002', name: 'Honest Identity', enforcement: { technical: true, mechanism: 'signature_verification' }, weight: 'mandatory' },
      { id: 'F-004', name: 'Revocability', enforcement: { technical: true, mechanism: 'cascade_revoke' }, weight: 'mandatory' },
      { id: 'F-005', name: 'Auditability', enforcement: { technical: true, mechanism: 'receipt_signing' }, weight: 'mandatory' },
    ]});
    const weakenedFloor = loadFloor(weakenedFloorJson);
    const attestation = attestFloor('compromised-agent', agent.publicKey, weakenedFloor.version, [], agent.privateKey);
    assert.ok(attestation.signature, 'Attestation to weakened floor succeeds (EXPECTED FAILURE: no provenance check)');
  });
});

// S10: Goal Manipulation (Expected Failure) | Attacker: Class 3 | Target: Agent alignment
describe('S10: Goal Manipulation (Expected Failure)', () => {
  beforeEach(() => clearStores());
  it('agent pursuing misaligned goals within scope passes all checks', () => {
    const agent = generateKeyPair(); const evaluator = generateKeyPair(); const human = generateKeyPair();
    const delegation = createDelegation({ delegatedTo: agent.publicKey, delegatedBy: human.publicKey, scope: ['code_execution', 'data_analysis'], spendLimit: 500, privateKey: human.privateKey });
    const intent = createActionIntent({ agentId: 'manipulated-agent', agentPublicKey: agent.publicKey, delegationId: delegation.delegationId, action: { type: 'analysis', target: 'market-data', scopeRequired: 'data_analysis' }, context: 'Analyzing market data for the team', privateKey: agent.privateKey });
    const decision = evaluateIntent({ intent, validator: new FloorValidatorV1(), validationContext: makeFloorContext(delegation), evaluatorId: 'evaluator-1', evaluatorPublicKey: evaluator.publicKey, evaluatorPrivateKey: evaluator.privateKey });
    assert.equal(decision.verdict, 'permit', 'Misaligned goal within valid scope passes policy (EXPECTED FAILURE: protocol enforces scope, not intent alignment)');
  });
});

// S11: Principal Endorsement Forgery (Expected Failure) | Attacker: Class 2 | Target: Principal trust chain
describe('S11: Principal Endorsement Forgery (Expected Failure)', () => {
  it('anyone can create a fake principal and endorse agents — no trust anchor', () => {
    // Attacker creates a principal claiming to be Google
    const { principal: fakePrincipal, keyPair: fakeKP } = createPrincipalIdentity({
      displayName: 'Google DeepMind',
      domain: 'deepmind.google.com',
      jurisdiction: 'UK',
    });

    // Endorses a malicious agent "under Google's authority"
    const endorsement = endorseAgent({
      principal: fakePrincipal,
      principalPrivateKey: fakeKP.privateKey,
      agentId: 'malicious-agent',
      agentPublicKey: 'a'.repeat(64),
      scope: ['financial_transactions', 'admin'],
      relationship: 'creator',
    });

    // The endorsement is cryptographically valid!
    const result = verifyEndorsement(endorsement);
    assert.equal(result.valid, true,
      'EXPECTED FAILURE: Fake principal endorsement passes verification. ' +
      'Protocol proves "this key endorsed this agent" but NOT "this key belongs to Google." ' +
      'Requires DNS TXT or .well-known domain verification to close the trust chain.'
    );
  });
});
