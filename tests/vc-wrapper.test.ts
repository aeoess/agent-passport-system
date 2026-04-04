import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPair, publicKeyFromPrivate } from '../src/crypto/keys.js';
import { toDIDKey } from '../src/core/did-interop.js';
import { importSPIFFESVID } from '../src/core/identity-bridge.js';
import {
  passportToVerifiableCredential,
  verifyVerifiableCredential,
  createVerifiablePresentation,
  verifyVerifiablePresentation,
} from '../src/core/vc-wrapper.js';

function makePassport(overrides?: Record<string, unknown>) {
  const kp = generateKeyPair();
  return {
    input: {
      agentId: 'agent-test-vc-001',
      publicKey: kp.publicKey,
      agentName: 'Test Agent',
      mission: 'VC wrapper testing',
      capabilities: ['research', 'analysis'],
      grade: 2,
      delegationScope: ['data_read', 'data_write'],
      createdAt: '2026-01-01T00:00:00.000Z',
      expiresAt: '2027-01-01T00:00:00.000Z',
      ...overrides,
    },
    keyPair: kp,
  };
}

describe('passportToVerifiableCredential', () => {
  it('produces a valid VC with did:key subject', async () => {
    const issuer = generateKeyPair();
    const { input } = makePassport();
    const vc = await passportToVerifiableCredential(input, issuer.privateKey);

    assert.ok(vc['@context'].includes('https://www.w3.org/ns/credentials/v2'));
    assert.deepEqual(vc.type, ['VerifiableCredential', 'AgentPassportCredential']);
    assert.ok((vc.issuer as string).startsWith('did:key:z6Mk'));

    const subject = vc.credentialSubject as Record<string, unknown>;
    assert.ok((subject.id as string).startsWith('did:key:z6Mk'));
    assert.equal(subject.agentId, 'agent-test-vc-001');
    assert.equal(subject.grade, 2);
    assert.deepEqual(subject.delegationScope, ['data_read', 'data_write']);
    assert.deepEqual(subject.capabilities, ['research', 'analysis']);
  });

  it('includes publicKey as did:key in credentialSubject', async () => {
    const issuer = generateKeyPair();
    const { input } = makePassport();
    const vc = await passportToVerifiableCredential(input, issuer.privateKey);
    const subject = vc.credentialSubject as Record<string, unknown>;
    const expectedDIDKey = toDIDKey(input.publicKey);
    assert.equal(subject.publicKey, expectedDIDKey);
  });

  it('sets issuanceDate and expirationDate from passport', async () => {
    const issuer = generateKeyPair();
    const { input } = makePassport();
    const vc = await passportToVerifiableCredential(input, issuer.privateKey);
    assert.equal(vc.issuanceDate, '2026-01-01T00:00:00.000Z');
    assert.equal(vc.expirationDate, '2027-01-01T00:00:00.000Z');
  });

  it('attaches SPIFFE evidence when provided', async () => {
    const issuer = generateKeyPair();
    const spiffeAtt = importSPIFFESVID({
      spiffeId: 'spiffe://cluster.example.com/ns/prod/sa/agent',
      expiresAt: '2026-12-31T23:59:59.000Z',
    });
    const { input } = makePassport({ evidence: [spiffeAtt] });
    const vc = await passportToVerifiableCredential(input, issuer.privateKey);

    const cred = vc as Record<string, unknown>;
    assert.ok(Array.isArray(cred.evidence));
    const evidence = (cred.evidence as any[])[0];
    assert.equal(evidence.type, 'InfrastructureAttestation');
    assert.equal(evidence.provider, 'cluster.example.com');
    assert.equal(evidence.subjectClass, 'workload');
  });

  it('omits evidence when none provided', async () => {
    const issuer = generateKeyPair();
    const { input } = makePassport();
    const vc = await passportToVerifiableCredential(input, issuer.privateKey);
    assert.equal((vc as any).evidence, undefined);
  });

  it('proof uses did:key verification method', async () => {
    const issuer = generateKeyPair();
    const { input } = makePassport();
    const vc = await passportToVerifiableCredential(input, issuer.privateKey);
    assert.ok(vc.proof.verificationMethod.startsWith('did:key:z6Mk'));
    assert.ok(vc.proof.verificationMethod.endsWith('#key-1'));
    assert.equal(vc.proof.type, 'Ed25519Signature2020');
    assert.equal(vc.proof.proofPurpose, 'assertionMethod');
  });
});

describe('verifyVerifiableCredential', () => {
  it('verifies a valid VC', async () => {
    const issuer = generateKeyPair();
    const { input } = makePassport();
    const vc = await passportToVerifiableCredential(input, issuer.privateKey);
    const result = await verifyVerifiableCredential(vc);

    assert.equal(result.valid, true);
    assert.ok(result.checks.some(c => c.includes('PASS: Ed25519 signature valid')));
    assert.ok(result.checks.some(c => c.includes('PASS: required fields present')));
    assert.ok(result.checks.some(c => c.includes('PASS: credential not expired')));
  });

  it('detects tampered credentialSubject', async () => {
    const issuer = generateKeyPair();
    const { input } = makePassport();
    const vc = await passportToVerifiableCredential(input, issuer.privateKey);

    // Tamper
    (vc.credentialSubject as any).grade = 3;
    const result = await verifyVerifiableCredential(vc);
    assert.equal(result.valid, false);
    assert.ok(result.checks.some(c => c.includes('FAIL') && c.includes('signature')));
  });

  it('detects tampered issuer', async () => {
    const issuer = generateKeyPair();
    const other = generateKeyPair();
    const { input } = makePassport();
    const vc = await passportToVerifiableCredential(input, issuer.privateKey);

    // Replace issuer DID (signature won't match)
    (vc as any).issuer = toDIDKey(other.publicKey);
    const result = await verifyVerifiableCredential(vc);
    assert.equal(result.valid, false);
  });

  it('detects expired credential', async () => {
    const issuer = generateKeyPair();
    const { input } = makePassport({ expiresAt: '2020-01-01T00:00:00.000Z' });
    const vc = await passportToVerifiableCredential(input, issuer.privateKey);
    const result = await verifyVerifiableCredential(vc);

    assert.equal(result.valid, false);
    assert.ok(result.checks.some(c => c.includes('FAIL: credential expired')));
  });

  it('reports evidence count in checks', async () => {
    const issuer = generateKeyPair();
    const att = importSPIFFESVID({
      spiffeId: 'spiffe://prod.io/ns/default/sa/agent',
      expiresAt: '2026-12-31T00:00:00.000Z',
    });
    const { input } = makePassport({ evidence: [att] });
    const vc = await passportToVerifiableCredential(input, issuer.privateKey);
    const result = await verifyVerifiableCredential(vc);
    assert.ok(result.checks.some(c => c.includes('1 evidence attachment(s) present')));
  });

  it('rejects VC with missing proof', async () => {
    const vc = {
      '@context': ['https://www.w3.org/ns/credentials/v2'],
      id: 'urn:test',
      type: ['VerifiableCredential'],
      issuer: 'did:key:z6Mk123',
      issuanceDate: new Date().toISOString(),
      credentialSubject: { id: 'test' },
    } as any;
    const result = await verifyVerifiableCredential(vc);
    assert.equal(result.valid, false);
    assert.ok(result.checks.some(c => c.includes('missing required VC fields')));
  });
});

describe('createVerifiablePresentation', () => {
  it('wraps credentials into a VP with did:key holder', async () => {
    const issuer = generateKeyPair();
    const holder = generateKeyPair();
    const { input } = makePassport({ publicKey: holder.publicKey });
    const vc = await passportToVerifiableCredential(input, issuer.privateKey);

    const vp = await createVerifiablePresentation([vc], holder.privateKey);

    assert.deepEqual(vp.type, ['VerifiablePresentation']);
    assert.ok(vp.holder.startsWith('did:key:z6Mk'));
    assert.equal(vp.holder, toDIDKey(holder.publicKey));
    assert.equal(vp.verifiableCredential.length, 1);
    assert.ok(vp.proof.verificationMethod.startsWith('did:key:'));
    assert.equal(vp.proof.proofPurpose, 'authentication');
  });

  it('includes challenge and domain for replay protection', async () => {
    const issuer = generateKeyPair();
    const holder = generateKeyPair();
    const { input } = makePassport({ publicKey: holder.publicKey });
    const vc = await passportToVerifiableCredential(input, issuer.privateKey);

    const vp = await createVerifiablePresentation([vc], holder.privateKey, {
      challenge: 'nonce-abc-123',
      domain: 'verifier.example.com',
    });

    const proof = vp.proof as any;
    assert.equal(proof.challenge, 'nonce-abc-123');
    assert.equal(proof.domain, 'verifier.example.com');
  });

  it('supports multiple credentials', async () => {
    const issuer = generateKeyPair();
    const holder = generateKeyPair();
    const p1 = makePassport({ publicKey: holder.publicKey, agentId: 'agent-1' });
    const p2 = makePassport({ publicKey: holder.publicKey, agentId: 'agent-2' });
    const vc1 = await passportToVerifiableCredential(p1.input, issuer.privateKey);
    const vc2 = await passportToVerifiableCredential(p2.input, issuer.privateKey);

    const vp = await createVerifiablePresentation([vc1, vc2], holder.privateKey);
    assert.equal(vp.verifiableCredential.length, 2);
  });
});

describe('verifyVerifiablePresentation', () => {
  it('verifies a valid VP with valid credentials', async () => {
    const issuer = generateKeyPair();
    const holder = generateKeyPair();
    const { input } = makePassport({ publicKey: holder.publicKey });
    const vc = await passportToVerifiableCredential(input, issuer.privateKey);
    const vp = await createVerifiablePresentation([vc], holder.privateKey);

    const result = await verifyVerifiablePresentation(vp);

    assert.equal(result.valid, true);
    assert.equal(result.credentials.length, 1);
    assert.ok(result.checks.some(c => c.includes('PASS: presentation signature valid')));
    assert.ok(result.checks.some(c => c.includes('PASS: credential[0]') && c.includes('verified')));
  });

  it('detects tampered VP proof', async () => {
    const issuer = generateKeyPair();
    const holder = generateKeyPair();
    const { input } = makePassport({ publicKey: holder.publicKey });
    const vc = await passportToVerifiableCredential(input, issuer.privateKey);
    const vp = await createVerifiablePresentation([vc], holder.privateKey);

    // Tamper with holder
    (vp as any).holder = toDIDKey(issuer.publicKey);
    const result = await verifyVerifiablePresentation(vp);
    assert.equal(result.valid, false);
    assert.ok(result.checks.some(c => c.includes('FAIL') && c.includes('presentation signature')));
  });

  it('detects tampered credential inside VP', async () => {
    const issuer = generateKeyPair();
    const holder = generateKeyPair();
    const { input } = makePassport({ publicKey: holder.publicKey });
    const vc = await passportToVerifiableCredential(input, issuer.privateKey);

    // Tamper with credential before wrapping
    (vc.credentialSubject as any).grade = 99;

    // Re-create VP with tampered VC (VP signature is over the tampered content, so VP proof is valid)
    const vp = await createVerifiablePresentation([vc], holder.privateKey);
    const result = await verifyVerifiablePresentation(vp);

    assert.equal(result.valid, false);
    assert.ok(result.checks.some(c => c.includes('FAIL: credential[0]')));
  });

  it('verifies VP with multiple credentials', async () => {
    const issuer = generateKeyPair();
    const holder = generateKeyPair();
    const p1 = makePassport({ publicKey: holder.publicKey, agentId: 'multi-1' });
    const p2 = makePassport({ publicKey: holder.publicKey, agentId: 'multi-2' });
    const vc1 = await passportToVerifiableCredential(p1.input, issuer.privateKey);
    const vc2 = await passportToVerifiableCredential(p2.input, issuer.privateKey);
    const vp = await createVerifiablePresentation([vc1, vc2], holder.privateKey);

    const result = await verifyVerifiablePresentation(vp);
    assert.equal(result.valid, true);
    assert.equal(result.credentials.length, 2);
    assert.ok(result.checks.some(c => c.includes('credential[0]') && c.includes('verified')));
    assert.ok(result.checks.some(c => c.includes('credential[1]') && c.includes('verified')));
  });

  it('rejects VP with missing proof', async () => {
    const vp = {
      '@context': ['https://www.w3.org/ns/credentials/v2'],
      type: ['VerifiablePresentation'],
      holder: 'did:key:z6Mk123',
      verifiableCredential: [],
    } as any;
    const result = await verifyVerifiablePresentation(vp);
    assert.equal(result.valid, false);
    assert.ok(result.checks.some(c => c.includes('missing required VP fields')));
  });
});

describe('round-trip: passport → VC → VP → verify', () => {
  it('full pipeline with SPIFFE evidence', async () => {
    const issuer = generateKeyPair();
    const holder = generateKeyPair();

    // 1. SPIFFE attestation
    const spiffeAtt = importSPIFFESVID({
      spiffeId: 'spiffe://prod.cluster.io/ns/default/sa/trading-agent',
      expiresAt: '2026-12-31T23:59:59.000Z',
    });

    // 2. Passport → VC with SPIFFE evidence + did:key
    const vc = await passportToVerifiableCredential({
      agentId: 'agent-spiffe-roundtrip',
      publicKey: holder.publicKey,
      agentName: 'SPIFFE Trading Agent',
      mission: 'Execute trades within risk limits',
      capabilities: ['trade', 'research'],
      grade: 2,
      delegationScope: ['data_read', 'commerce'],
      createdAt: '2026-01-01T00:00:00.000Z',
      expiresAt: '2027-01-01T00:00:00.000Z',
      evidence: [spiffeAtt],
    }, issuer.privateKey);

    // 3. Verify VC independently
    const vcResult = await verifyVerifiableCredential(vc);
    assert.equal(vcResult.valid, true);

    // 4. Wrap in VP
    const vp = await createVerifiablePresentation([vc], holder.privateKey, {
      challenge: 'challenge-xyz',
      domain: 'gateway.aeoess.com',
    });

    // 5. Verify VP
    const vpResult = await verifyVerifiablePresentation(vp);
    assert.equal(vpResult.valid, true);
    assert.equal(vpResult.credentials.length, 1);

    // 6. Verify the credential subject has all interop fields
    const subject = vpResult.credentials[0].credentialSubject as Record<string, unknown>;
    assert.equal(subject.grade, 2);
    assert.deepEqual(subject.delegationScope, ['data_read', 'commerce']);
    assert.ok((subject.publicKey as string).startsWith('did:key:z6Mk'));

    // 7. Verify evidence survived the round-trip
    const cred = vpResult.credentials[0] as any;
    assert.equal(cred.evidence[0].provider, 'prod.cluster.io');
  });
});
