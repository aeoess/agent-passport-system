import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPair, publicKeyFromPrivate } from '../src/crypto/keys.js';
import { createDelegation, verifyDelegation } from '../src/core/delegation.js';

// DID interop
import { toDIDKey, fromDIDKey, passportToDIDDocument } from '../src/core/did-interop.js';

// Identity bridge
import {
  parseSPIFFEID, importSPIFFESVID,
  importOAuthToken, mapOAuthScopes,
} from '../src/core/identity-bridge.js';

// VC wrapper
import {
  passportToVerifiableCredential,
  verifyVerifiableCredential,
  createVerifiablePresentation,
  verifyVerifiablePresentation,
} from '../src/core/vc-wrapper.js';

// Credential request protocol
import {
  createCredentialRequest,
  fulfillCredentialRequest,
  verifyCredentialResponse,
} from '../src/core/credential-request.js';

// ═══ Credential Request Protocol Unit Tests ═══

describe('Credential Request Protocol', () => {

  describe('createCredentialRequest', () => {
    it('creates a request with requested claims and challenge', () => {
      const req = createCredentialRequest(
        ['grade', 'capabilities'],
        'did:key:z6MkVerifier',
        'challenge-123',
      );
      assert.deepEqual(req.requestedClaims, ['grade', 'capabilities']);
      assert.equal(req.verifierDID, 'did:key:z6MkVerifier');
      assert.equal(req.challenge, 'challenge-123');
      assert.ok(req.id.startsWith('creq_'));
      assert.ok(req.createdAt);
    });

    it('generates a challenge when none provided', () => {
      const req = createCredentialRequest(['grade'], 'did:key:z6MkVerifier');
      assert.ok(req.challenge.length > 0);
    });

    it('rejects empty claims array', () => {
      assert.throws(
        () => createCredentialRequest([], 'did:key:z6MkVerifier'),
        /at least one claim/,
      );
    });

    it('rejects missing verifier DID', () => {
      assert.throws(
        () => createCredentialRequest(['grade'], ''),
        /Verifier DID is required/,
      );
    });
  });

  describe('fulfillCredentialRequest — selective disclosure', () => {
    it('includes only requested claims in the VC', async () => {
      const agent = generateKeyPair();
      const req = createCredentialRequest(
        ['grade', 'capabilities'],
        'did:key:z6MkVerifier',
        'selective-challenge',
      );

      const vp = await fulfillCredentialRequest(req, {
        agentId: 'agent-selective-001',
        publicKey: agent.publicKey,
        agentName: 'Selective Agent',
        mission: 'Secret mission',
        capabilities: ['research', 'analysis'],
        grade: 2,
        delegationScope: ['data_read', 'commerce'],
        expiresAt: '2027-01-01T00:00:00.000Z',
      }, agent.privateKey);

      // VP should have challenge bound
      assert.equal((vp.proof as any).challenge, 'selective-challenge');

      // Extract the credential subject
      const vc = vp.verifiableCredential[0];
      const subject = vc.credentialSubject as Record<string, unknown>;

      // Should have: id, agentId (mandatory) + grade, capabilities (requested)
      assert.ok(subject.id);
      assert.equal(subject.agentId, 'agent-selective-001');
      assert.equal(subject.grade, 2);
      assert.deepEqual(subject.capabilities, ['research', 'analysis']);

      // Should NOT have: mission, delegationScope (not requested)
      assert.equal(subject.mission, undefined);
      assert.equal(subject.delegationScope, undefined);
    });

    it('includes all claims when all requested', async () => {
      const agent = generateKeyPair();
      const req = createCredentialRequest(
        ['grade', 'capabilities', 'delegationScope', 'mission', 'agentName'],
        'did:key:z6MkVerifier',
      );
      const vp = await fulfillCredentialRequest(req, {
        agentId: 'agent-full',
        publicKey: agent.publicKey,
        agentName: 'Full Agent',
        mission: 'Full disclosure',
        capabilities: ['trade'],
        grade: 3,
        delegationScope: ['commerce'],
        expiresAt: '2027-01-01T00:00:00.000Z',
      }, agent.privateKey);

      const subject = vp.verifiableCredential[0].credentialSubject as Record<string, unknown>;
      assert.equal(subject.grade, 3);
      assert.equal(subject.mission, 'Full disclosure');
      assert.deepEqual(subject.delegationScope, ['commerce']);
    });
  });

  describe('verifyCredentialResponse', () => {
    it('verifies and extracts claims from a valid response', async () => {
      const agent = generateKeyPair();
      const challenge = 'verify-me-123';
      const req = createCredentialRequest(['grade', 'capabilities'], 'did:key:z6MkVerifier', challenge);

      const vp = await fulfillCredentialRequest(req, {
        agentId: 'agent-verify-001',
        publicKey: agent.publicKey,
        capabilities: ['research'],
        grade: 2,
        expiresAt: '2027-01-01T00:00:00.000Z',
      }, agent.privateKey);

      const result = await verifyCredentialResponse(vp, challenge);

      assert.equal(result.valid, true);
      assert.equal(result.claims.grade, 2);
      assert.deepEqual(result.claims.capabilities, ['research']);
      assert.equal(result.claims.agentId, 'agent-verify-001');
      assert.ok(result.checks.some(c => c.includes('PASS: challenge matches')));
      assert.ok(result.checks.some(c => c.includes('PASS: presentation signature valid')));
    });

    it('rejects mismatched challenge', async () => {
      const agent = generateKeyPair();
      const req = createCredentialRequest(['grade'], 'did:key:z6MkVerifier', 'real-challenge');
      const vp = await fulfillCredentialRequest(req, {
        agentId: 'agent-bad-challenge',
        publicKey: agent.publicKey,
        grade: 1,
        expiresAt: '2027-01-01T00:00:00.000Z',
      }, agent.privateKey);

      const result = await verifyCredentialResponse(vp, 'wrong-challenge');
      assert.equal(result.valid, false);
      assert.ok(result.checks.some(c => c.includes('FAIL: challenge mismatch')));
    });

    it('rejects tampered credential in response', async () => {
      const agent = generateKeyPair();
      const req = createCredentialRequest(['grade'], 'did:key:z6MkVerifier', 'tamper-test');
      const vp = await fulfillCredentialRequest(req, {
        agentId: 'agent-tamper',
        publicKey: agent.publicKey,
        grade: 1,
        expiresAt: '2027-01-01T00:00:00.000Z',
      }, agent.privateKey);

      // Tamper with the credential inside the VP
      (vp.verifiableCredential[0].credentialSubject as any).grade = 3;
      const result = await verifyCredentialResponse(vp, 'tamper-test');
      // VP signature is still over old content, so VP proof fails too
      assert.equal(result.valid, false);
    });

    it('detects expired credential in response', async () => {
      const agent = generateKeyPair();
      const req = createCredentialRequest(['grade'], 'did:key:z6MkVerifier', 'expired-test');
      const vp = await fulfillCredentialRequest(req, {
        agentId: 'agent-expired',
        publicKey: agent.publicKey,
        grade: 2,
        expiresAt: '2020-01-01T00:00:00.000Z',
      }, agent.privateKey);

      const result = await verifyCredentialResponse(vp, 'expired-test');
      assert.equal(result.valid, false);
      assert.ok(result.checks.some(c => c.includes('expired')));
    });
  });
});

// ═══ Full Pipeline Integration Tests ═══

describe('Identity Pipeline: Bring Your Own Identity', () => {

  // ── Path A: SPIFFE ──
  describe('SPIFFE path: SVID → attestation → VC → VP → verify', () => {
    it('full SPIFFE pipeline produces verifiable Grade 2 credential', async () => {
      const issuer = generateKeyPair();
      const agent = generateKeyPair();

      // 1. Parse and import SPIFFE SVID
      const parsed = parseSPIFFEID('spiffe://prod.cluster.io/ns/default/sa/trading-agent');
      assert.equal(parsed.trustDomain, 'prod.cluster.io');
      assert.equal(parsed.workloadPath, '/ns/default/sa/trading-agent');

      const attestation = importSPIFFESVID({
        spiffeId: 'spiffe://prod.cluster.io/ns/default/sa/trading-agent',
        x509Cert: 'MIIBbase64cert',
        expiresAt: '2026-12-31T23:59:59.000Z',
      });
      assert.equal(attestation.provider, 'prod.cluster.io');
      assert.equal(attestation.subjectClass, 'workload');
      assert.equal(attestation.verificationMethod, 'x509');

      // 2. Create VC with Grade 2 (SVID = infrastructure attestation → runtime_bound)
      const vc = await passportToVerifiableCredential({
        agentId: 'agent-spiffe-pipeline',
        publicKey: agent.publicKey,
        agentName: 'SPIFFE Trading Agent',
        capabilities: ['trade', 'research'],
        grade: 2,
        delegationScope: ['commerce', 'data_read'],
        createdAt: '2026-01-01T00:00:00.000Z',
        expiresAt: '2027-01-01T00:00:00.000Z',
        evidence: [attestation],
      }, issuer.privateKey);

      // 3. Verify the VC
      const vcResult = await verifyVerifiableCredential(vc);
      assert.equal(vcResult.valid, true);
      assert.ok(vcResult.checks.some(c => c.includes('evidence attachment')));

      // 4. Create VP
      const vp = await createVerifiablePresentation([vc], agent.privateKey, {
        challenge: 'spiffe-nonce-001',
        domain: 'gateway.aeoess.com',
      });
      assert.ok(vp.holder.startsWith('did:key:z6Mk'));

      // 5. Verify VP
      const vpResult = await verifyVerifiablePresentation(vp);
      assert.equal(vpResult.valid, true);

      // 6. Verify the credential subject carries grade and evidence through
      const subject = vpResult.credentials[0].credentialSubject as Record<string, unknown>;
      assert.equal(subject.grade, 2);
      const cred = vpResult.credentials[0] as any;
      assert.equal(cred.evidence[0].provider, 'prod.cluster.io');
      assert.equal(cred.evidence[0].verificationMethod, 'x509');
    });
  });

  // ── Path B: OAuth ──
  describe('OAuth path: token → scope ceiling → delegation → narrowing', () => {
    it('OAuth scope becomes delegation ceiling, narrowing enforced', () => {
      // 1. Import OAuth token
      const oauthResult = importOAuthToken({
        sub: 'service-account-42',
        scope: 'read:data write:logs admin:config',
        iss: 'https://auth.corp.example.com',
        exp: Math.floor(Date.now() / 1000) + 3600,
      });
      assert.ok(oauthResult.agentId.startsWith('agent-oauth-'));
      assert.deepEqual(oauthResult.delegationScope, ['data_read', 'data_write', 'governance']);

      // 2. Create root delegation with OAuth scope as ceiling
      const root = generateKeyPair();
      const agent = generateKeyPair();
      const rootDelegation = createDelegation({
        delegatedBy: root.publicKey,
        delegatedTo: agent.publicKey,
        scope: oauthResult.delegationScope,
        spendLimit: 1000,
        maxDepth: 3,
        privateKey: root.privateKey,
        expiresInHours: 48,
      });
      assert.deepEqual(rootDelegation.scope, ['data_read', 'data_write', 'governance']);

      // 3. Sub-delegate with narrowing: must be subset of OAuth ceiling
      const subAgent = generateKeyPair();
      const narrowed = createDelegation({
        delegatedBy: agent.publicKey,
        delegatedTo: subAgent.publicKey,
        scope: ['data_read'],  // narrowed from ['data_read', 'data_write', 'governance']
        spendLimit: 100,       // narrowed from 1000
        maxDepth: 2,
        privateKey: agent.privateKey,
        expiresInHours: 24,    // narrowed from 48 hours
        parentDelegationId: rootDelegation.delegationId,
      });

      // 4. Verify narrowing invariants
      assert.ok(narrowed.scope.every(s => rootDelegation.scope.includes(s)), 'scope must be subset');
      assert.ok((narrowed.spendLimit || 0) <= (rootDelegation.spendLimit || 0), 'spend must narrow');
      assert.ok(new Date(narrowed.expiresAt) <= new Date(rootDelegation.expiresAt), 'time must narrow');

      // 5. Verify signatures
      const rootValid = verifyDelegation(rootDelegation);
      assert.equal(rootValid.valid, true);
      const narrowedValid = verifyDelegation(narrowed);
      assert.equal(narrowedValid.valid, true);

      // 6. Attempt scope escalation beyond OAuth ceiling: blocked by set membership
      const escalatedScope = ['data_read', 'commerce']; // 'commerce' not in OAuth ceiling
      const commerceInCeiling = escalatedScope.every(s => oauthResult.delegationScope.includes(s));
      assert.equal(commerceInCeiling, false, 'commerce not in OAuth ceiling');
    });
  });

  // ── Path C: DID ──
  describe('DID path: did:key ↔ did:aps bridge via alsoKnownAs', () => {
    it('DID Document bridges did:key and did:aps with service endpoint', () => {
      const agent = generateKeyPair();

      // 1. Create did:key
      const didKey = toDIDKey(agent.publicKey);
      assert.ok(didKey.startsWith('did:key:z6Mk'));

      // 2. Create DID Document
      const doc = passportToDIDDocument({
        agent_id: 'agent-did-bridge',
        public_key: agent.publicKey,
        created_at: '2026-01-01T00:00:00.000Z',
      }) as any;

      // 3. Verify did:key is the primary identifier
      assert.equal(doc.id, didKey);

      // 4. Verify alsoKnownAs bridges to did:aps
      assert.ok(doc.alsoKnownAs.length > 0);
      assert.ok(doc.alsoKnownAs[0].startsWith('did:aps:z'));

      // 5. External verifier resolves did:key and finds APS service endpoint
      const apsService = doc.service.find((s: any) => s.type === 'AgentPassportService');
      assert.ok(apsService);
      assert.equal(apsService.serviceEndpoint.agentId, 'agent-did-bridge');
      assert.equal(apsService.serviceEndpoint.protocol, 'aps');

      // 6. Round-trip: did:key → public key → did:key
      const recovered = fromDIDKey(didKey);
      assert.equal(recovered, agent.publicKey);
      assert.equal(toDIDKey(recovered), didKey);

      // 7. Verifier can resolve the alsoKnownAs did:aps to get the same key
      const apsMultibase = doc.alsoKnownAs[0].split(':').slice(2).join(':');
      // The verification method also uses the same multibase
      assert.equal(doc.verificationMethod[0].publicKeyMultibase, apsMultibase);
    });
  });

  // ── Path D: Cross-System ──
  describe('Cross-system: SPIFFE agent → VC → OAuth verifier', () => {
    it('SPIFFE agent presents VC to OAuth-authenticated verifier via credential request', async () => {
      // ── SPIFFE Agent Setup ──
      const agentKeys = generateKeyPair();
      const issuerKeys = generateKeyPair();

      // Agent has a SPIFFE SVID
      const spiffeAtt = importSPIFFESVID({
        spiffeId: 'spiffe://prod.cluster.io/ns/payments/sa/payment-agent',
        x509Cert: 'MIIBcert',
        expiresAt: '2026-12-31T23:59:59.000Z',
      });

      // ── OAuth Verifier Setup ──
      const verifierOAuth = importOAuthToken({
        sub: 'verifier-service',
        scope: 'read:agents admin:verify',
        iss: 'https://auth.verifier.example.com',
        exp: Math.floor(Date.now() / 1000) + 3600,
      });
      const verifierDIDKey = toDIDKey(generateKeyPair().publicKey);

      // ── Credential Request ──
      // Verifier requests grade + capabilities + delegationScope
      const request = createCredentialRequest(
        ['grade', 'capabilities', 'delegationScope'],
        verifierDIDKey,
        'cross-system-challenge-001',
      );

      // ── Agent Fulfills Request ──
      const vp = await fulfillCredentialRequest(request, {
        agentId: 'agent-payment-spiffe',
        publicKey: agentKeys.publicKey,
        agentName: 'Payment Agent',
        capabilities: ['commerce', 'data_read'],
        grade: 2,
        delegationScope: ['commerce'],
        mission: 'Process payments',
        createdAt: '2026-01-01T00:00:00.000Z',
        expiresAt: '2027-01-01T00:00:00.000Z',
        evidence: [spiffeAtt],
      }, agentKeys.privateKey);

      // ── Verifier Validates Response ──
      const result = await verifyCredentialResponse(vp, 'cross-system-challenge-001');

      assert.equal(result.valid, true);
      assert.ok(result.checks.some(c => c.includes('PASS: challenge matches')));
      assert.ok(result.checks.some(c => c.includes('PASS: presentation signature valid')));
      assert.ok(result.checks.some(c => c.includes('PASS: credential[0] signature valid')));

      // ── Verifier Extracts Claims ──
      assert.equal(result.claims.grade, 2);
      assert.deepEqual(result.claims.capabilities, ['commerce', 'data_read']);
      assert.deepEqual(result.claims.delegationScope, ['commerce']);

      // Mission was NOT disclosed (not requested)
      assert.equal(result.claims.mission, undefined);

      // ── Verifier Checks if Agent's Scope Fits Their OAuth Ceiling ──
      const verifierScope = verifierOAuth.delegationScope; // ['data_read', 'governance']
      const agentScope = result.claims.delegationScope as string[];
      const agentFitsVerifierScope = agentScope.every(s => verifierScope.includes(s));
      // 'commerce' is NOT in verifier's OAuth ceiling ['data_read', 'governance']
      assert.equal(agentFitsVerifierScope, false,
        'commerce scope exceeds verifier OAuth ceiling — cross-system boundary enforced');

      // ── Verify SPIFFE evidence survived the selective disclosure ──
      const vc = vp.verifiableCredential[0] as any;
      assert.ok(Array.isArray(vc.evidence));
      assert.equal(vc.evidence[0].provider, 'prod.cluster.io');

      // ── Both identity systems feed into APS enforcement ──
      // Agent identity: SPIFFE SVID → Grade 2 → did:key in VC
      // Verifier identity: OAuth token → delegation ceiling → scope check
      // Enforcement: APS credential request protocol binds them together
      assert.ok((vc.credentialSubject as any).id.startsWith('did:key:z6Mk'));
    });
  });
});
