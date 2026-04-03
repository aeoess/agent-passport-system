import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPair } from '../src/crypto/keys.js';
import {
  toDIDKey, fromDIDKey,
  didWebToUrl, resolveDIDWeb,
  passportToDIDDocument,
} from '../src/core/did-interop.js';
import { hexToMultibase, multibaseToHex } from '../src/core/did.js';

describe('did:key', () => {

  describe('toDIDKey', () => {
    it('produces did:key:z6Mk prefix for Ed25519', () => {
      const kp = generateKeyPair();
      const didKey = toDIDKey(kp.publicKey);
      assert.ok(didKey.startsWith('did:key:z6Mk'), `Expected z6Mk prefix, got: ${didKey}`);
    });

    it('produces consistent output for same input', () => {
      const kp = generateKeyPair();
      assert.equal(toDIDKey(kp.publicKey), toDIDKey(kp.publicKey));
    });

    it('produces different output for different keys', () => {
      const a = generateKeyPair();
      const b = generateKeyPair();
      assert.notEqual(toDIDKey(a.publicKey), toDIDKey(b.publicKey));
    });

    it('rejects invalid hex (too short)', () => {
      assert.throws(() => toDIDKey('abcd'), /Invalid Ed25519 public key/);
    });

    it('rejects invalid hex (non-hex chars)', () => {
      assert.throws(() => toDIDKey('g'.repeat(64)), /Invalid Ed25519 public key/);
    });

    it('rejects empty string', () => {
      assert.throws(() => toDIDKey(''), /Invalid Ed25519 public key/);
    });
  });

  describe('fromDIDKey', () => {
    it('round-trips with toDIDKey', () => {
      const kp = generateKeyPair();
      const didKey = toDIDKey(kp.publicKey);
      const recovered = fromDIDKey(didKey);
      assert.equal(recovered, kp.publicKey);
    });

    it('round-trips 10 random keys', () => {
      for (let i = 0; i < 10; i++) {
        const kp = generateKeyPair();
        assert.equal(fromDIDKey(toDIDKey(kp.publicKey)), kp.publicKey);
      }
    });

    it('rejects non-did:key string', () => {
      assert.throws(() => fromDIDKey('did:aps:abc123'), /Invalid did:key format/);
    });

    it('rejects did:key without z-prefix', () => {
      assert.throws(() => fromDIDKey('did:key:abc'), /z-prefix/);
    });

    it('rejects non-string input', () => {
      assert.throws(() => fromDIDKey(123 as any), /must be a string/);
    });
  });

  describe('known vector', () => {
    // Verify the multicodec prefix is 0xed01 (Ed25519)
    it('multibase starts with z6Mk for all-zero key', () => {
      const zeroKey = '0'.repeat(64);
      const didKey = toDIDKey(zeroKey);
      // z6Mk is the expected base58btc prefix for 0xed01 + 32 zero bytes
      assert.ok(didKey.startsWith('did:key:z6Mk'), `Expected z6Mk, got: ${didKey}`);
    });

    it('matches hexToMultibase from did.ts', () => {
      const kp = generateKeyPair();
      const multibase = hexToMultibase(kp.publicKey);
      const didKey = toDIDKey(kp.publicKey);
      assert.equal(didKey, `did:key:${multibase}`);
    });

    it('fromDIDKey matches multibaseToHex', () => {
      const kp = generateKeyPair();
      const multibase = hexToMultibase(kp.publicKey);
      const fromDid = fromDIDKey(`did:key:${multibase}`);
      const fromMultibase = multibaseToHex(multibase);
      assert.equal(fromDid, fromMultibase);
    });
  });
});

describe('did:web', () => {

  describe('didWebToUrl', () => {
    it('resolves bare domain to .well-known', () => {
      const url = didWebToUrl('did:web:example.com');
      assert.equal(url, 'https://example.com/.well-known/did.json');
    });

    it('resolves domain with path segments', () => {
      const url = didWebToUrl('did:web:example.com:users:alice');
      assert.equal(url, 'https://example.com/users/alice/did.json');
    });

    it('handles percent-encoded port', () => {
      const url = didWebToUrl('did:web:example.com%3A8443');
      assert.equal(url, 'https://example.com:8443/.well-known/did.json');
    });

    it('handles percent-encoded port with path', () => {
      const url = didWebToUrl('did:web:example.com%3A8443:dids:123');
      assert.equal(url, 'https://example.com:8443/dids/123/did.json');
    });

    it('rejects invalid prefix', () => {
      assert.throws(() => didWebToUrl('did:key:z6Mk123'), /Invalid did:web format/);
    });

    it('rejects non-string', () => {
      assert.throws(() => didWebToUrl(null as any), /must be a string/);
    });

    it('rejects did:web with no domain', () => {
      assert.throws(() => didWebToUrl('did:web:'), /must include a domain/);
    });
  });

  describe('resolveDIDWeb', () => {
    it('throws on network error for nonexistent domain', async () => {
      await assert.rejects(
        () => resolveDIDWeb('did:web:this-domain-does-not-exist-12345.example'),
        (err: Error) => err.message.includes('resolution failed') || err.message.includes('fetch')
      );
    });
  });
});

describe('passportToDIDDocument', () => {
  it('produces valid DID Document structure', () => {
    const kp = generateKeyPair();
    const doc = passportToDIDDocument({
      agent_id: 'agent-test-001',
      public_key: kp.publicKey,
      created_at: '2026-01-01T00:00:00.000Z',
    }) as any;

    assert.ok(doc['@context']);
    assert.ok(doc.id.startsWith('did:key:z6Mk'));
    assert.equal(doc.controller, doc.id);
    assert.equal(doc.verificationMethod.length, 1);
    assert.equal(doc.verificationMethod[0].type, 'Ed25519VerificationKey2020');
    assert.ok(doc.verificationMethod[0].publicKeyMultibase.startsWith('z'));
    assert.deepEqual(doc.authentication, [`${doc.id}#key-1`]);
    assert.deepEqual(doc.assertionMethod, [`${doc.id}#key-1`]);
    assert.deepEqual(doc.capabilityDelegation, [`${doc.id}#key-1`]);
    assert.equal(doc.created, '2026-01-01T00:00:00.000Z');
    assert.equal(doc.updated, '2026-01-01T00:00:00.000Z');
  });

  it('includes APS service endpoint', () => {
    const kp = generateKeyPair();
    const doc = passportToDIDDocument({
      agent_id: 'agent-test-svc',
      public_key: kp.publicKey,
    }) as any;

    assert.equal(doc.service.length, 1);
    assert.equal(doc.service[0].type, 'AgentPassportService');
    assert.equal(doc.service[0].serviceEndpoint.agentId, 'agent-test-svc');
    assert.equal(doc.service[0].serviceEndpoint.protocol, 'aps');
  });

  it('includes alsoKnownAs with did:aps', () => {
    const kp = generateKeyPair();
    const doc = passportToDIDDocument({
      agent_id: 'agent-test-aka',
      public_key: kp.publicKey,
    }) as any;

    assert.equal(doc.alsoKnownAs.length, 1);
    assert.ok(doc.alsoKnownAs[0].startsWith('did:aps:z'));
  });

  it('key in DID Document round-trips back to original', () => {
    const kp = generateKeyPair();
    const doc = passportToDIDDocument({
      agent_id: 'agent-roundtrip',
      public_key: kp.publicKey,
    }) as any;

    const recovered = fromDIDKey(doc.id);
    assert.equal(recovered, kp.publicKey);
  });

  it('rejects invalid public key', () => {
    assert.throws(
      () => passportToDIDDocument({ agent_id: 'x', public_key: 'bad' }),
      /Invalid passport/,
    );
  });

  it('rejects missing agent_id', () => {
    const kp = generateKeyPair();
    assert.throws(
      () => passportToDIDDocument({ agent_id: '', public_key: kp.publicKey }),
      /agent_id is required/,
    );
  });
});
