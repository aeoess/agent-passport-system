import { describe, it } from 'node:test';
import assert from 'node:assert';
import {
  decodeQntmInvite,
  deriveQntmKeys,
  deriveNonce,
  qntmEncrypt,
  qntmDecrypt,
  serializeEnvelope,
  buildRelayMessage,
  computeKeyId,
  encryptForRelay,
  decryptFromRelay,
  extractEnvelopeDid,
  verifyEnvelopeDid,
} from '../src/interop/qntm-bridge.js';
import { generateKeyPair } from '../src/crypto/keys.js';

// Vessenes' test conversation invite token
const TEST_INVITE_TOKEN = 'p2F2AWR0eXBlZmRpcmVjdGVzdWl0ZWVRU1AtMWdjb252X2lkUNyoO3DM12Oom1lTss0u5nhraW52aXRlX3NhbHRYIJnHTkpBRQwpSj_7ZHMUHvPKnpf3r7yY_8gPRXk5RN2AbWludml0ZV9zZWNyZXRYIKbYnBf7banlbzaMK1YpeMzUNJAKg1Bi0P37WzHwvaqibWludml0ZXJfaWtfcGtYIIqw_2wL77fyrkF2igHm0SQXKd0hRcnA29phGsQQhAvJ';

// Known-answer test vectors from vessenes
const EXPECTED = {
  rootKey:  '5b9f2361408c3932d4685d8ccb9733a1da980086c49a7b6615f6bca5e1a67c01',
  aeadKey:  'b557d6071c2237eff670aa965f8f3bb516f9ba1d788166f8faf7388f5a260ec3',
  nonceKey: 'd88a1a1dee9dd0761a61a228a368ad72c15b96108c04cb072cc2b8fd63056c4f',
  convId:   'dca83b70ccd763a89b5953b2cd2ee678',
};

function toHex(arr: Uint8Array): string {
  return Buffer.from(arr).toString('hex');
}

describe('qntm Bridge — Invite Token Parsing', () => {
  it('decodes invite token correctly', () => {
    const invite = decodeQntmInvite(TEST_INVITE_TOKEN);
    assert.strictEqual(invite.v, 1);
    assert.strictEqual(invite.type, 'direct');
    assert.strictEqual(invite.suite, 'QSP-1');
    assert.strictEqual(toHex(invite.conv_id), EXPECTED.convId);
    assert.strictEqual(invite.conv_id.length, 16);
    assert.strictEqual(invite.invite_salt.length, 32);
    assert.strictEqual(invite.invite_secret.length, 32);
    assert.strictEqual(invite.inviter_ik_pk.length, 32);
  });
});

describe('qntm Bridge — HKDF Key Derivation (Known-Answer)', () => {
  it('derives root_key matching vessenes vector', () => {
    const invite = decodeQntmInvite(TEST_INVITE_TOKEN);
    const keys = deriveQntmKeys(invite);
    assert.strictEqual(toHex(keys.rootKey), EXPECTED.rootKey);
  });

  it('derives aead_key matching vessenes vector', () => {
    const invite = decodeQntmInvite(TEST_INVITE_TOKEN);
    const keys = deriveQntmKeys(invite);
    assert.strictEqual(toHex(keys.aeadKey), EXPECTED.aeadKey);
  });

  it('derives nonce_key matching vessenes vector', () => {
    const invite = decodeQntmInvite(TEST_INVITE_TOKEN);
    const keys = deriveQntmKeys(invite);
    assert.strictEqual(toHex(keys.nonceKey), EXPECTED.nonceKey);
  });

  it('all three keys match in single derivation', () => {
    const invite = decodeQntmInvite(TEST_INVITE_TOKEN);
    const keys = deriveQntmKeys(invite);
    assert.strictEqual(toHex(keys.rootKey), EXPECTED.rootKey);
    assert.strictEqual(toHex(keys.aeadKey), EXPECTED.aeadKey);
    assert.strictEqual(toHex(keys.nonceKey), EXPECTED.nonceKey);
    assert.strictEqual(toHex(keys.convId), EXPECTED.convId);
  });
});

describe('qntm Bridge — Nonce Derivation', () => {
  it('produces 24-byte nonce from message ID', () => {
    const invite = decodeQntmInvite(TEST_INVITE_TOKEN);
    const keys = deriveQntmKeys(invite);
    const msgId = new Uint8Array(16).fill(0x42);
    const nonce = deriveNonce(keys.nonceKey, msgId);
    assert.strictEqual(nonce.length, 24);
  });

  it('different message IDs produce different nonces', () => {
    const invite = decodeQntmInvite(TEST_INVITE_TOKEN);
    const keys = deriveQntmKeys(invite);
    const nonce1 = deriveNonce(keys.nonceKey, new Uint8Array(16).fill(0x01));
    const nonce2 = deriveNonce(keys.nonceKey, new Uint8Array(16).fill(0x02));
    assert.notStrictEqual(toHex(nonce1), toHex(nonce2));
  });
});

describe('qntm Bridge — Encrypt/Decrypt Roundtrip', () => {
  it('encrypts and decrypts a plaintext message', async () => {
    const invite = decodeQntmInvite(TEST_INVITE_TOKEN);
    const keys = deriveQntmKeys(invite);
    const senderKeyId = new Uint8Array(16).fill(0xAA);
    const plaintext = new TextEncoder().encode('Hello from APS via qntm relay!');

    const envelope = await qntmEncrypt(plaintext, keys, senderKeyId, 0);
    assert.strictEqual(envelope.v, 1);
    assert.strictEqual(toHex(envelope.conv), EXPECTED.convId);
    assert.ok(envelope.ct.length > plaintext.length); // ciphertext has auth tag

    const decrypted = await qntmDecrypt(envelope, keys);
    assert.strictEqual(new TextDecoder().decode(decrypted), 'Hello from APS via qntm relay!');
  });

  it('encrypts APS SignedExecutionEnvelope-sized payload', async () => {
    const invite = decodeQntmInvite(TEST_INVITE_TOKEN);
    const keys = deriveQntmKeys(invite);
    const senderKeyId = new Uint8Array(16).fill(0xBB);
    // Simulate a realistic APS envelope (~2KB)
    const payload = new TextEncoder().encode(JSON.stringify({
      intent: { action: 'research:search', target: 'arxiv.org', scope: 'research' },
      decision: { verdict: 'permit', principlesEvaluated: 8, floorVersion: '0.1' },
      receipt: { status: 'success', summary: 'Retrieved 5 papers on agent governance' },
      signatures: { intent: 'sig1...', decision: 'sig2...', receipt: 'sig3...' },
    }));

    const envelope = await qntmEncrypt(payload, keys, senderKeyId, 1);
    const decrypted = await qntmDecrypt(envelope, keys);
    const parsed = JSON.parse(new TextDecoder().decode(decrypted));
    assert.strictEqual(parsed.intent.action, 'research:search');
    assert.strictEqual(parsed.decision.verdict, 'permit');
    assert.strictEqual(parsed.receipt.status, 'success');
  });

  it('[ADVERSARIAL] decryption fails with wrong conversation keys', async () => {
    const invite = decodeQntmInvite(TEST_INVITE_TOKEN);
    const keys = deriveQntmKeys(invite);
    const senderKeyId = new Uint8Array(16).fill(0xCC);
    const plaintext = new TextEncoder().encode('secret message');

    const envelope = await qntmEncrypt(plaintext, keys, senderKeyId, 2);

    // Tamper with the AEAD key
    const wrongKeys = { ...keys, aeadKey: new Uint8Array(32).fill(0xFF) };
    await assert.rejects(
      () => qntmDecrypt(envelope, wrongKeys),
      /ciphertext.*cannot.*decrypted|ciphertext verification failed|wrong secret key|incorrect/i,
    );
  });

  it('[ADVERSARIAL] tampered ciphertext fails decryption', async () => {
    const invite = decodeQntmInvite(TEST_INVITE_TOKEN);
    const keys = deriveQntmKeys(invite);
    const senderKeyId = new Uint8Array(16).fill(0xDD);
    const plaintext = new TextEncoder().encode('authenticated data');

    const envelope = await qntmEncrypt(plaintext, keys, senderKeyId, 3);
    // Flip a byte in ciphertext
    envelope.ct[0] ^= 0xFF;

    await assert.rejects(
      () => qntmDecrypt(envelope, keys),
      /ciphertext.*cannot.*decrypted|ciphertext verification failed|wrong secret key|incorrect/i,
    );
  });
});

describe('qntm Bridge — Envelope Serialization', () => {
  it('serializes envelope to base64', async () => {
    const invite = decodeQntmInvite(TEST_INVITE_TOKEN);
    const keys = deriveQntmKeys(invite);
    const senderKeyId = new Uint8Array(16).fill(0xEE);
    const plaintext = new TextEncoder().encode('test');

    const envelope = await qntmEncrypt(plaintext, keys, senderKeyId, 0);
    const b64 = serializeEnvelope(envelope);
    assert.ok(typeof b64 === 'string');
    assert.ok(b64.length > 0);
    // Should be valid base64
    const decoded = Buffer.from(b64, 'base64');
    assert.ok(decoded.length > 0);
  });

  it('builds relay message with correct format', async () => {
    const invite = decodeQntmInvite(TEST_INVITE_TOKEN);
    const keys = deriveQntmKeys(invite);
    const senderKeyId = new Uint8Array(16).fill(0xFF);
    const plaintext = new TextEncoder().encode('relay test');

    const envelope = await qntmEncrypt(plaintext, keys, senderKeyId, 1);
    const relayMsg = buildRelayMessage(envelope);
    assert.strictEqual(relayMsg.conv_id, EXPECTED.convId);
    assert.ok(typeof relayMsg.envelope_b64 === 'string');
    assert.ok(relayMsg.envelope_b64.length > 0);
  });
});

describe('qntm Bridge — Key ID', () => {
  it('computes 16-byte key ID from public key', () => {
    const kp = generateKeyPair();
    const keyId = computeKeyId(Buffer.from(kp.publicKey, 'hex'));
    assert.strictEqual(keyId.length, 16);
  });

  it('different keys produce different IDs', () => {
    const kp1 = generateKeyPair();
    const kp2 = generateKeyPair();
    const id1 = computeKeyId(Buffer.from(kp1.publicKey, 'hex'));
    const id2 = computeKeyId(Buffer.from(kp2.publicKey, 'hex'));
    assert.notStrictEqual(toHex(id1), toHex(id2));
  });
});

describe('qntm Bridge — High-Level API', () => {
  it('encryptForRelay produces relay-ready message', async () => {
    const kp = generateKeyPair();
    const payload = new TextEncoder().encode('APS envelope payload');
    const relayMsg = await encryptForRelay(
      payload,
      TEST_INVITE_TOKEN,
      Buffer.from(kp.publicKey, 'hex'),
      0,
    );
    assert.strictEqual(relayMsg.conv_id, EXPECTED.convId);
    assert.ok(relayMsg.envelope_b64.length > 0);
  });

  it('full roundtrip: encryptForRelay → decryptFromRelay', async () => {
    const kp = generateKeyPair();
    const original = 'Full E2E roundtrip through qntm bridge — APS SignedExecutionEnvelope inside';
    const payload = new TextEncoder().encode(original);

    const relayMsg = await encryptForRelay(
      payload,
      TEST_INVITE_TOKEN,
      Buffer.from(kp.publicKey, 'hex'),
      0,
    );

    const decrypted = await decryptFromRelay(relayMsg.envelope_b64, TEST_INVITE_TOKEN);
    assert.strictEqual(new TextDecoder().decode(decrypted), original);
  });

  it('[ADVERSARIAL] decryptFromRelay fails with wrong invite token', async () => {
    const kp = generateKeyPair();
    const payload = new TextEncoder().encode('secret');

    const relayMsg = await encryptForRelay(
      payload,
      TEST_INVITE_TOKEN,
      Buffer.from(kp.publicKey, 'hex'),
      0,
    );

    // Corrupt the middle of the token (invite_secret region) to ensure different keys
    const tokenChars = TEST_INVITE_TOKEN.split('');
    for (let i = 80; i < 90; i++) tokenChars[i] = 'A';
    const badToken = tokenChars.join('');
    // Use completely different keys — derive from a different token section
    // Corrupting the invite_secret portion will produce valid CBOR but wrong keys
    let failed = false;
    try {
      const decrypted = await decryptFromRelay(relayMsg.envelope_b64, badToken);
      // If it somehow decrypts, the content should be garbage (not the original)
      const text = new TextDecoder().decode(decrypted);
      if (text !== 'secret') failed = true; // wrong content = corruption detected
    } catch {
      failed = true; // decryption error = expected
    }
    assert.ok(failed, 'Should fail with wrong invite token');
  });
});


describe('qntm Bridge — DID Field (QSP-1 v0.1.1)', () => {
  it('includes DID in encrypted envelope when provided', async () => {
    const invite = decodeQntmInvite(TEST_INVITE_TOKEN);
    const keys = deriveQntmKeys(invite);
    const senderKeyId = new Uint8Array(16).fill(0x11);
    const plaintext = new TextEncoder().encode('test with DID');
    const testDid = 'did:aps:z3Bmy2y8WtbRXNBYayR64kYqXN1XRi6Hqch6FwKFxmSWH';

    const envelope = await qntmEncrypt(plaintext, keys, senderKeyId, 0, testDid);
    assert.strictEqual(envelope.did, testDid);

    // Serialize and verify DID survives roundtrip
    const b64 = serializeEnvelope(envelope);
    const extractedDid = extractEnvelopeDid(b64);
    assert.strictEqual(extractedDid, testDid);
  });

  it('omits DID when not provided', async () => {
    const invite = decodeQntmInvite(TEST_INVITE_TOKEN);
    const keys = deriveQntmKeys(invite);
    const senderKeyId = new Uint8Array(16).fill(0x22);
    const plaintext = new TextEncoder().encode('test without DID');

    const envelope = await qntmEncrypt(plaintext, keys, senderKeyId, 0);
    assert.strictEqual(envelope.did, undefined);

    const b64 = serializeEnvelope(envelope);
    const extractedDid = extractEnvelopeDid(b64);
    assert.strictEqual(extractedDid, undefined);
  });

  it('encryptForRelay passes DID through to envelope', async () => {
    const kp = generateKeyPair();
    const testDid = 'did:aps:z6Mkge31dDNxE8uzUgPHez3ubePXBaoH7yYCJi1BmbDygfHf';
    const payload = new TextEncoder().encode('payload with DID');

    const relayMsg = await encryptForRelay(
      payload, TEST_INVITE_TOKEN, Buffer.from(kp.publicKey, 'hex'), 0, testDid,
    );

    const extractedDid = extractEnvelopeDid(relayMsg.envelope_b64);
    assert.strictEqual(extractedDid, testDid);
  });

  it('verifyEnvelopeDid returns true for matching key', async () => {
    const kp = generateKeyPair();
    const payload = new TextEncoder().encode('verify test');
    const testDid = 'did:aps:' + kp.publicKey;

    const relayMsg = await encryptForRelay(
      payload, TEST_INVITE_TOKEN, Buffer.from(kp.publicKey, 'hex'), 0, testDid,
    );

    const valid = verifyEnvelopeDid(relayMsg.envelope_b64, kp.publicKey);
    assert.strictEqual(valid, true);
  });

  it('[ADVERSARIAL] verifyEnvelopeDid returns false for wrong key', async () => {
    const kp = generateKeyPair();
    const wrongKp = generateKeyPair();
    const payload = new TextEncoder().encode('wrong key test');

    const relayMsg = await encryptForRelay(
      payload, TEST_INVITE_TOKEN, Buffer.from(kp.publicKey, 'hex'), 0,
    );

    const valid = verifyEnvelopeDid(relayMsg.envelope_b64, wrongKp.publicKey);
    assert.strictEqual(valid, false);
  });

  it('DID field is backwards compatible — decrypt works with or without DID', async () => {
    const kp = generateKeyPair();
    const original = 'backwards compatibility test';
    const payload = new TextEncoder().encode(original);
    const testDid = 'did:agentid:agent_test_001';

    // Encrypt WITH DID
    const withDid = await encryptForRelay(
      payload, TEST_INVITE_TOKEN, Buffer.from(kp.publicKey, 'hex'), 0, testDid,
    );

    // Encrypt WITHOUT DID
    const withoutDid = await encryptForRelay(
      payload, TEST_INVITE_TOKEN, Buffer.from(kp.publicKey, 'hex'), 1,
    );

    // Both decrypt correctly
    const d1 = await decryptFromRelay(withDid.envelope_b64, TEST_INVITE_TOKEN);
    const d2 = await decryptFromRelay(withoutDid.envelope_b64, TEST_INVITE_TOKEN);
    assert.strictEqual(new TextDecoder().decode(d1), original);
    assert.strictEqual(new TextDecoder().decode(d2), original);
  });
});
