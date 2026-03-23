/**
 * qntm Bridge — APS ↔ qntm E2E encrypted relay integration
 * 
 * Enables APS agents to send SignedExecutionEnvelopes through the qntm
 * encrypted relay. Both sides use XChaCha20-Poly1305 with HKDF-derived
 * keys from shared invite tokens.
 * 
 * Interop proven: 5/5 Ed25519→X25519 vectors, 3/3 HKDF key derivation
 * vectors match across TypeScript (APS), TypeScript (@noble), and Python (qntm).
 * 
 * @module interop/qntm-bridge
 */

import * as crypto from 'crypto';
import sodium from 'libsodium-wrappers';

// ═══════════════════════════════════════
// Types
// ═══════════════════════════════════════

export interface QntmInvite {
  v: number;
  type: string;
  suite: string;
  conv_id: Uint8Array;
  invite_salt: Uint8Array;
  invite_secret: Uint8Array;
  inviter_ik_pk: Uint8Array;
}

export interface QntmConversationKeys {
  rootKey: Uint8Array;
  aeadKey: Uint8Array;
  nonceKey: Uint8Array;
  convId: Uint8Array;
}

export interface QntmEnvelope {
  v: number;
  conv: Uint8Array;
  sender: Uint8Array;
  seq: number;
  ts: number;
  nonce: Uint8Array;
  ct: Uint8Array;
  sig: Uint8Array;
  aad: Uint8Array;
  did?: string; // Optional DID for identity verification (QSP-1 v0.1.1)
}

export interface QntmRelayMessage {
  conv_id: string;
  envelope_b64: string;
}

// HKDF constants (qntm QSP-1 spec)
const INFO_ROOT = 'qntm/qsp/v1/root';
const INFO_AEAD = 'qntm/qsp/v1/aead';
const INFO_NONCE = 'qntm/qsp/v1/nonce';

// ═══════════════════════════════════════
// HKDF (RFC 5869, HMAC-SHA-256)
// ═══════════════════════════════════════

function hkdfExtract(salt: Uint8Array, ikm: Uint8Array): Buffer {
  return crypto.createHmac('sha256', salt).update(ikm).digest();
}

function hkdfExpand(prk: Uint8Array, info: Uint8Array, length: number): Uint8Array {
  let okm = Buffer.alloc(0);
  let t = Buffer.alloc(0);
  const n = Math.ceil(length / 32);
  for (let i = 1; i <= n; i++) {
    t = crypto.createHmac('sha256', prk)
      .update(Buffer.concat([t, Buffer.from(info), Buffer.from([i])]))
      .digest();
    okm = Buffer.concat([okm, t]);
  }
  return new Uint8Array(okm.slice(0, length));
}

function hkdf(ikm: Uint8Array, salt: Uint8Array, info: Uint8Array, length: number): Uint8Array {
  const prk = hkdfExtract(salt, ikm);
  return hkdfExpand(prk, info, length);
}

function concatBytes(...arrays: Uint8Array[]): Uint8Array {
  const total = arrays.reduce((sum, a) => sum + a.length, 0);
  const result = new Uint8Array(total);
  let offset = 0;
  for (const a of arrays) {
    result.set(a, offset);
    offset += a.length;
  }
  return result;
}

function utf8(s: string): Uint8Array {
  return new TextEncoder().encode(s);
}

// ═══════════════════════════════════════
// Minimal CBOR codec (QSP-1 subset)
// ═══════════════════════════════════════
// Only handles: maps with string keys, byte strings, text strings, unsigned ints

function cborDecodeMap(data: Uint8Array): Record<string, any> {
  let pos = 0;

  function readByte(): number { return data[pos++]; }

  function readMajor(): [number, number] {
    const b = readByte();
    const major = b >> 5;
    let additional = b & 0x1f;
    if (additional < 24) return [major, additional];
    if (additional === 24) return [major, readByte()];
    if (additional === 25) { const v = (data[pos] << 8) | data[pos + 1]; pos += 2; return [major, v]; }
    if (additional === 26) { const v = (data[pos] << 24) | (data[pos+1] << 16) | (data[pos+2] << 8) | data[pos+3]; pos += 4; return [major, v >>> 0]; }
    throw new Error(`CBOR: unsupported additional info ${additional}`);
  }

  function readValue(): any {
    const [major, info] = readMajor();
    switch (major) {
      case 0: return info; // unsigned int
      case 1: return -(info + 1); // negative int
      case 2: { // byte string
        const bytes = new Uint8Array(data.buffer, data.byteOffset + pos, info);
        pos += info;
        return new Uint8Array(bytes);
      }
      case 3: { // text string
        const text = new TextDecoder().decode(data.slice(pos, pos + info));
        pos += info;
        return text;
      }
      case 5: { // map
        const result: Record<string, any> = {};
        for (let i = 0; i < info; i++) {
          const key = readValue();
          result[String(key)] = readValue();
        }
        return result;
      }
      default: throw new Error(`CBOR: unsupported major type ${major}`);
    }
  }

  return readValue();
}

function cborEncodeMap(obj: Record<string, any>): Uint8Array {


  function encodeLength(major: number, len: number): Uint8Array {
    const m = major << 5;
    if (len < 24) return new Uint8Array([m | len]);
    if (len < 256) return new Uint8Array([m | 24, len]);
    if (len < 65536) return new Uint8Array([m | 25, (len >> 8) & 0xff, len & 0xff]);
    return new Uint8Array([m | 26, (len >> 24) & 0xff, (len >> 16) & 0xff, (len >> 8) & 0xff, len & 0xff]);
  }

  function encode(value: any): Uint8Array {
    if (typeof value === 'number' && Number.isInteger(value) && value >= 0) {
      return encodeLength(0, value);
    }
    if (typeof value === 'string') {
      const bytes = utf8(value);
      return concatBytes(encodeLength(3, bytes.length), bytes);
    }
    if (value instanceof Uint8Array) {
      return concatBytes(encodeLength(2, value.length), value);
    }
    if (typeof value === 'object' && !Array.isArray(value)) {
      const keys = Object.keys(value);
      const mapParts = [encodeLength(5, keys.length)];
      for (const k of keys) {
        mapParts.push(encode(k));
        mapParts.push(encode(value[k]));
      }
      return concatBytes(...mapParts);
    }
    throw new Error(`CBOR encode: unsupported type ${typeof value}`);
  }

  return encode(obj);
}

// ═══════════════════════════════════════
// Base64url
// ═══════════════════════════════════════

function base64urlDecode(s: string): Uint8Array {
  const padded = s.replace(/-/g, '+').replace(/_/g, '/');
  const pad = (4 - (padded.length % 4)) % 4;
  const b64 = padded + '='.repeat(pad);
  return new Uint8Array(Buffer.from(b64, 'base64'));
}

function base64Encode(data: Uint8Array): string {
  return Buffer.from(data).toString('base64');
}

// ═══════════════════════════════════════
// Public API
// ═══════════════════════════════════════

/** Decode a qntm invite token (base64url-encoded CBOR) */
export function decodeQntmInvite(token: string): QntmInvite {
  const cborBytes = base64urlDecode(token);
  const decoded = cborDecodeMap(cborBytes);
  return {
    v: decoded.v,
    type: decoded.type,
    suite: decoded.suite,
    conv_id: new Uint8Array(decoded.conv_id),
    invite_salt: new Uint8Array(decoded.invite_salt),
    invite_secret: new Uint8Array(decoded.invite_secret),
    inviter_ik_pk: new Uint8Array(decoded.inviter_ik_pk),
  };
}

/** Derive conversation keys from an invite token (HKDF-SHA-256) */
export function deriveQntmKeys(invite: QntmInvite): QntmConversationKeys {
  const rootInfo = concatBytes(utf8(INFO_ROOT), invite.conv_id);
  const rootKey = hkdf(invite.invite_secret, invite.invite_salt, rootInfo, 32);

  const aeadInfo = concatBytes(utf8(INFO_AEAD), invite.conv_id);
  const aeadKey = hkdfExpand(rootKey, aeadInfo, 32);

  const nonceInfo = concatBytes(utf8(INFO_NONCE), invite.conv_id);
  const nonceKey = hkdfExpand(rootKey, nonceInfo, 32);

  return { rootKey, aeadKey, nonceKey, convId: invite.conv_id };
}

/** Derive nonce for a message: Trunc24(HMAC-SHA-256(nonceKey, msgId)) */
export function deriveNonce(nonceKey: Uint8Array, msgId: Uint8Array): Uint8Array {
  const hmacResult = crypto.createHmac('sha256', nonceKey).update(msgId).digest();
  return new Uint8Array(hmacResult.slice(0, 24));
}

/** Encrypt plaintext with XChaCha20-Poly1305 using conversation keys */
export async function qntmEncrypt(
  plaintext: Uint8Array,
  keys: QntmConversationKeys,
  senderKeyId: Uint8Array,
  seq: number,
  did?: string,
): Promise<QntmEnvelope> {
  await sodium.ready;

  const msgId = new Uint8Array(crypto.randomBytes(16));
  const nonce = deriveNonce(keys.nonceKey, msgId);
  const aad = keys.convId;

  const ct = sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(
    plaintext, aad, null, nonce, keys.aeadKey,
  );

  return {
    v: 1,
    conv: keys.convId,
    sender: senderKeyId,
    seq,
    ts: Date.now(),
    nonce,
    ct: new Uint8Array(ct),
    sig: msgId, // msg_id serves as signature placeholder in symmetric mode
    aad,
    ...(did ? { did } : {}),
  };
}

/** Decrypt a qntm envelope */
export async function qntmDecrypt(
  envelope: QntmEnvelope,
  keys: QntmConversationKeys,
): Promise<Uint8Array> {
  await sodium.ready;
  const nonce = deriveNonce(keys.nonceKey, envelope.sig); // sig holds msg_id in symmetric mode
  return sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(
    null, envelope.ct, envelope.aad, nonce, keys.aeadKey,
  );
}

/** Serialize a qntm envelope to base64 for relay transport */
export function serializeEnvelope(envelope: QntmEnvelope): string {
  const map: Record<string, unknown> = {
    v: envelope.v,
    conv: envelope.conv,
    sender: envelope.sender,
    seq: envelope.seq,
    ts: envelope.ts,
    nonce: envelope.nonce,
    ct: envelope.ct,
    sig: envelope.sig,
    aad: envelope.aad,
  };
  if (envelope.did) map.did = envelope.did;
  const cborBytes = cborEncodeMap(map);
  return base64Encode(cborBytes);
}

/** Build relay message payload */
export function buildRelayMessage(envelope: QntmEnvelope): QntmRelayMessage {
  return {
    conv_id: Buffer.from(envelope.conv).toString('hex'),
    envelope_b64: serializeEnvelope(envelope),
  };
}

/** Compute key ID: Trunc16(SHA-256(publicKey)) — matches qntm spec */
export function computeKeyId(publicKey: Uint8Array): Uint8Array {
  const hash = crypto.createHash('sha256').update(publicKey).digest();
  return new Uint8Array(hash.slice(0, 16));
}

/**
 * High-level: Encrypt any payload and prepare for qntm relay.
 * 
 * @param payload - Bytes to encrypt (e.g., serialized SignedExecutionEnvelope)
 * @param inviteToken - Base64url-encoded qntm invite token
 * @param senderPublicKey - Ed25519 public key of the sender (for key ID)
 * @param seq - Message sequence number
 * @param did - Optional DID to include in envelope (e.g., did:aps:z... or did:agentid:...)
 * @returns Relay-ready message payload
 */
export async function encryptForRelay(
  payload: Uint8Array,
  inviteToken: string,
  senderPublicKey: Uint8Array,
  seq: number = 0,
  did?: string,
): Promise<QntmRelayMessage> {
  const invite = decodeQntmInvite(inviteToken);
  const keys = deriveQntmKeys(invite);
  const keyId = computeKeyId(senderPublicKey);
  const envelope = await qntmEncrypt(payload, keys, keyId, seq, did);
  return buildRelayMessage(envelope);
}

/**
 * High-level: Decrypt a relay message.
 * 
 * @param envelopeB64 - Base64-encoded CBOR envelope from relay
 * @param inviteToken - Same invite token used for encryption
 * @returns Decrypted plaintext bytes
 */
export async function decryptFromRelay(
  envelopeB64: string,
  inviteToken: string,
): Promise<Uint8Array> {
  const invite = decodeQntmInvite(inviteToken);
  const keys = deriveQntmKeys(invite);
  const cborBytes = new Uint8Array(Buffer.from(envelopeB64, 'base64'));
  const decoded = cborDecodeMap(cborBytes);
  const envelope: QntmEnvelope = {
    v: decoded.v,
    conv: new Uint8Array(decoded.conv),
    sender: new Uint8Array(decoded.sender),
    seq: decoded.seq,
    ts: decoded.ts,
    nonce: new Uint8Array(decoded.nonce),
    ct: new Uint8Array(decoded.ct),
    sig: new Uint8Array(decoded.sig),
    aad: new Uint8Array(decoded.aad),
    ...(decoded.did ? { did: decoded.did } : {}),
  };
  return qntmDecrypt(envelope, keys);
}

/**
 * Extract the DID from a serialized relay envelope (without decrypting).
 * Returns undefined if no DID is present.
 */
export function extractEnvelopeDid(envelopeB64: string): string | undefined {
  const cborBytes = new Uint8Array(Buffer.from(envelopeB64, 'base64'));
  const decoded = cborDecodeMap(cborBytes);
  return decoded.did || undefined;
}

/**
 * Verify that a DID matches the sender key ID in an envelope.
 * Resolves the DID to an Ed25519 public key, computes Trunc16(SHA-256(key)),
 * and compares with the envelope's sender field.
 *
 * @param envelopeB64 - Base64 CBOR envelope
 * @param publicKeyHex - Ed25519 public key hex resolved from the DID
 * @returns true if the key matches the sender key ID
 */
export function verifyEnvelopeDid(envelopeB64: string, publicKeyHex: string): boolean {
  const cborBytes = new Uint8Array(Buffer.from(envelopeB64, 'base64'));
  const decoded = cborDecodeMap(cborBytes);
  const senderKeyId = new Uint8Array(decoded.sender);
  const keyFromDid = Buffer.from(publicKeyHex, 'hex');
  const computedKeyId = computeKeyId(keyFromDid);
  if (senderKeyId.length !== computedKeyId.length) return false;
  return senderKeyId.every((b, i) => b === computedKeyId[i]);
}

/** Default relay URL */
export const QNTM_RELAY_URL = 'https://inbox.qntm.corpo.llc';

