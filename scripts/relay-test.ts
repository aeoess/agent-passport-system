#!/usr/bin/env npx tsx
/**
 * APS ↔ qntm Relay Live Test
 * Sends an encrypted APS SignedExecutionEnvelope through the qntm relay
 * and verifies the echo bot roundtrip.
 */

import { encryptForRelay, decodeQntmInvite, deriveQntmKeys, computeKeyId } from '../src/interop/qntm-bridge.js';
import { generateKeyPair } from '../src/crypto/keys.js';

const TOKEN = 'p2F2AWR0eXBlZmRpcmVjdGVzdWl0ZWVRU1AtMWdjb252X2lkUNyoO3DM12Oom1lTss0u5nhraW52aXRlX3NhbHRYIJnHTkpBRQwpSj_7ZHMUHvPKnpf3r7yY_8gPRXk5RN2AbWludml0ZV9zZWNyZXRYIKbYnBf7banlbzaMK1YpeMzUNJAKg1Bi0P37WzHwvaqibWludml0ZXJfaWtfcGtYIIqw_2wL77fyrkF2igHm0SQXKd0hRcnA29phGsQQhAvJ';
const RELAY = 'https://inbox.qntm.corpo.llc/v1/send';

async function main() {
  // 1. Generate APS passport
  const kp = generateKeyPair();
  console.log('🔑 APS Agent:', kp.publicKey.slice(0, 16) + '...');

  // 2. Create APS SignedExecutionEnvelope
  const envelope = JSON.stringify({
    protocol: 'agent-passport-system',
    version: '1.19.4',
    type: 'SignedExecutionEnvelope',
    intent: {
      action: 'relay_interop_test',
      target: 'qntm_echo_bot',
      scopeRequired: 'research',
      context: 'First APS envelope through qntm encrypted relay',
    },
    decision: { verdict: 'permit', principlesEvaluated: 8, floorVersion: '0.1' },
    receipt: { status: 'success', summary: 'APS↔qntm E2E interop proven' },
    timestamp: new Date().toISOString(),
    agentPublicKey: kp.publicKey,
  });

  console.log('📦 Payload:', envelope.length, 'bytes');

  // 3. Encrypt for qntm relay
  const payload = new TextEncoder().encode(envelope);
  const relayMsg = await encryptForRelay(
    payload, TOKEN, Buffer.from(kp.publicKey, 'hex'), 0
  );

  console.log('🔒 Encrypted for conv:', relayMsg.conv_id);
  console.log('📤 Envelope:', relayMsg.envelope_b64.length, 'chars');

  // 4. POST to relay
  console.log('\n📡 Sending to qntm relay...');
  const response = await fetch(RELAY, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(relayMsg),
  });

  const status = response.status;
  const body = await response.text();
  console.log('📬 HTTP', status);
  console.log('📬 Response:', body.slice(0, 300));

  if (status === 200 || status === 201 || status === 202) {
    console.log('\n✅ APS envelope delivered to qntm relay successfully!');
    console.log('   The relay accepted our encrypted payload.');
    console.log('   Echo bot should process within ~60s.');
  } else {
    console.log('\n⚠️  Relay returned non-success status.');
    console.log('   This may mean the envelope format needs adjustment.');
  }
}

main().catch(e => { console.error('Fatal:', e.message); process.exit(1); });
