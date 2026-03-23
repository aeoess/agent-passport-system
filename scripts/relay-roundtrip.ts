#!/usr/bin/env npx tsx
/**
 * APS ↔ qntm Full E2E Roundtrip Test
 * 1. Subscribe to WebSocket
 * 2. Send encrypted APS envelope via HTTP
 * 3. Receive echo via WebSocket
 * 4. Verify the APS payload survived the roundtrip
 */

import { encryptForRelay, decryptFromRelay, decodeQntmInvite, deriveQntmKeys, computeKeyId } from '../src/interop/qntm-bridge.js';
import { generateKeyPair } from '../src/crypto/keys.js';

const TOKEN = 'p2F2AWR0eXBlZmRpcmVjdGVzdWl0ZWVRU1AtMWdjb252X2lkUNyoO3DM12Oom1lTss0u5nhraW52aXRlX3NhbHRYIJnHTkpBRQwpSj_7ZHMUHvPKnpf3r7yY_8gPRXk5RN2AbWludml0ZV9zZWNyZXRYIKbYnBf7banlbzaMK1YpeMzUNJAKg1Bi0P37WzHwvaqibWludml0ZXJfaWtfcGtYIIqw_2wL77fyrkF2igHm0SQXKd0hRcnA29phGsQQhAvJ';
const CONV_ID = 'dca83b70ccd763a89b5953b2cd2ee678';
const RELAY_SEND = 'https://inbox.qntm.corpo.llc/v1/send';
const WS_URL = `wss://inbox.qntm.corpo.llc/v1/subscribe?conv_id=${CONV_ID}&from_seq=0`;

async function main() {
  const kp = generateKeyPair();
  console.log('🔑 APS Agent:', kp.publicKey.slice(0, 16) + '...');

  // Create APS payload
  const apsPayload = {
    protocol: 'agent-passport-system',
    version: '1.19.4',
    type: 'SignedExecutionEnvelope',
    intent: { action: 'e2e_roundtrip_test', target: 'qntm_echo_bot', scope: 'research' },
    decision: { verdict: 'permit', principlesEvaluated: 8, floorVersion: '0.1' },
    receipt: { status: 'success', summary: 'APS↔qntm E2E roundtrip proof' },
    nonce: Math.random().toString(36).slice(2), // unique per test
    timestamp: new Date().toISOString(),
  };
  const payloadStr = JSON.stringify(apsPayload);
  console.log('📦 Payload:', payloadStr.length, 'bytes, nonce:', apsPayload.nonce);

  // Step 1: Connect WebSocket and track messages
  console.log('\n📡 Connecting WebSocket...');
  const ws = new WebSocket(WS_URL);
  let ourSeq = -1;
  let headSeq = -1;
  const received: any[] = [];

  const done = new Promise<void>((resolve, reject) => {
    const timeout = setTimeout(() => {
      console.log('\n⏱  Timeout after 90s. Echo bot runs on ~60s cron.');
      console.log('   Messages received:', received.length);
      if (received.length > 0) {
        console.log('   Last message seq:', received[received.length - 1].seq);
      }
      resolve();
    }, 90000);

    ws.onopen = () => console.log('🔗 WebSocket connected');

    ws.onmessage = async (event: any) => {
      try {
        const frame = JSON.parse(typeof event.data === 'string' ? event.data : event.data.toString());

        if (frame.type === 'ready') {
          headSeq = frame.head_seq;
          console.log(`✅ Ready. Head seq: ${headSeq}`);
          return;
        }

        if (frame.type === 'pong') return;

        if (frame.type === 'message') {
          received.push(frame);
          console.log(`📬 Message seq=${frame.seq} (${frame.envelope_b64.length} chars)`);

          // Only try to decrypt messages after we sent ours
          if (frame.seq > ourSeq && ourSeq >= 0) {
            try {
              const plaintext = await decryptFromRelay(frame.envelope_b64, TOKEN);
              const text = new TextDecoder().decode(plaintext);
              console.log(`🔓 Decrypted: ${text.slice(0, 200)}`);

              // Check if it's our echo
              if (text.includes(apsPayload.nonce)) {
                console.log('\n🎉 ECHO ROUNDTRIP CONFIRMED!');
                console.log('   Our nonce found in echo response.');
                console.log('   APS envelope survived: relay → echo bot → relay → us');
                clearTimeout(timeout);
                resolve();
                return;
              }
            } catch (e: any) {
              // Echo bot may re-encrypt with different keys
              console.log(`   (cannot decrypt seq=${frame.seq}: ${e.message.slice(0, 80)})`);
            }
          }
        }
      } catch (e: any) {
        console.log('Frame parse error:', e.message);
      }
    };

    ws.onerror = (e: any) => { console.log('WebSocket error:', e.message || e); };
    ws.onclose = () => { console.log('WebSocket closed'); clearTimeout(timeout); resolve(); };
  });

  // Step 2: Wait for WS ready, then send
  await new Promise(r => setTimeout(r, 2000)); // Wait for WS connection + replay

  console.log('\n📤 Encrypting and sending APS envelope...');
  const payload = new TextEncoder().encode(payloadStr);
  const relayMsg = await encryptForRelay(payload, TOKEN, Buffer.from(kp.publicKey, 'hex'), 0);

  const resp = await fetch(RELAY_SEND, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(relayMsg),
  });
  const body = await resp.json() as any;
  ourSeq = body.seq;
  console.log(`📬 Sent! HTTP ${resp.status}, seq=${ourSeq}`);
  console.log('⏳ Waiting for echo (bot polls every ~60s)...\n');

  // Step 3: Wait for echo or timeout
  await done;
  ws.close();

  console.log('\n📊 Summary:');
  console.log(`   Messages seen: ${received.length}`);
  console.log(`   Our send seq: ${ourSeq}`);
  console.log(`   Payload nonce: ${apsPayload.nonce}`);
}

main().catch(e => { console.error('Fatal:', e); process.exit(1); });
