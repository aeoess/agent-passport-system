// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPair } from '../src/crypto/keys.js';
import {
  createAgoraMessage, verifyAgoraMessage,
  createFeed, appendToFeed, getThread, getByTopic, getByAuthor, getTopics,
  createRegistry, registerAgent, verifyFeed
} from '../src/core/agora.js';
import type { AgoraFeed, AgoraRegistry } from '../src/types/agora.js';

// Helper: make a test agent
function makeAgent(name: string) {
  const kp = generateKeyPair();
  return {
    agentId: `agent-${name}-${Date.now().toString(36)}`,
    agentName: name,
    publicKey: kp.publicKey,
    privateKey: kp.privateKey,
  };
}

describe('Agora — Message Creation', () => {
  it('creates a signed message', () => {
    const agent = makeAgent('test-agent');
    const msg = createAgoraMessage({
      ...agent,
      topic: 'general',
      type: 'discussion',
      subject: 'Hello Agora',
      content: 'First message in the Agora.',
    });
    assert.ok(msg.id.startsWith('msg-'));
    assert.equal(msg.version, '1.0');
    assert.equal(msg.author.agentName, 'test-agent');
    assert.equal(msg.topic, 'general');
    assert.equal(msg.type, 'discussion');
    assert.ok(msg.signature.length > 0);
  });

  it('creates a reply', () => {
    const agent = makeAgent('replier');
    const msg = createAgoraMessage({
      ...agent,
      topic: 'general',
      type: 'ack',
      subject: 'Re: Hello',
      content: 'Got it.',
      replyTo: 'msg-abc123',
    });
    assert.equal(msg.replyTo, 'msg-abc123');
  });
});

describe('Agora — Signature Verification', () => {
  it('verifies valid message', () => {
    const agent = makeAgent('signer');
    const msg = createAgoraMessage({
      ...agent,
      topic: 'integration',
      type: 'proposal',
      subject: 'Let us integrate',
      content: 'I want to use your protocol.',
    });
    const result = verifyAgoraMessage(msg);
    assert.ok(result.valid);
    assert.equal(result.errors.length, 0);
  });

  it('rejects tampered content', () => {
    const agent = makeAgent('tamper-test');
    const msg = createAgoraMessage({
      ...agent,
      topic: 'general',
      type: 'discussion',
      subject: 'Original',
      content: 'Original content.',
    });
    // Tamper
    msg.content = 'TAMPERED content!';
    const result = verifyAgoraMessage(msg);
    assert.ok(!result.valid);
    assert.ok(result.errors.some(e => e.includes('Invalid')));
  });

  it('rejects wrong key', () => {
    const agent1 = makeAgent('agent-a');
    const agent2 = makeAgent('agent-b');
    const msg = createAgoraMessage({
      ...agent1,
      topic: 'general',
      type: 'discussion',
      subject: 'Spoofed?',
      content: 'Trying to spoof.',
    });
    // Swap public key to agent2 (signature won't match)
    msg.author.publicKey = agent2.publicKey;
    const result = verifyAgoraMessage(msg);
    assert.ok(!result.valid);
  });

  it('checks registry membership', () => {
    const agent = makeAgent('registered');
    const msg = createAgoraMessage({
      ...agent,
      topic: 'general',
      type: 'discussion',
      subject: 'Hi',
      content: 'I am registered.',
    });
    // With empty registry. The signature still verifies, but the identity
    // check ran and failed, so the overall verdict is not valid. This
    // assertion used to read `assert.ok(r1.valid)`, which pinned the defect:
    // the registry error was reported and ignored at the same time.
    const emptyReg = createRegistry();
    const r1 = verifyAgoraMessage(msg, emptyReg);
    assert.ok(r1.signatureValid); // Signature is still valid
    assert.ok(!r1.knownAgent); // But not in registry
    assert.ok(!r1.valid); // so the message does not verify overall

    // With agent registered
    const reg = registerAgent(emptyReg, {
      agentId: agent.agentId,
      agentName: agent.agentName,
      publicKey: agent.publicKey,
      joinedAt: new Date().toISOString(),
      role: 'member',
    });
    const r2 = verifyAgoraMessage(msg, reg);
    assert.ok(r2.valid);
    assert.ok(r2.knownAgent);
  });
});

describe('Agora — Feed Operations', () => {
  it('creates empty feed', () => {
    const feed = createFeed();
    assert.equal(feed.messageCount, 0);
    assert.equal(feed.messages.length, 0);
    assert.equal(feed.version, '1.0');
  });

  it('appends messages', () => {
    const agent = makeAgent('poster');
    let feed = createFeed();
    const msg1 = createAgoraMessage({
      ...agent, topic: 'general', type: 'discussion',
      subject: 'First', content: 'Hello',
    });
    const msg2 = createAgoraMessage({
      ...agent, topic: 'integration', type: 'proposal',
      subject: 'Second', content: 'Let us work together',
    });
    feed = appendToFeed(feed, msg1);
    feed = appendToFeed(feed, msg2);
    assert.equal(feed.messageCount, 2);
    assert.equal(feed.messages.length, 2);
  });

  it('filters by topic', () => {
    const agent = makeAgent('topictest');
    let feed = createFeed();
    feed = appendToFeed(feed, createAgoraMessage({
      ...agent, topic: 'general', type: 'discussion',
      subject: 'A', content: 'general stuff',
    }));
    feed = appendToFeed(feed, createAgoraMessage({
      ...agent, topic: 'integration', type: 'proposal',
      subject: 'B', content: 'integration stuff',
    }));
    feed = appendToFeed(feed, createAgoraMessage({
      ...agent, topic: 'general', type: 'discussion',
      subject: 'C', content: 'more general',
    }));
    assert.equal(getByTopic(feed, 'general').length, 2);
    assert.equal(getByTopic(feed, 'integration').length, 1);
  });

  it('builds threads', () => {
    const a1 = makeAgent('alice');
    const a2 = makeAgent('bob');
    let feed = createFeed();
    const root = createAgoraMessage({
      ...a1, topic: 'general', type: 'discussion',
      subject: 'Thread root', content: 'Starting a thread',
    });
    feed = appendToFeed(feed, root);
    const reply = createAgoraMessage({
      ...a2, topic: 'general', type: 'ack',
      subject: 'Re: Thread root', content: 'Replying',
      replyTo: root.id,
    });
    feed = appendToFeed(feed, reply);
    const thread = getThread(feed, root.id);
    assert.equal(thread.length, 2);
    assert.equal(thread[0].id, root.id);
    assert.equal(thread[1].replyTo, root.id);
  });

  it('lists topics with counts', () => {
    const agent = makeAgent('counter');
    let feed = createFeed();
    for (let i = 0; i < 3; i++) {
      feed = appendToFeed(feed, createAgoraMessage({
        ...agent, topic: 'hot-topic', type: 'discussion',
        subject: `msg ${i}`, content: `content ${i}`,
      }));
    }
    feed = appendToFeed(feed, createAgoraMessage({
      ...agent, topic: 'cold-topic', type: 'discussion',
      subject: 'lone', content: 'only one',
    }));
    const topics = getTopics(feed);
    assert.equal(topics[0].topic, 'hot-topic');
    assert.equal(topics[0].count, 3);
    assert.equal(topics[1].count, 1);
  });
});

describe('Agora — Registry', () => {
  it('registers agents', () => {
    let reg = createRegistry();
    const a1 = makeAgent('alpha');
    const a2 = makeAgent('beta');
    reg = registerAgent(reg, {
      agentId: a1.agentId, agentName: 'alpha',
      publicKey: a1.publicKey, joinedAt: new Date().toISOString(), role: 'founder',
    });
    reg = registerAgent(reg, {
      agentId: a2.agentId, agentName: 'beta',
      publicKey: a2.publicKey, joinedAt: new Date().toISOString(), role: 'member',
    });
    assert.equal(reg.agents.length, 2);
  });

  it('deduplicates by public key', () => {
    let reg = createRegistry();
    const agent = makeAgent('duper');
    reg = registerAgent(reg, {
      agentId: agent.agentId, agentName: 'duper-v1',
      publicKey: agent.publicKey, joinedAt: new Date().toISOString(), role: 'member',
    });
    reg = registerAgent(reg, {
      agentId: agent.agentId, agentName: 'duper-v2',
      publicKey: agent.publicKey, joinedAt: new Date().toISOString(), role: 'founder',
    });
    assert.equal(reg.agents.length, 1);
    assert.equal(reg.agents[0].agentName, 'duper-v2');
  });
});

describe('Agora — Full Feed Verification', () => {
  it('verifies entire feed', () => {
    const a1 = makeAgent('verified-1');
    const a2 = makeAgent('verified-2');
    let feed = createFeed();
    feed = appendToFeed(feed, createAgoraMessage({
      ...a1, topic: 'general', type: 'announcement',
      subject: 'Hello', content: 'First post',
    }));
    feed = appendToFeed(feed, createAgoraMessage({
      ...a2, topic: 'general', type: 'discussion',
      subject: 'Welcome', content: 'Welcome to the agora',
    }));
    const result = verifyFeed(feed);
    assert.equal(result.total, 2);
    assert.equal(result.valid, 2);
    assert.equal(result.invalid.length, 0);
  });

  it('catches tampered messages in feed', () => {
    const agent = makeAgent('tamper-feed');
    let feed = createFeed();
    feed = appendToFeed(feed, createAgoraMessage({
      ...agent, topic: 'general', type: 'discussion',
      subject: 'OK', content: 'Fine',
    }));
    // Tamper
    feed.messages[0].content = 'HACKED';
    const result = verifyFeed(feed);
    assert.equal(result.valid, 0);
    assert.equal(result.invalid.length, 1);
  });
});

// ══════════════════════════════════════════════════════════════════
// Invariant: a verification function cannot report overall valid while
// simultaneously reporting load-bearing verification errors.
// ══════════════════════════════════════════════════════════════════
// verifyAgoraMessage ran the registry check, pushed 'Author not found in
// agent registry' into errors, and then returned valid: signatureValid,
// so the registry check never reached the verdict. The observable result
// was {"valid":true, errors:["Author not found in agent registry"]}, and
// verifyFeed counted such messages as valid with invalid: []. Overall
// valid now reflects every predicate that ran, and the components are
// reported separately so a caller can tell which one failed.

describe('Agora: the verdict reflects every check that ran', () => {
  function signedMessage(name: string) {
    const agent = makeAgent(name);
    return {
      agent,
      msg: createAgoraMessage({
        ...agent,
        topic: 'general',
        type: 'discussion',
        subject: 'Subject',
        content: 'Content',
      }),
    };
  }

  it('valid is never true while errors are reported', () => {
    const { msg } = signedMessage('unregistered');
    const result = verifyAgoraMessage(msg, createRegistry());
    assert.equal(
      result.valid && result.errors.length > 0,
      false,
      `valid=${result.valid} with errors ${JSON.stringify(result.errors)}`,
    );
  });

  it('an author absent from a supplied registry is not valid', () => {
    const { msg } = signedMessage('stranger');
    const result = verifyAgoraMessage(msg, createRegistry());
    assert.equal(result.valid, false);
    assert.equal(result.signatureValid, true, 'the signature itself is fine');
    assert.equal(result.knownAgent, false);
    assert.equal(result.registryChecked, true);
    assert.ok(result.errors.some(e => e.includes('registry')));
  });

  it('a registered author with a good signature is valid', () => {
    const { agent, msg } = signedMessage('member');
    const registry = registerAgent(createRegistry(), {
      agentId: agent.agentId,
      agentName: agent.agentName,
      publicKey: agent.publicKey,
      joinedAt: new Date().toISOString(),
      role: 'member',
    });
    const result = verifyAgoraMessage(msg, registry);
    assert.equal(result.valid, true, result.errors.join(' | '));
    assert.equal(result.signatureValid, true);
    assert.equal(result.knownAgent, true);
    assert.equal(result.registryChecked, true);
    assert.deepEqual(result.errors, []);
  });

  it('with no registry the result says so rather than implying membership', () => {
    const { msg } = signedMessage('anonymous');
    const result = verifyAgoraMessage(msg);
    assert.equal(result.registryChecked, false);
    assert.equal(result.knownAgent, false);
    assert.equal(result.signatureValid, true);
    // Signature-only verification. Valid here means the message was not
    // altered after signing, not that its author is a known participant.
    assert.equal(result.valid, true);
    assert.deepEqual(result.errors, []);
  });

  it('a tampered message from a registered author is not valid', () => {
    const { agent, msg } = signedMessage('member-tamper');
    const registry = registerAgent(createRegistry(), {
      agentId: agent.agentId,
      agentName: agent.agentName,
      publicKey: agent.publicKey,
      joinedAt: new Date().toISOString(),
      role: 'member',
    });
    msg.content = 'rewritten after signing';
    const result = verifyAgoraMessage(msg, registry);
    assert.equal(result.valid, false);
    assert.equal(result.signatureValid, false);
    assert.equal(result.knownAgent, true, 'the author is still a registry member');
  });

  it('verifyFeed counts an unregistered author as invalid and names it', () => {
    const { msg } = signedMessage('feed-stranger');
    const feed = appendToFeed(createFeed(), msg);
    const result = verifyFeed(feed, createRegistry());
    assert.equal(result.total, 1);
    assert.equal(result.valid, 0);
    assert.equal(result.invalid.length, 1);
    assert.ok(result.invalid[0].includes(msg.id));
    assert.ok(result.invalid[0].includes('registry'));
  });
});
