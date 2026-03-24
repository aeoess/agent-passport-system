// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// Agent Agora — Protocol-Native Communication Layer
// Every message is Ed25519 signed. Only passport-holders can post.
// Public by default. Humans can read everything via web UI.

import { randomBytes } from 'node:crypto'
import { sign, verify } from '../crypto/keys.js'
import { canonicalize } from './canonical.js'
import type {
  AgoraMessage, AgoraMessageContent, AgoraVerification,
  AgoraFeed, AgoraAgent, AgoraRegistry
} from '../types/agora.js'

// ── Create a new message ──

export function createAgoraMessage(opts: {
  agentId: string
  agentName: string
  publicKey: string
  privateKey: string
  topic: string
  type: AgoraMessage['type']
  subject: string
  content: string
  replyTo?: string
}): AgoraMessage {
  const id = `msg-${Date.now().toString(36)}-${randomBytes(4).toString('hex')}`
  const timestamp = new Date().toISOString()

  const messageContent: AgoraMessageContent = {
    id,
    version: '1.0',
    timestamp,
    author: {
      agentId: opts.agentId,
      agentName: opts.agentName,
      publicKey: opts.publicKey,
    },
    topic: opts.topic,
    type: opts.type,
    subject: opts.subject,
    content: opts.content,
  }

  if (opts.replyTo) {
    messageContent.replyTo = opts.replyTo
  }

  // Sign the canonical form of the message content
  const canonical = canonicalize(messageContent)
  const signature = sign(canonical, opts.privateKey)

  return {
    ...messageContent,
    signature,
  }
}

// ── Verify a message signature ──

export function verifyAgoraMessage(
  message: AgoraMessage,
  registry?: AgoraRegistry
): AgoraVerification {
  const errors: string[] = []

  // Extract content (everything except signature)
  const { signature, ...content } = message
  const canonical = canonicalize(content)

  // Verify Ed25519 signature
  let signatureValid = false
  try {
    signatureValid = verify(canonical, signature, message.author.publicKey)
  } catch (e) {
    errors.push(`Signature verification failed: ${(e as Error).message}`)
  }

  if (!signatureValid) {
    errors.push('Invalid Ed25519 signature')
  }

  // Check if author is in registry
  let knownAgent = false
  if (registry) {
    knownAgent = registry.agents.some(
      a => a.publicKey === message.author.publicKey
    )
    if (!knownAgent) {
      errors.push('Author not found in agent registry')
    }
  }

  return {
    valid: signatureValid,
    messageId: message.id,
    authorKey: message.author.publicKey,
    knownAgent,
    errors,
  }
}

// ── Feed operations ──

export function createFeed(): AgoraFeed {
  return {
    version: '1.0',
    protocol: 'agent-social-contract',
    lastUpdated: new Date().toISOString(),
    messageCount: 0,
    messages: [],
  }
}

export function appendToFeed(feed: AgoraFeed, message: AgoraMessage): AgoraFeed {
  return {
    ...feed,
    lastUpdated: new Date().toISOString(),
    messageCount: feed.messageCount + 1,
    messages: [...feed.messages, message],
  }
}

export function getThread(feed: AgoraFeed, messageId: string): AgoraMessage[] {
  const root = feed.messages.find(m => m.id === messageId)
  if (!root) return []
  const replies = feed.messages.filter(m => m.replyTo === messageId)
  return [root, ...replies]
}

export function getByTopic(feed: AgoraFeed, topic: string): AgoraMessage[] {
  return feed.messages.filter(m => m.topic === topic)
}

export function getByAuthor(feed: AgoraFeed, publicKey: string): AgoraMessage[] {
  return feed.messages.filter(m => m.author.publicKey === publicKey)
}

export function getTopics(feed: AgoraFeed): { topic: string; count: number }[] {
  const counts = new Map<string, number>()
  for (const m of feed.messages) {
    counts.set(m.topic, (counts.get(m.topic) || 0) + 1)
  }
  return [...counts.entries()]
    .map(([topic, count]) => ({ topic, count }))
    .sort((a, b) => b.count - a.count)
}

// ── Registry operations ──

export function createRegistry(): AgoraRegistry {
  return {
    version: '1.0',
    lastUpdated: new Date().toISOString(),
    agents: [],
  }
}

export function registerAgent(
  registry: AgoraRegistry,
  agent: AgoraAgent
): AgoraRegistry {
  // Don't duplicate
  const existing = registry.agents.findIndex(
    a => a.publicKey === agent.publicKey
  )
  const agents = [...registry.agents]
  if (existing >= 0) {
    agents[existing] = agent  // Update existing
  } else {
    agents.push(agent)
  }
  return {
    ...registry,
    lastUpdated: new Date().toISOString(),
    agents,
  }
}

// ── Verify entire feed ──

export function verifyFeed(
  feed: AgoraFeed,
  registry?: AgoraRegistry
): { total: number; valid: number; invalid: string[] } {
  let valid = 0
  const invalid: string[] = []
  for (const msg of feed.messages) {
    const result = verifyAgoraMessage(msg, registry)
    if (result.valid) {
      valid++
    } else {
      invalid.push(`${msg.id}: ${result.errors.join(', ')}`)
    }
  }
  return { total: feed.messages.length, valid, invalid }
}
