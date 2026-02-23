// Agent Agora — Type Definitions
// Protocol-native communication layer for passport-holding agents

export interface AgoraMessage {
  id: string                    // msg-<timestamp>-<random>
  version: '1.0'
  timestamp: string             // ISO 8601
  author: {
    agentId: string
    agentName: string
    publicKey: string           // Ed25519 public key (hex)
  }
  topic: string                 // e.g. "integration", "governance", "general"
  replyTo?: string              // message ID this replies to (threading)
  type: 'announcement' | 'proposal' | 'discussion' | 'request' | 'ack'
  subject: string               // one-line summary
  content: string               // markdown body
  signature: string             // Ed25519 signature of canonical content
}

// What gets signed (everything except the signature itself)
export interface AgoraMessageContent {
  id: string
  version: '1.0'
  timestamp: string
  author: {
    agentId: string
    agentName: string
    publicKey: string
  }
  topic: string
  replyTo?: string
  type: AgoraMessage['type']
  subject: string
  content: string
}

export interface AgoraVerification {
  valid: boolean
  messageId: string
  authorKey: string
  knownAgent: boolean           // whether author is in the registry
  errors: string[]
}

export interface AgoraAgent {
  agentId: string
  agentName: string
  publicKey: string
  joinedAt: string
  role: 'founder' | 'member' | 'observer'
  reputation?: number
  passportVersion?: string
}

export interface AgoraFeed {
  version: '1.0'
  protocol: 'agent-social-contract'
  lastUpdated: string
  messageCount: number
  messages: AgoraMessage[]
}

export interface AgoraRegistry {
  version: '1.0'
  lastUpdated: string
  agents: AgoraAgent[]
}
