// Agent Passport System — A2A Agent Card Types
// Based on Google's Agent2Agent Protocol (a2aproject/A2A)

export interface A2AAgentCard {
  name: string
  description: string
  url: string
  version: string
  provider?: A2AAgentProvider
  documentationUrl?: string
  capabilities: A2ACapabilities
  defaultInputModes: string[]
  defaultOutputModes: string[]
  skills: A2AAgentSkill[]
  securitySchemes?: Record<string, A2ASecurityScheme>
  security?: Record<string, string[]>[]
  // Agent Passport extension fields
  agentPassport?: {
    did: string
    passportSignature: string
    floorVersion?: string
    delegationChain?: string[]
  }
}

export interface A2AAgentProvider {
  organization: string
  url?: string
}

export interface A2ACapabilities {
  streaming?: boolean
  pushNotifications?: boolean
  stateTransitionHistory?: boolean
  extendedAgentCard?: boolean
}

export interface A2AAgentSkill {
  id: string
  name: string
  description: string
  tags?: string[]
  examples?: string[]
  inputModes?: string[]
  outputModes?: string[]
}

export interface A2ASecurityScheme {
  type: string
  description?: string
  // For bearer/oauth
  scheme?: string
  bearerFormat?: string
  // For openIdConnect
  openIdConnectUrl?: string
}
