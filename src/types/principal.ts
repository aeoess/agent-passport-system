// Agent Passport System — Principal Identity Types
// The human (or organization) behind the agent.
// Creates a cryptographic chain: Principal → Agent.

export type DisclosureLevel = 'public' | 'verified-only' | 'minimal'

/**
 * A Principal is the human or organization that owns/operates agents.
 * They have their own Ed25519 keypair, separate from any agent's keys.
 */
export interface PrincipalIdentity {
  principalId: string
  displayName: string
  publicKey: string           // Ed25519 public key (hex)
  domain?: string             // verifiable domain (e.g. "aeoess.com")
  jurisdiction?: string       // legal context (e.g. "US", "EU")
  contactChannel?: string     // e.g. "telegram:@aeoess", "email:tima@aeoess.com"
  disclosureLevel: DisclosureLevel
  createdAt: string
  metadata: Record<string, unknown>
  /** Optional legal entity binding (e.g. Corpo Wyoming DAO LLC).
   *  Root trust anchor: the entity establishes the maximum authority ceiling
   *  that every downstream delegation narrows from. */
  entityBinding?: EntityBinding
}

/** Legal entity binding — links a principal to a registered legal entity.
 *  The entity proves the agent ecosystem has a legal counterparty
 *  for contracts, regulated payments, and dispute resolution. */
export interface EntityBinding {
  entityId: string              // e.g. "corpo_ent_<uuid>"
  jurisdiction: string          // e.g. "WY", "DE", "SG"
  entityType?: string           // e.g. "dao_llc", "llc", "corp"
  operatingAgreementHash?: string  // sha256 of governance doc
  verificationEndpoint?: string    // e.g. "https://api.corpo.llc/api/v1/entities/{id}"
  boundAt: string               // ISO timestamp of binding
}

/**
 * An Endorsement is the principal's cryptographic sign-off on an agent.
 * "I created/operate this agent and I'm accountable for it."
 * The principal signs the agent's public key + scope, creating a
 * verifiable chain from human to machine.
 */
export interface PrincipalEndorsement {
  endorsementId: string
  principalId: string
  principalPublicKey: string
  agentId: string
  agentPublicKey: string
  scope: string[]             // what the agent can do on the principal's behalf
  relationship: 'creator' | 'operator' | 'employer' | 'sponsor'
  endorsedAt: string
  expiresAt: string
  revoked: boolean
  revokedAt?: string
  revokedReason?: string
  signature: string           // Ed25519 signed by principal's private key
}

/**
 * Selective disclosure: a principal can reveal different amounts
 * of identity information depending on context.
 */
export interface PrincipalDisclosure {
  disclosureId: string
  principalId: string
  level: DisclosureLevel
  // What's revealed at each level:
  // minimal: just principalId hash + signature (verifiable but anonymous)
  // verified-only: principalId + publicKey + domain (revealed to trusted agents)
  // public: everything (full transparency)
  revealedFields: Record<string, unknown>
  proof: string               // signature over revealedFields
  createdAt: string
}

/**
 * Fleet: a principal's collection of endorsed agents.
 */
export interface FleetRecord {
  principalId: string
  principalPublicKey: string
  agents: FleetAgent[]
  createdAt: string
  updatedAt: string
}

export interface FleetAgent {
  agentId: string
  agentPublicKey: string
  endorsementId: string
  relationship: PrincipalEndorsement['relationship']
  status: 'active' | 'revoked' | 'expired'
  endorsedAt: string
}

/**
 * Result of verifying an endorsement.
 */
export interface EndorsementVerification {
  valid: boolean
  expired: boolean
  revoked: boolean
  principalId: string
  agentId: string
  errors: string[]
}
