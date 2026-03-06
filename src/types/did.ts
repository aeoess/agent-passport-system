// Agent Passport System — W3C DID & Verifiable Credentials Types
// Implements W3C DID Core (https://www.w3.org/TR/did-core/)
// and W3C VC Data Model 2.0 (https://www.w3.org/TR/vc-data-model-2.0/)

// ── DID Document (W3C DID Core) ──

export interface DIDDocument {
  '@context': string[]
  id: string                           // did:aps:<hex-public-key>
  controller: string | string[]        // DID of the controlling entity
  verificationMethod: VerificationMethod[]
  authentication: string[]             // refs to verification methods
  assertionMethod: string[]            // for signing VCs
  capabilityDelegation?: string[]      // for issuing delegations
  service?: ServiceEndpoint[]
  created: string
  updated: string
}

export interface VerificationMethod {
  id: string                           // did:aps:<key>#key-1
  type: 'Ed25519VerificationKey2020'
  controller: string
  publicKeyMultibase: string           // z-prefixed base58btc of Ed25519 public key
}

export interface ServiceEndpoint {
  id: string
  type: string
  serviceEndpoint: string
}

// ── Verifiable Credential (W3C VC Data Model 2.0) ──

export interface VerifiableCredential {
  '@context': string[]
  id: string
  type: string[]
  issuer: string | { id: string; name?: string }
  issuanceDate: string
  expirationDate?: string
  credentialSubject: Record<string, unknown>
  proof: LinkedDataProof
}

export interface LinkedDataProof {
  type: 'Ed25519Signature2020'
  created: string
  verificationMethod: string           // did:aps:<key>#key-1
  proofPurpose: 'assertionMethod' | 'authentication' | 'capabilityDelegation'
  proofValue: string                   // base64url-encoded Ed25519 signature
}

// ── Verifiable Presentation ──

export interface VerifiablePresentation {
  '@context': string[]
  id: string
  type: string[]
  holder: string                       // DID of the presenting agent
  verifiableCredential: VerifiableCredential[]
  proof: LinkedDataProof
}

// ── Credential Subject types for each protocol artifact ──

export interface PassportCredentialSubject {
  id: string                           // DID of the agent
  agentName: string
  ownerAlias: string
  mission: string
  capabilities: string[]
  runtime: {
    platform: string
    models: string[]
  }
  beneficiary?: string
}

export interface DelegationCredentialSubject {
  id: string                           // DID of the delegate
  delegatedBy: string                  // DID of the delegator
  scope: string[]
  spendLimit?: number
  maxDepth: number
  currentDepth: number
  expiresAt: string
}

export interface FloorAttestationCredentialSubject {
  id: string                           // DID of the attesting agent
  floorVersion: string
  principles: string[]
  extensions?: string[]
  attestedAt: string
}

export interface PolicyReceiptCredentialSubject {
  id: string                           // DID of the acting agent
  intentId: string
  actionType: string
  target: string
  verdict: 'approve' | 'deny' | 'escalate'
  rationale: string
  signatureChain: {
    intentSignature: string
    evaluationSignature: string
    receiptSignature: string
  }
}

// ── DID Resolution ──

export interface DIDResolutionResult {
  didDocument: DIDDocument | null
  didDocumentMetadata: {
    created: string
    updated: string
    deactivated?: boolean
  }
  didResolutionMetadata: {
    contentType: string
    error?: string
  }
}
