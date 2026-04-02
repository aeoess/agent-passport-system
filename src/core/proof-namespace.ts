// ══════════════════════════════════════════════════════════════════
// Proof ID Namespacing — Cross-System Interop
// ══════════════════════════════════════════════════════════════════
// Source: desiorac on A2A#1672 — cross-issuer lineage traversal
// requires namespaced proof IDs so resolvers know which system
// issued a receipt and where to verify it.
//
// Format: aps:<receipt_id>
// Resolution: GET gateway.aeoess.com/.well-known/receipts/<id>
// ══════════════════════════════════════════════════════════════════

const APS_NAMESPACE = 'aps'

/**
 * Add APS namespace prefix to a proof/receipt ID.
 * `drv_abc123` → `aps:drv_abc123`
 */
export function namespaceProofId(id: string): string {
  if (id.startsWith(`${APS_NAMESPACE}:`)) return id // already namespaced
  return `${APS_NAMESPACE}:${id}`
}

/**
 * Parse a namespaced proof ID into namespace + bare ID.
 * `aps:drv_abc123` → { namespace: 'aps', id: 'drv_abc123' }
 * `did:arkforge:prf_xyz` → { namespace: 'did:arkforge', id: 'prf_xyz' }
 * `bare_id` → { namespace: null, id: 'bare_id' }
 */
export function parseNamespacedId(namespacedId: string): {
  namespace: string | null
  id: string
  issuer?: string
} {
  // DID-style: did:method:id
  if (namespacedId.startsWith('did:')) {
    const parts = namespacedId.split(':')
    if (parts.length >= 3) {
      const ns = parts.slice(0, 2).join(':') // 'did:aps' or 'did:arkforge'
      const id = parts.slice(2).join(':')
      return { namespace: ns, id }
    }
  }

  // Simple namespace: prefix:id
  const colonIdx = namespacedId.indexOf(':')
  if (colonIdx > 0 && colonIdx < namespacedId.length - 1) {
    return {
      namespace: namespacedId.substring(0, colonIdx),
      id: namespacedId.substring(colonIdx + 1),
    }
  }

  return { namespace: null, id: namespacedId }
}

/**
 * Build a resolution URL for a namespaced proof ID.
 * `aps:drv_abc123` → `https://gateway.aeoess.com/.well-known/receipts/drv_abc123`
 *
 * Known resolvers (WG registry):
 * - aps → gateway.aeoess.com/.well-known/receipts/
 * - (extensible — WG members register their resolver URLs)
 */
const KNOWN_RESOLVERS: Record<string, string> = {
  aps: 'https://gateway.aeoess.com/.well-known/receipts/',
}

export function resolveProofUrl(
  namespacedId: string,
  resolverRegistry?: Record<string, string>
): string | null {
  const parsed = parseNamespacedId(namespacedId)
  if (!parsed.namespace) return null

  const resolvers = { ...KNOWN_RESOLVERS, ...resolverRegistry }
  const baseUrl = resolvers[parsed.namespace]
  if (!baseUrl) return null

  return `${baseUrl}${encodeURIComponent(parsed.id)}`
}


// ══════════════════════════════════════════════════════════════════
// Rekor Anchor Types — Transparency Log Integration
// ══════════════════════════════════════════════════════════════════
// Source: desiorac on A2A#1672 — independent temporal proof
// The gateway submits receipt hashes to Sigstore Rekor.
// Any verifier can confirm existence and timing without trusting the issuer.
// ══════════════════════════════════════════════════════════════════

/** Minimum Rekor anchor payload (4 fields, per cross-issuer resolution spec) */
export interface RekorAnchorPayload {
  /** SHA-256 hash of the canonicalized receipt body */
  receipt_hash: string
  /** Agent DID who produced the receipt */
  agent_did: string
  /** Issuer URL (gateway that signed the receipt) */
  issuer: string
  /** When the receipt was anchored */
  anchored_at: string
}

/** Result of a Rekor submission */
export interface RekorAnchorResult {
  /** Rekor transparency log index */
  logIndex: number
  /** Rekor entry UUID */
  entryUUID: string
  /** Inclusion proof from the Merkle tree */
  inclusionProof?: {
    treeSize: number
    rootHash: string
    hashes: string[]
    logIndex: number
  }
  /** The payload that was anchored */
  payload: RekorAnchorPayload
  /** Whether the anchor was verified against the log */
  verified: boolean
}

/** Verification result when checking a Rekor anchor */
export interface RekorVerificationResult {
  /** Whether the anchor entry exists in Rekor */
  found: boolean
  /** Whether the receipt hash matches the anchored hash */
  hashMatch: boolean
  /** Whether the inclusion proof is valid */
  proofValid: boolean
  /** The anchored timestamp (independent of the issuer) */
  anchoredAt?: string
  /** Errors */
  errors: string[]
}

/**
 * Create a Rekor anchor payload from a receipt hash.
 * This is the 4-field payload that gets submitted to the transparency log.
 * The caller computes the receipt hash (sha256 of canonicalized body).
 */
export function createRekorAnchorPayload(input: {
  /** Pre-computed SHA-256 hash of the receipt body (e.g. "sha256:abc123") */
  receiptHash: string
  agentDid: string
  issuer: string
}): RekorAnchorPayload {
  return {
    receipt_hash: input.receiptHash,
    agent_did: input.agentDid,
    issuer: input.issuer,
    anchored_at: new Date().toISOString(),
  }
}
