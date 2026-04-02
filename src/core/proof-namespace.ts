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
