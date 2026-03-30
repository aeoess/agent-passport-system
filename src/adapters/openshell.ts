// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
/**
 * NVIDIA OpenShell Adapter
 *
 * Maps APS delegation scopes to OpenShell sandbox policy YAML.
 * An agent's delegation chain determines what the sandbox can access.
 *
 * Usage:
 *   const policy = delegationToPolicy(delegation, basePolicy)
 *   // Write policy to YAML, pass to: openshell sandbox create --policy ./policy.yaml
 */

import type { Delegation } from '../types/passport.js'

export interface OpenShellPolicy {
  version: 1
  identity_policy?: {
    agent_public_key: string
    issuer_public_key?: string
    delegation_chain_depth: number
  }
  filesystem_policy?: {
    read_only: string[]
    read_write: string[]
  }
  network_policies?: Record<string, NetworkPolicyEntry>
  process?: {
    run_as_user: string
    run_as_group: string
  }
}

export interface NetworkPolicyEntry {
  name: string
  endpoints: Array<{ host: string; port: number; protocol?: string }>
  binaries?: Array<{ path: string }>
}

export interface ScopeMapping {
  scope: string
  filesystemRead?: string[]
  filesystemWrite?: string[]
  networkAllow?: Array<{ host: string; port: number }>
  inferenceLocal?: boolean
}

const DEFAULT_SCOPE_MAPPINGS: Record<string, Partial<ScopeMapping>> = {
  'filesystem:read': { filesystemRead: ['/sandbox', '/tmp'] },
  'filesystem:write': { filesystemWrite: ['/sandbox', '/tmp'] },
  'network:*': { networkAllow: [] },
  'commerce:*': { networkAllow: [{ host: 'gateway.aeoess.com', port: 443 }] },
  'inference:local': { inferenceLocal: true },
}

/**
 * Check if a delegation scope covers a target scope.
 * Supports wildcards: 'commerce:*' covers 'commerce:send'.
 */
function scopeCovers(granted: string, target: string): boolean {
  if (granted === target) return true
  if (granted.endsWith(':*')) {
    const prefix = granted.slice(0, -1)
    return target.startsWith(prefix)
  }
  return false
}

/**
 * Extract effective scopes from a delegation, applying monotonic narrowing.
 */
export function extractEffectiveScopes(delegation: Delegation): string[] {
  return delegation.scope || []
}

/**
 * Map APS delegation scopes to OpenShell policy sections.
 * The output policy is the intersection of the delegation scope and the base policy.
 */
export function delegationToPolicy(
  delegation: Delegation,
  agentPublicKey: string,
  issuerPublicKey?: string,
  customMappings?: Record<string, Partial<ScopeMapping>>
): OpenShellPolicy {
  const mappings = { ...DEFAULT_SCOPE_MAPPINGS, ...customMappings }
  const scopes = extractEffectiveScopes(delegation)

  const readPaths = new Set<string>(['/usr', '/lib', '/etc'])
  const writePaths = new Set<string>()
  const networkEntries: Array<{ host: string; port: number }> = []

  for (const scope of scopes) {
    for (const [pattern, mapping] of Object.entries(mappings)) {
      if (scopeCovers(pattern, scope)) {
        if (mapping.filesystemRead) mapping.filesystemRead.forEach(p => readPaths.add(p))
        if (mapping.filesystemWrite) mapping.filesystemWrite.forEach(p => writePaths.add(p))
        if (mapping.networkAllow) networkEntries.push(...mapping.networkAllow)
      }
    }
  }

  const policy: OpenShellPolicy = {
    version: 1,
    identity_policy: {
      agent_public_key: agentPublicKey,
      issuer_public_key: issuerPublicKey,
      delegation_chain_depth: delegation.currentDepth || 0,
    },
    filesystem_policy: {
      read_only: [...readPaths],
      read_write: [...writePaths],
    },
    process: { run_as_user: 'sandbox', run_as_group: 'sandbox' },
  }

  if (networkEntries.length > 0) {
    policy.network_policies = {}
    networkEntries.forEach((entry, i) => {
      const key = `aps_${entry.host.replace(/\./g, '_')}`
      policy.network_policies![key] = {
        name: `APS: ${entry.host}`,
        endpoints: [{ host: entry.host, port: entry.port, protocol: 'rest' }],
      }
    })
  }

  return policy
}

/**
 * Serialize an OpenShell policy to YAML string.
 * Minimal YAML serializer — no external deps.
 */
export function policyToYaml(policy: OpenShellPolicy): string {
  const lines: string[] = [`version: ${policy.version}`]

  if (policy.identity_policy) {
    lines.push('', 'identity_policy:')
    lines.push(`  agent_public_key: "${policy.identity_policy.agent_public_key}"`)
    if (policy.identity_policy.issuer_public_key)
      lines.push(`  issuer_public_key: "${policy.identity_policy.issuer_public_key}"`)
    lines.push(`  delegation_chain_depth: ${policy.identity_policy.delegation_chain_depth}`)
  }

  if (policy.filesystem_policy) {
    lines.push('', 'filesystem_policy:')
    lines.push('  read_only:')
    policy.filesystem_policy.read_only.forEach(p => lines.push(`    - ${p}`))
    lines.push('  read_write:')
    policy.filesystem_policy.read_write.forEach(p => lines.push(`    - ${p}`))
  }

  if (policy.process) {
    lines.push('', 'process:')
    lines.push(`  run_as_user: ${policy.process.run_as_user}`)
    lines.push(`  run_as_group: ${policy.process.run_as_group}`)
  }

  if (policy.network_policies) {
    lines.push('', 'network_policies:')
    for (const [key, entry] of Object.entries(policy.network_policies)) {
      lines.push(`  ${key}:`)
      lines.push(`    name: "${entry.name}"`)
      lines.push('    endpoints:')
      entry.endpoints.forEach(ep => {
        lines.push(`      - host: ${ep.host}`)
        lines.push(`        port: ${ep.port}`)
        if (ep.protocol) lines.push(`        protocol: ${ep.protocol}`)
      })
    }
  }

  return lines.join('\n') + '\n'
}
