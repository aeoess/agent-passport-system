// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
/**
 * Cedar Policy Format Bridge for IBAC
 *
 * Converts between Cedar-style policy strings and IBAC tuples,
 * and between APS delegations and Cedar policy format.
 * No external dependencies.
 */

import type { Delegation } from '../types/passport.js'
import type { IBACTuple } from './ibac.js'

/**
 * Parse a Cedar-style policy string into IBAC tuples.
 *
 * Supported format:
 *   permit(principal == "agent:agent-123", action == "tool:query_db", resource == "table:patients");
 *   permit(principal == "agent:agent-123", action == "tool:read", resource == "file:report.pdf")
 *     when { max_rows < 100 };
 */
export function cedarPolicyToTuples(cedarPolicy: string): IBACTuple[] {
  const tuples: IBACTuple[] = []
  const lines = cedarPolicy.split(';').map(l => l.trim()).filter(Boolean)

  for (const line of lines) {
    const match = line.match(
      /permit\s*\(\s*principal\s*==\s*"([^"]+)"\s*,\s*action\s*==\s*"([^"]+)"\s*,\s*resource\s*==\s*"([^"]+)"\s*\)/
    )
    if (!match) continue

    const tuple: IBACTuple = {
      principal: match[1],
      action: match[2],
      resource: match[3],
    }

    // Parse optional "when { ... }" constraints
    const whenMatch = line.match(/when\s*\{([^}]+)\}/)
    if (whenMatch) {
      const constraints: Record<string, unknown> = {}
      const pairs = whenMatch[1].split(',').map(s => s.trim()).filter(Boolean)
      for (const pair of pairs) {
        const kv = pair.match(/(\w+)\s*(<|>|<=|>=|==)\s*(\S+)/)
        if (kv) {
          const val = isNaN(Number(kv[3])) ? kv[3].replace(/"/g, '') : Number(kv[3])
          constraints[kv[1]] = val
        }
      }
      if (Object.keys(constraints).length > 0) {
        tuple.constraints = constraints
      }
    }

    tuples.push(tuple)
  }

  return tuples
}

/**
 * Generate a Cedar-style policy string from an APS delegation.
 * Each scope in the delegation becomes a separate permit statement.
 */
export function delegationToCedarPolicy(delegation: Delegation): string {
  const principal = `agent:${delegation.delegatedTo}`
  const statements = delegation.scope.map(scope => {
    // Parse scope format: "prefix:verb:resource" or "prefix:verb"
    const parts = scope.split(':')
    let action: string
    let resource: string

    if (parts.length >= 3) {
      action = `tool:${parts[1]}`
      resource = parts.slice(2).join(':')
    } else if (parts.length === 2) {
      action = `tool:${parts[1]}`
      resource = `${parts[0]}:*`
    } else {
      action = `tool:${scope}`
      resource = '*'
    }

    return `permit(\n  principal == "${principal}",\n  action == "${action}",\n  resource == "${resource}"\n)`
  })

  return statements.join(';\n\n') + ';'
}
