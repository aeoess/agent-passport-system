// Feasibility Linting — Module (Gap 7)
// Cheap preflight checks at delegation-time and task-time
// Catches 90% of impossible missions with 10% of the effort

import type { Delegation } from '../types/passport.js'
import type { TaskRoleSpec } from '../types/coordination.js'
import type { FeasibilityIssue, FeasibilityResult } from '../types/feasibility.js'
import { scopeCovers } from './delegation.js'

function result(issues: FeasibilityIssue[]): FeasibilityResult {
  const errorCount = issues.filter(i => i.severity === 'error').length
  const warningCount = issues.filter(i => i.severity === 'warning').length
  return {
    feasible: errorCount === 0,
    issues,
    errorCount,
    warningCount,
  }
}

// ══════════════════════════════════════
// DELEGATION LINTING
// ══════════════════════════════════════

/**
 * Lint a delegation for obvious problems BEFORE signing.
 * Call this at delegation-creation time to catch bad inputs early.
 */
export function lintDelegation(opts: {
  delegatedTo: string
  delegatedBy: string
  scope: string[]
  spendLimit?: number
  maxDepth?: number
  currentDepth?: number
  expiresInHours?: number
}): FeasibilityResult {
  const issues: FeasibilityIssue[] = []

  // 1. Empty scope — delegation grants nothing
  if (!opts.scope || opts.scope.length === 0) {
    issues.push({
      code: 'EMPTY_SCOPE',
      severity: 'error',
      message: 'Delegation has no scope — grants zero permissions',
      field: 'scope',
    })
  }

  // 2. Self-delegation — delegating to yourself
  if (opts.delegatedTo && opts.delegatedTo === opts.delegatedBy) {
    issues.push({
      code: 'SELF_DELEGATION',
      severity: 'warning',
      message: 'Agent is delegating to itself',
      field: 'delegatedTo',
    })
  }

  // 3. Missing identity fields
  if (!opts.delegatedTo) {
    issues.push({
      code: 'MISSING_DELEGATE',
      severity: 'error',
      message: 'No delegate specified (delegatedTo is empty)',
      field: 'delegatedTo',
    })
  }
  if (!opts.delegatedBy) {
    issues.push({
      code: 'MISSING_DELEGATOR',
      severity: 'error',
      message: 'No delegator specified (delegatedBy is empty)',
      field: 'delegatedBy',
    })
  }

  // 4. Negative or zero spend limit
  if (opts.spendLimit !== undefined) {
    if (opts.spendLimit < 0) {
      issues.push({
        code: 'NEGATIVE_SPEND',
        severity: 'error',
        message: `Spend limit is negative: ${opts.spendLimit}`,
        field: 'spendLimit',
      })
    }
    if (opts.spendLimit === 0) {
      issues.push({
        code: 'ZERO_SPEND',
        severity: 'warning',
        message: 'Spend limit is zero — no spending permitted',
        field: 'spendLimit',
      })
    }
  }

  // 5. Depth already exceeded
  const depth = opts.currentDepth ?? 0
  const maxD = opts.maxDepth ?? 1
  if (depth > maxD) {
    issues.push({
      code: 'DEPTH_EXCEEDED',
      severity: 'error',
      message: `Current depth ${depth} exceeds max depth ${maxD}`,
      field: 'currentDepth',
    })
  }
  if (depth === maxD) {
    issues.push({
      code: 'DEPTH_AT_LIMIT',
      severity: 'warning',
      message: `Depth at limit (${depth}/${maxD}) — no further sub-delegation possible`,
      field: 'currentDepth',
    })
  }

  // 6. Zero or negative expiry
  if (opts.expiresInHours !== undefined && opts.expiresInHours <= 0) {
    issues.push({
      code: 'EXPIRED_AT_CREATION',
      severity: 'error',
      message: `Delegation expires immediately or in the past (${opts.expiresInHours}h)`,
      field: 'expiresInHours',
    })
  }

  // 7. Very short expiry warning
  if (opts.expiresInHours !== undefined && opts.expiresInHours > 0 && opts.expiresInHours < 1) {
    issues.push({
      code: 'SHORT_EXPIRY',
      severity: 'warning',
      message: `Delegation expires in less than 1 hour (${opts.expiresInHours}h)`,
      field: 'expiresInHours',
    })
  }

  // 8. Wildcard scope warning
  if (opts.scope && opts.scope.some(s => s === '*')) {
    issues.push({
      code: 'WILDCARD_SCOPE',
      severity: 'warning',
      message: 'Delegation grants wildcard (*) scope — no restrictions on actions',
      field: 'scope',
    })
  }

  return result(issues)
}

// ══════════════════════════════════════
// TASK FEASIBILITY LINTING
// ══════════════════════════════════════

/**
 * Check if a delegation can feasibly complete a task role.
 * Call at task-assignment time to catch mismatches early.
 */
export function lintTaskFeasibility(opts: {
  delegation: Delegation
  role: TaskRoleSpec
  taskDeadline?: string       // ISO timestamp
}): FeasibilityResult {
  const issues: FeasibilityIssue[] = []
  const { delegation, role } = opts

  // 1. Scope coverage — does delegation cover required scopes?
  for (const required of role.allowedScopes) {
    const covered = delegation.scope.some(ds => scopeCovers(ds, required))
    if (!covered) {
      issues.push({
        code: 'SCOPE_MISMATCH',
        severity: 'error',
        message: `Delegation scope [${delegation.scope.join(', ')}] does not cover required scope "${required}"`,
        field: 'scope',
      })
    }
  }

  // 2. Forbidden scope violation — delegation grants a forbidden scope
  for (const forbidden of role.forbiddenScopes) {
    const granted = delegation.scope.some(ds => scopeCovers(ds, forbidden))
    if (granted) {
      issues.push({
        code: 'FORBIDDEN_SCOPE',
        severity: 'warning',
        message: `Delegation grants "${forbidden}" which is forbidden for this role`,
        field: 'scope',
      })
    }
  }

  // 3. Delegation expires before task deadline
  if (opts.taskDeadline) {
    const delegationExpiry = new Date(delegation.expiresAt)
    const deadline = new Date(opts.taskDeadline)
    if (delegationExpiry < deadline) {
      issues.push({
        code: 'DELEGATION_EXPIRES_BEFORE_DEADLINE',
        severity: 'error',
        message: `Delegation expires ${delegation.expiresAt} but task deadline is ${opts.taskDeadline}`,
        field: 'expiresAt',
      })
    }
  }

  // 4. Delegation already expired
  if (new Date(delegation.expiresAt) < new Date()) {
    issues.push({
      code: 'DELEGATION_EXPIRED',
      severity: 'error',
      message: `Delegation expired at ${delegation.expiresAt}`,
      field: 'expiresAt',
    })
  }

  // 5. No remaining spend budget
  if (delegation.spendLimit !== undefined) {
    const remaining = delegation.spendLimit - (delegation.spentAmount ?? 0)
    if (remaining <= 0) {
      issues.push({
        code: 'BUDGET_EXHAUSTED',
        severity: 'error',
        message: `Delegation budget exhausted: spent ${delegation.spentAmount} of ${delegation.spendLimit}`,
        field: 'spendLimit',
      })
    }
  }

  // 6. Depth at limit — cannot sub-delegate if task requires it
  if (delegation.currentDepth >= delegation.maxDepth) {
    issues.push({
      code: 'CANNOT_SUBDELEGATE',
      severity: 'info',
      message: `Delegation at depth limit (${delegation.currentDepth}/${delegation.maxDepth}) — sub-delegation not possible`,
      field: 'currentDepth',
    })
  }

  return result(issues)
}

// ══════════════════════════════════════
// GATEWAY-COMPATIBLE DELEGATION LINTING
// ══════════════════════════════════════
// Only 2 checks that work against current gateway schema.
// Advisory only. Does NOT emit reputation signals.
// Infeasible delegations are ADMIN mistakes, not agent misbehavior.

export interface GatewayLintResult {
  severity: 'error' | 'warning'
  code: string
  message: string
}

export interface GatewayLintReport {
  delegation_id?: string
  checks_run: number
  checks_skipped: number
  skipped_reasons: string[]
  errors: number
  warnings: number
  results: GatewayLintResult[]
}

/**
 * Lint a delegation against a task context using only checks
 * that the gateway can actually enforce.
 *
 * When context is not provided, checks that depend on it are skipped
 * and listed in skipped_reasons. An empty-context call returns a report
 * that says "N checks skipped" — not a false "clean" report.
 */
export function lintDelegationForGateway(
  delegation: Delegation,
  context?: {
    requiredScopes?: string[]
    estimatedSpend?: number
  },
): GatewayLintReport {
  const results: GatewayLintResult[] = []
  let checksRun = 0
  let checksSkipped = 0
  const skippedReasons: string[] = []

  // ── Check 1: SPEND_TOO_LOW ──
  if (delegation.spendLimit !== undefined && context?.estimatedSpend !== undefined) {
    checksRun++
    if (delegation.spendLimit < context.estimatedSpend) {
      results.push({
        severity: 'error',
        code: 'SPEND_TOO_LOW',
        message: `Spend limit ($${delegation.spendLimit}) is below estimated task cost ($${context.estimatedSpend}).`,
      })
    }
  } else {
    checksSkipped++
    if (context?.estimatedSpend === undefined) {
      skippedReasons.push('estimatedSpend not provided')
    } else {
      skippedReasons.push('spendLimit not set on delegation')
    }
  }

  // ── Check 2: SCOPE_MISSING ──
  if (context?.requiredScopes && context.requiredScopes.length > 0) {
    checksRun++
    const missingScopes = context.requiredScopes.filter(
      required => !delegation.scope.some(granted => scopeCovers(granted, required)),
    )
    if (missingScopes.length > 0) {
      results.push({
        severity: 'error',
        code: 'SCOPE_MISSING',
        message: `Task requires scope '${missingScopes.join("', '")}' but delegation grants [${delegation.scope.map(s => `'${s}'`).join(', ')}].`,
      })
    }
  } else {
    checksSkipped++
    skippedReasons.push('requiredScopes not provided')
  }

  // ── Skipped checks (gateway schema limitations) ──
  checksSkipped += 3
  skippedReasons.push(
    'ALREADY_EXPIRED: expiresAt not in gateway delegations table',
    'DEADLINE_IMPOSSIBLE: expiresAt not available',
    'DEPTH_MAXED: currentDepth not tracked by gateway',
  )

  return {
    delegation_id: delegation.delegationId,
    checks_run: checksRun,
    checks_skipped: checksSkipped,
    skipped_reasons: skippedReasons,
    errors: results.filter(r => r.severity === 'error').length,
    warnings: results.filter(r => r.severity === 'warning').length,
    results,
  }
}
