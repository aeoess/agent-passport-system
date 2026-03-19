// Feasibility Linting — Types (Gap 7)
// Cheap preflight checks that catch 90% of impossible missions

export type FeasibilitySeverity = 'error' | 'warning' | 'info'

export interface FeasibilityIssue {
  code: string              // e.g., 'EXPIRED_DELEGATION', 'SCOPE_MISMATCH'
  severity: FeasibilitySeverity
  message: string
  field?: string            // which field has the problem
}

export interface FeasibilityResult {
  feasible: boolean         // true if no errors (warnings OK)
  issues: FeasibilityIssue[]
  errorCount: number
  warningCount: number
}
