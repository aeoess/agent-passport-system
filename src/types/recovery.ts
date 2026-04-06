// ══════════════════════════════════════════════════════════════════
// Recovery Policy — Standard Failure and Recovery Patterns
// ══════════════════════════════════════════════════════════════════
// When an agent action is denied or a tool call fails, the recovery
// policy prescribes what happens next. This replaces ad-hoc error
// handling with configurable, auditable recovery behavior.
//
// Fills the "standard failure patterns" gap identified in enterprise
// agent orchestration (ref: Nate B Jones, agent stack Layer 6).
// ══════════════════════════════════════════════════════════════════

/**
 * Recovery strategy for a denied or failed agent action.
 */
export type RecoveryStrategy =
  | 'retry_narrower'      // Retry with reduced scope (e.g., read-only instead of read-write)
  | 'retry_backoff'       // Retry same action with exponential backoff
  | 'escalate_human'      // Route to human principal for manual decision
  | 'escalate_operator'   // Route to operator agent for re-evaluation
  | 'degrade_scope'       // Continue with reduced delegation scope
  | 'degrade_autonomy'    // Drop autonomy level (e.g., from autonomous to supervised)
  | 'substitute_tool'     // Try an alternative tool for the same goal
  | 'terminate'           // End the delegation chain, agent stops
  | 'quarantine'          // Suspend agent, preserve state for investigation
  | 'ignore'              // Log and continue (for non-critical failures)

/**
 * Condition that triggers a specific recovery strategy.
 */
export interface RecoveryTrigger {
  /** What kind of failure triggers this recovery */
  failureType:
    | 'scope_denied'           // Action outside delegation scope
    | 'budget_exceeded'        // Spend limit reached
    | 'merchant_blocked'       // Merchant not on allowlist
    | 'passport_expired'       // Agent passport expired
    | 'delegation_revoked'     // Delegation chain revoked
    | 'tool_error'             // External tool returned an error
    | 'tool_timeout'           // External tool didn't respond in time
    | 'rate_limited'           // Rate limit hit on external service
    | 'human_denied'           // Human principal rejected the action
    | 'policy_violation'       // Values floor constraint violated
    | 'behavioral_drift'       // Agent behavior deviates from expected pattern
    | 'unknown'                // Catch-all for unclassified failures
  /** Optional: only trigger if consecutive failure count exceeds this */
  afterConsecutiveFailures?: number
  /** Optional: only trigger if failure occurs within this time window (ISO 8601 duration) */
  withinWindow?: string
}

/**
 * A single recovery rule: when trigger matches, apply strategy.
 */
export interface RecoveryRule {
  /** Human-readable name for this rule */
  name: string
  /** When this rule activates */
  trigger: RecoveryTrigger
  /** What to do when triggered */
  strategy: RecoveryStrategy
  /** For retry strategies: max attempts before falling through to next rule */
  maxRetries?: number
  /** For retry_backoff: initial delay in milliseconds */
  initialBackoffMs?: number
  /** For degrade_scope: which scopes to remove */
  scopesToRemove?: string[]
  /** For escalate_human: context message for the human */
  escalationMessage?: string
  /** For substitute_tool: alternative tool identifier */
  alternativeTool?: string
  /** Priority (lower = evaluated first). Default: 100 */
  priority?: number
}

/**
 * Complete recovery policy for an agent or delegation.
 * Evaluated top-down by priority. First matching rule wins.
 */
export interface RecoveryPolicy {
  /** Policy identifier */
  policyId: string
  /** Policy version (for auditability) */
  version: string
  /** Rules evaluated in priority order */
  rules: RecoveryRule[]
  /** Default strategy if no rule matches */
  defaultStrategy: RecoveryStrategy
  /** Max total recovery attempts across all rules before hard stop */
  maxTotalAttempts: number
  /** If true, every recovery action produces a signed receipt */
  auditRecoveryActions: boolean
}

/**
 * Record of a recovery action taken. Signed and appended to audit trail.
 */
export interface RecoveryEvent {
  eventId: string
  timestamp: string
  agentId: string
  delegationId: string
  /** The original action that failed */
  failedAction: string
  /** What went wrong */
  failureType: RecoveryTrigger['failureType']
  /** Error detail from the original failure */
  failureDetail: string
  /** Which rule matched */
  matchedRule: string
  /** What recovery strategy was applied */
  strategyApplied: RecoveryStrategy
  /** Attempt number (1-indexed) */
  attemptNumber: number
  /** Whether recovery succeeded */
  recoverySucceeded: boolean
  /** If recovery produced a new action, its receipt ID */
  recoveryReceiptId?: string
}
