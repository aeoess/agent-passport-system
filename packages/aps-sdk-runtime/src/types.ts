/**
 * @aeoess/aps-sdk-runtime — type definitions
 *
 * Mirrors spec Sections 4 (RuntimePassport), 5 (ActionDescriptor),
 * 6 (Decision / Session). All required fields present. Hex hashes are
 * carried as strings at this stage; binary marshaling lands when the
 * N-API binding (Stream A) is wired in.
 */

/** Hex-encoded SHA-256 digest (64 lowercase hex chars in canonical form). */
export type HexHash = string;

/** Opaque passport identifier (URN, DID, or content-addressed handle). */
export type PassportId = string;

/** ISO-8601 UTC timestamp. */
export type Timestamp = string;

// ─────────────────────────────────────────────────────────────────────
// Section 4 — RuntimePassport
// ─────────────────────────────────────────────────────────────────────

export type RiskClass = "low" | "medium" | "high" | "critical";

export interface ScopeGrant {
  readonly tool: string;
  readonly operations: readonly string[];
  readonly resourcePattern?: string;
  readonly maxRiskClass: RiskClass;
}

export interface DelegationChainLink {
  readonly issuer: PassportId;
  readonly subject: PassportId;
  readonly issuedAt: Timestamp;
  readonly expiresAt: Timestamp;
  readonly signature: HexHash;
}

export interface RuntimePassport {
  readonly id: PassportId;
  readonly publicKey: HexHash;
  readonly scopes: readonly ScopeGrant[];
  readonly delegationChain: readonly DelegationChainLink[];
  readonly issuedAt: Timestamp;
  readonly expiresAt: Timestamp;
  readonly signature: HexHash;
}

// ─────────────────────────────────────────────────────────────────────
// Section 5 — ActionDescriptor
// ─────────────────────────────────────────────────────────────────────

export interface ActionDescriptor {
  readonly toolDescriptorHash: HexHash;
  readonly operationId: string;
  readonly resourcePath: string;
  readonly riskClass: RiskClass;
  readonly parametersHash?: HexHash;
  readonly timestamp: Timestamp;
}

// ─────────────────────────────────────────────────────────────────────
// Section 6 — Decision / Session
// ─────────────────────────────────────────────────────────────────────

export type DecisionOutcome = "permit" | "deny" | "indeterminate";

export interface DecisionReason {
  readonly code: string;
  readonly message: string;
}

export interface Decision {
  readonly outcome: DecisionOutcome;
  readonly reason: DecisionReason;
  readonly receiptHash: HexHash;
  readonly evaluatedAt: Timestamp;
  readonly sessionId: string;
}

export interface Session {
  readonly id: string;
  readonly passportId: PassportId;
  readonly openedAt: Timestamp;
  readonly timeAnchor: Timestamp;
  readonly registryEpoch: number;
}
