// Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// ══════════════════════════════════════════════════════════════════
// x402 protocol shapes — v1 wire types
// ══════════════════════════════════════════════════════════════════
// Mirrors coinbase/x402 specs/x402-specification-v1.md exactly so
// PaymentRequirements built by this rail are valid as 402 response
// bodies and PaymentPayload values produced by an x402 client can
// be passed to the facilitator unchanged.
//
// Field names are spec-literal (camelCase, no aliasing). Strings
// carry numeric values for atomic units, unix timestamps, and
// nonces — matching the spec's avoidance of JS-number precision.
//
// The 'exact' scheme on EVM signs an EIP-3009 transferWithAuthorization
// authorization off-chain; the facilitator submits the on-chain
// transaction at /settle. APS records the resulting transaction hash
// as tx_proof on the signed PaymentReceipt.
// ══════════════════════════════════════════════════════════════════

/**
 * Network identifier per x402 v1. Open string union — the spec lists
 * a known set today (base, base-sepolia, avalanche, avalanche-fuji,
 * ethereum-mainnet, iotex), but new networks can be added without an
 * SDK upgrade.
 */
export type X402Network =
  | 'base'
  | 'base-sepolia'
  | 'avalanche'
  | 'avalanche-fuji'
  | 'ethereum-mainnet'
  | 'iotex'
  | (string & {})

/** Payment scheme. Only 'exact' is widely deployed in v1. */
export type X402Scheme = 'exact' | (string & {})

/** Always 1 in v1. Reserved for forward-compatible negotiation. */
export const X402_VERSION = 1 as const

// ── PaymentRequirements (server → client, 402 body) ────────────────

export interface X402PaymentRequirements {
  scheme: X402Scheme
  network: X402Network
  /** Required payment amount in atomic token units (e.g., USDC has 6
   *  decimals, so 1 USDC = "1000000"). */
  maxAmountRequired: string
  /** Token contract address (e.g., USDC on Base). */
  asset: string
  /** Recipient wallet address. */
  payTo: string
  /** URL of the protected resource being paid for. */
  resource: string
  /** Human-readable description of the resource. */
  description: string
  mimeType?: string
  outputSchema?: Record<string, unknown>
  /** Maximum time allowed for payment completion. */
  maxTimeoutSeconds: number
  /** Scheme-specific additional information (EIP-712 domain, etc). */
  extra?: Record<string, unknown>
}

/** Body of the resource server's 402 response. */
export interface X402PaymentRequirementsResponse {
  x402Version: number
  /** Optional error message when the 402 is in response to a failed
   *  payment attempt rather than the initial request. */
  error?: string
  accepts: X402PaymentRequirements[]
}

// ── EIP-3009 authorization (signed off-chain by client) ────────────

export interface EIP3009Authorization {
  /** Payer address. */
  from: string
  /** Recipient address (matches PaymentRequirements.payTo). */
  to: string
  /** Atomic units; matches PaymentRequirements.maxAmountRequired. */
  value: string
  /** Unix timestamp seconds when authorization becomes valid. */
  validAfter: string
  /** Unix timestamp seconds when authorization expires. */
  validBefore: string
  /** 32-byte hex nonce (0x-prefixed) preventing replay. */
  nonce: string
}

/** Payload for the 'exact' scheme. */
export interface X402ExactSchemePayload {
  /** EIP-712 signature of the EIP-3009 TransferWithAuthorization
   *  typed data. 65-byte secp256k1 signature, 0x-prefixed hex. */
  signature: string
  authorization: EIP3009Authorization
}

// ── PaymentPayload (client → server, X-PAYMENT body) ───────────────

export interface X402PaymentPayload {
  x402Version: number
  scheme: X402Scheme
  network: X402Network
  /** Scheme-specific payload. For 'exact', X402ExactSchemePayload. */
  payload: X402ExactSchemePayload | Record<string, unknown>
}

// ── Facilitator API: /verify ──────────────────────────────────────

export interface X402VerifyRequest {
  x402Version: number
  paymentPayload: X402PaymentPayload
  paymentRequirements: X402PaymentRequirements
}

export interface X402VerifyResponse {
  isValid: boolean
  /** Set when isValid=false; closed taxonomy is facilitator-defined.
   *  Common values include 'insufficient_funds', 'invalid_signature',
   *  'expired_authorization', 'nonce_already_used'. */
  invalidReason?: string
  /** Resolved payer address (matches authorization.from). */
  payer?: string
}

// ── Facilitator API: /settle ──────────────────────────────────────

export interface X402SettleRequest {
  x402Version: number
  paymentPayload: X402PaymentPayload
  paymentRequirements: X402PaymentRequirements
}

export interface X402SettleResponse {
  success: boolean
  /** Set when success=false. */
  errorReason?: string
  /** Payer address. */
  payer: string
  /** On-chain transaction hash. May be empty when success=false. */
  transaction: string
  network: X402Network
}

/** Combined verify+settle outcome that the rail's submitPayment
 *  produces internally. Not on the wire; convenience for callers. */
export interface X402SubmitOutcome {
  verified: boolean
  /** Set when verified=false. */
  invalidReason?: string
  /** Set when verified=true. */
  settled?: boolean
  /** Set when verified=true && settled=true. */
  transaction?: string
  /** Set when verified=true && settled=false. */
  settleErrorReason?: string
  /** Resolved payer address from facilitator. */
  payer?: string
}
