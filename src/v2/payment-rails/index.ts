// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// ══════════════════════════════════════════════════════════════════
// Payment Rails — public surface
// ══════════════════════════════════════════════════════════════════
// Generalized PaymentRail interface + composable governance hooks
// (preAuthorize, emitReceipt, emitDenial) + signed PaymentReceipt
// and PaymentDenial primitives + Nano reference adapter.
//
// SDK scope: interface, hooks, canonicalization, signature
// verification, reference adapter. Out of scope: custodial wallet,
// credential storage, tx routing, processor accounts. Those live in
// the private gateway.
// ══════════════════════════════════════════════════════════════════

export type {
  CreateInvoiceOpts,
  DelegationView,
  DenialReason,
  EmitDenialInput,
  EmitReceiptInput,
  GovernanceHooks,
  InvoiceStatus,
  PaymentDenial,
  PaymentInvoice,
  PaymentRail,
  PaymentReceipt,
  PreAuthorizeInput,
  PreAuthorizeResult,
  SendPaymentOpts,
  VerifyTransactionResult,
} from './types.js'

export {
  canonicalizeDenialForId,
  canonicalizeDenialForSig,
  canonicalizeInvoice,
  canonicalizeReceiptForId,
  canonicalizeReceiptForSig,
  invoiceDigest,
  sha256Hex as paymentRailsSha256Hex,
} from './canonicalize.js'

export {
  createDefaultGovernanceHooks,
  emitDenial,
  emitReceipt,
  preAuthorize,
  verifyPaymentDenial,
  verifyPaymentReceipt,
} from './hooks.js'
export type {
  DenialVerifyReason,
  DenialVerifyResult,
  ReceiptVerifyReason,
  ReceiptVerifyResult,
} from './hooks.js'

export {
  createNanoRail,
  NanoPaymentRail,
  rawToXno,
  xnoToRaw,
} from './nano.js'
export type {
  FetchBlockInfo,
  FetchHistory,
  NanoBlockInfo,
  NanoHistoryEntry,
  NanoRailConfig,
} from './nano.js'

// ── x402 reference adapter (Base + USDC, Coinbase facilitator) ───
// Implements PaymentRail over the x402 v1 protocol (coinbase/x402).
// Settles USDC on Base (eip155:8453) via the EIP-3009 'exact' scheme
// against a caller-supplied facilitator. The Coinbase CDP public
// facilitator URL is exported as X402_DEFAULT_FACILITATOR_URL.

export {
  createX402Rail,
  DEFAULT_FACILITATOR_URL as X402_DEFAULT_FACILITATOR_URL,
  USDC_BASE_MAINNET,
  USDC_BASE_SEPOLIA,
  X402PaymentRail,
} from './x402/index.js'
export type {
  FacilitatorSettle as X402FacilitatorSettle,
  FacilitatorVerify as X402FacilitatorVerify,
  X402RailConfig,
} from './x402/index.js'

export { X402_VERSION } from './x402/types.js'
export type {
  EIP3009Authorization,
  X402ExactSchemePayload,
  X402Network,
  X402PaymentPayload,
  X402PaymentRequirements,
  X402PaymentRequirementsResponse,
  X402Scheme,
  X402SettleRequest,
  X402SettleResponse,
  X402SubmitOutcome,
  X402VerifyRequest,
  X402VerifyResponse,
} from './x402/types.js'

// ── Stripe Issuing reference adapter (agent-scoped virtual cards) ──
// Implements PaymentRail by minting one-time virtual cards via the
// Stripe Issuing API and intercepting issuing_authorization.request
// webhooks to enforce APS delegation gates BEFORE Stripe approves.
// Reference adapter is sk_test_ only; refuses sk_live_ in constructor.

export {
  createStripeIssuingRail,
  defaultMapDelegationToSpendingControls,
  StripeIssuingRail,
  verifyStripeSignature,
} from './stripe-issuing/index.js'
export type {
  Authorization as StripeAuthorization,
  AuthorizationDecision as StripeAuthorizationDecision,
  AuthorizationEvent as StripeAuthorizationEvent,
  CardholderRef as StripeCardholderRef,
  DelegationLookup as StripeDelegationLookup,
  FetchLike as StripeFetchLike,
  MerchantData as StripeMerchantData,
  SpendingControls as StripeSpendingControls,
  SpendingControlsMapper as StripeSpendingControlsMapper,
  SpendingLimit as StripeSpendingLimit,
  SpendingLimitInterval as StripeSpendingLimitInterval,
  StripeIssuingConfig,
  VirtualCard as StripeVirtualCard,
} from './stripe-issuing/index.js'
