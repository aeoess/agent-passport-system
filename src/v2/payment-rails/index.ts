// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0
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

// ── Foundation: canonical V2Delegation scope resolution ──────────
// Single source of truth for spend-cap field-name resolution across
// every binding adapter. Direct per-rail field reads are forbidden.
export { resolveSpendLimitCents } from './scope-resolution.js'

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
  verifyPaymentDenialWithDID,
  verifyPaymentReceipt,
  verifyPaymentReceiptWithDID,
} from './hooks.js'
export type {
  DenialVerifyReason,
  DenialVerifyResult,
  ReceiptVerifyReason,
  ReceiptVerifyResult,
  ResolveDidDocument,
  VerifyReceiptOptions,
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

// ── AP2 v0.2 interop adapter (Google Agent Payments Protocol) ────
// Pinned to AP2 v0.2 (April 2026). Maps APS V2Delegation to AP2
// mandate dicts (CheckoutMandate / OpenCheckoutMandate / PaymentMandate
// / OpenPaymentMandate) and back.

export {
  AP2_VERSION,
  ap2MandateToApsDelegation,
  apsToAp2CartMandate,
  apsToAp2IntentMandate,
  apsToAp2OpenPaymentMandate,
  apsToAp2PaymentMandate,
  signAp2Mandate,
  verifyAp2Mandate,
  verifyAp2MandateWithDID,
} from './ap2/index.js'

export type {
  AP2AllowedMerchantsConstraint,
  AP2AllowedPayeesConstraint,
  AP2AllowedPaymentInstrumentsConstraint,
  AP2Amount,
  AP2AmountRangeConstraint,
  AP2BudgetConstraint,
  AP2CheckoutConstraint,
  AP2CheckoutMandate,
  AP2Cnf,
  AP2Item,
  AP2LineItemRequirement,
  AP2LineItemsConstraint,
  AP2Mandate,
  AP2Merchant,
  AP2OpenCheckoutMandate,
  AP2OpenPaymentMandate,
  AP2PaymentConstraint,
  AP2PaymentInstrument,
  AP2PaymentMandate,
  AP2PaymentReferenceConstraint,
  AP2Pisp,
  AP2VctCheckout,
  AP2VctOpenCheckout,
  AP2VctOpenPayment,
  AP2VctPayment,
  Ap2VerifyReason,
  Ap2VerifyResult,
  Ap2ToApsOptions,
  ApsToAp2CartOptions,
  ApsToAp2IntentOptions,
  ApsToAp2OpenPaymentOptions,
  ApsToAp2PaymentOptions,
  CartDetails,
  CartMandate,
  IntentMandate,
  SignedAP2Mandate,
  VerifyAp2MandateOptions,
} from './ap2/index.js'

// ── Conformance harness ───────────────────────────────────────────
// Standard scenarios any third-party PaymentRail adapter can run to
// claim conformance to the APS governance contract. See
// docs/governance/payment-rail-conformance.md for the full guide.

export {
  HARNESS_FIXED_NOW,
  HARNESS_ISSUER_PRIV,
  runConformance,
  STANDARD_SCENARIOS,
} from './conformance/index.js'

export type {
  ConformanceContext,
  ConformanceReport,
  ConformanceScenario,
  RunConformanceOpts,
  ScenarioOutcome,
  ScenarioReport,
} from './conformance/index.js'

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

// Phase 4.1 boundary split: the orchestration class `StripeIssuingRail`
// and `createStripeIssuingRail` factory have moved to the private gateway
// repo. The SDK ships only protocol primitives — mapper, V2Delegation
// projection, signature verifier, form encoder, and the rail constants.
// Gateway consumes them via the `agent-passport-system` npm package.
export {
  defaultMapDelegationToSpendingControls,
  delegationToView as stripeIssuingDelegationToView,
  encodeForm as stripeIssuingEncodeForm,
  verifyStripeSignature,
  DEFAULT_API_BASE as STRIPE_ISSUING_DEFAULT_API_BASE,
  DEFAULT_REQUIRED_SCOPE as STRIPE_ISSUING_DEFAULT_REQUIRED_SCOPE,
  DEFAULT_TOLERANCE_SEC as STRIPE_ISSUING_DEFAULT_TOLERANCE_SEC,
  RAIL_NAME as STRIPE_ISSUING_RAIL_NAME,
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

// ── ACP reference adapter (Agentic Commerce Protocol — OpenAI + Stripe) ──
// Implements APS governance over ACP v2025-09-29 checkout-session
// operations (POST /checkout_sessions, update, complete, cancel,
// retrieve). Crosswalks V2Delegation to permitted operations and
// maps APS denial reasons to ACP error type/code envelopes so the
// merchant sees a well-formed ACP error instead of a transport
// failure. Reference adapter does not transport — gateway product.

export {
  ACP_API_VERSION,
  acpSessionToDelegationHints,
  apsToAcpError,
  checkAcpSessionUnderBudget,
  delegationToAcpAllowed,
  mapAcpDenialToFoundation,
  preAuthorizeAcpCheckout,
  signAcpDenial,
  signAcpReceipt,
  verifyAcpDenial,
  verifyAcpDenialWithDID,
  verifyAcpReceipt,
  verifyAcpReceiptWithDID,
} from './acp/index.js'
export type {
  AcpAllowedFromDelegation,
  AcpPreAuthorizeOptions,
  AcpPreAuthorizeResult,
  SignAcpDenialInput,
  SignAcpReceiptInput,
  VerifyAcpReceiptOptions,
} from './acp/index.js'
export type {
  AcpBuyer,
  AcpCheckoutSession,
  AcpCheckoutSessionStatus,
  AcpCompleteCheckoutSessionRequest,
  AcpCreateCheckoutSessionRequest,
  AcpDenial,
  AcpDenialReason,
  AcpErrorCode,
  AcpErrorResponse,
  AcpErrorType,
  AcpFulfillmentAddress,
  AcpFulfillmentOption,
  AcpHookConfig,
  AcpItem,
  AcpLineItem,
  AcpMessage,
  AcpMessageContentType,
  AcpMessageType,
  AcpOp,
  AcpPaymentData,
  AcpPaymentMethod,
  AcpPaymentProvider,
  AcpPaymentProviderName,
  AcpReceipt,
  AcpTotal,
  AcpTotalType,
  AcpUpdateCheckoutSessionRequest,
  AcpVerifyReason,
  AcpVerifyResult,
} from './acp/types.js'

// ── MPP reference adapter (Stripe + Tempo + Visa Machine Payments Protocol) ──
// Implements APS governance over MPP draft-httpauth-payment-00 — an
// HTTP authentication scheme for machine payments where servers
// emit a 402 with WWW-Authenticate: Payment and clients retry with
// Authorization: Payment carrying proof. Method-agnostic: tempo
// stablecoins, Visa MPP card spec, Bitcoin Lightning all sit in a
// discriminated union. Crosswalks V2Delegation to permitted methods
// and maps APS denial reasons to HTTP 402/403/410/503 envelopes.

export {
  apsToMppHttpError,
  delegationToMppAllowed,
  mapMppDenialToFoundation,
  MPP_VERSION,
  preAuthorizeMppPayment,
  signMppDenial,
  signMppReceipt,
  verifyMppDenial,
  verifyMppDenialWithDID,
  verifyMppReceipt,
  verifyMppReceiptWithDID,
} from './mpp/index.js'
export type {
  MppAllowedFromDelegation,
  MppPreAuthorizeResult,
  PreAuthorizeMppOptions,
  SignMppDenialInput,
  SignMppReceiptInput,
  VerifyMppOptions,
} from './mpp/index.js'
export type {
  MppApsReceipt,
  MppAuthorization,
  MppDenial,
  MppDenialReason,
  MppMethod,
  MppMethodCard,
  MppMethodLightning,
  MppMethodTempo,
  MppMethodType,
  MppPaymentChallenge,
  MppPaymentReceipt,
  MppVerifyReason,
  MppVerifyResult,
} from './mpp/types.js'

// ── Cycles reference adapter (reserve/commit/release budget authority) ──
// Implements APS governance over Cycles (runcycles.io) — a four-event
// lifecycle (decide / reserve / commit / release) plus error envelope
// for pre-execution budget and action-authority decisions. Emits
// rail.budget_reservation.{permit,release,denial}.v1 receipts that
// bind to CyclesEvidence envelopes by URL + content-hash, with the
// closed-taxonomy denial mapping per runcycles/cycles-protocol#93.

export {
  CYCLES_PROTOCOL_VERSION,
  CYCLES_EVIDENCE_SCHEMA_VERSION,
  RAIL_BUDGET_RESERVATION_PERMIT_CLAIM_TYPE,
  RAIL_BUDGET_RESERVATION_RELEASE_CLAIM_TYPE,
  RAIL_BUDGET_RESERVATION_DENIAL_CLAIM_TYPE,
  mapCyclesDenialToFoundation,
  signCyclesPermitReceipt,
  signCyclesReleaseReceipt,
  signCyclesDenial,
  verifyCyclesPermitReceipt,
  verifyCyclesPermitReceiptWithDID,
  verifyCyclesReleaseReceipt,
  verifyCyclesReleaseReceiptWithDID,
  verifyCyclesDenial,
  verifyCyclesDenialWithDID,
  verifyCyclesPermitReceiptWithEvidence,
  verifyCyclesReleaseReceiptWithEvidence,
  verifyCyclesDenialWithEvidence,
  resolveEvidenceRef,
  recomputeEvidenceContentHash,
  toEvidenceDescriptorInput,
} from './cycles/index.js'
export type {
  CyclesArtifactType,
  CyclesDecision,
  CyclesDenial,
  CyclesDenialDetail,
  CyclesDenialSource,
  CyclesEvidenceRef,
  CyclesEvidenceView,
  CyclesPermitReceipt,
  CyclesReleaseReceipt,
  CyclesResolveDidDocument,
  CyclesVerifyReason,
  CyclesVerifyResult,
  SignCyclesDenialInput,
  SignCyclesPermitReceiptInput,
  SignCyclesReleaseReceiptInput,
  VerifyCyclesOptions,
} from './cycles/types.js'
export type { CyclesVerifyWithEvidenceResult } from './cycles/index.js'
export type {
  EvidenceResolver,
  EvidenceFetchResult,
  EvidenceResolutionResult,
  EvidenceResolutionStatus,
  EvidenceFailurePolicy,
  ResolveEvidenceConfig,
  FetchedCyclesEvidenceEnvelope,
  EvidenceDescriptorInput,
  EvidenceObservationBasis,
} from './cycles/index.js'
