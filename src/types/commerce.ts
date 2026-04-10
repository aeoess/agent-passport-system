// ══════════════════════════════════════════════════════════════════
// Layer 7 — Agentic Commerce: Type Definitions
// ══════════════════════════════════════════════════════════════════
// Integration with the Agentic Commerce Protocol (ACP) by OpenAI + Stripe.
// Every commerce action is passport-verified, delegation-scoped,
// spend-limited, and produces signed ActionReceipts.
// ══════════════════════════════════════════════════════════════════

// ── ACP Checkout Session (mirrors the spec) ──

export interface ACPCheckoutSession {
  id: string
  status: 'open' | 'completed' | 'cancelled' | 'expired'
  items: ACPLineItem[]
  totals: ACPTotals
  fulfillment?: ACPFulfillment
  fulfillmentOptions?: ACPFulfillmentOption[]
  paymentMethods?: ACPPaymentMethod[]
  customer?: ACPCustomer
  metadata?: Record<string, unknown>
  createdAt: string
  updatedAt: string
}

export interface ACPLineItem {
  id: string
  skuId: string
  name: string
  description?: string
  quantity: number
  unitPrice: ACPMoney
  totalPrice: ACPMoney
  imageUrl?: string
  productUrl?: string
}

export interface ACPMoney {
  amount: number       // in smallest currency unit (cents)
  currency: string     // ISO 4217 (e.g. 'usd')
}

export interface ACPTotals {
  subtotal: ACPMoney
  tax?: ACPMoney
  shipping?: ACPMoney
  discount?: ACPMoney
  total: ACPMoney
}

export interface ACPFulfillment {
  type: 'shipping' | 'pickup' | 'digital'
  address?: ACPAddress
  optionId?: string
}

export interface ACPFulfillmentOption {
  id: string
  name: string
  description?: string
  price: ACPMoney
  estimatedDelivery?: string
}

export interface ACPPaymentMethod {
  type: 'shared_payment_token' | 'card' | 'link' | string
  id?: string
}

export interface ACPCustomer {
  name?: string
  email?: string
  phone?: string
}

export interface ACPAddress {
  name?: string
  lineOne: string
  lineTwo?: string
  city: string
  state?: string
  country: string
  postalCode: string
}

// ── ACP Order Events (webhook payloads) ──

export interface ACPOrderEvent {
  eventId: string
  type: 'order.created' | 'order.updated' | 'order.shipped' | 'order.delivered' | 'order.cancelled'
  checkoutSessionId: string
  orderId: string
  timestamp: string
  data: Record<string, unknown>
}

// ── Passport-Enforced Commerce Types ──

export interface CommerceConfig {
  merchantBaseUrl: string
  merchantName: string
  bearerToken?: string
  webhookUrl?: string
  webhookSecret?: string
  defaultCurrency?: string
}

export interface CommerceDelegation {
  agentId: string
  delegationId: string
  scope: string[]            // must include 'commerce:checkout'
  spendLimit: number         // max spend in smallest currency unit
  spentAmount: number        // running total
  currency: string
  approvedMerchants?: string[]  // optional allowlist
  requireHumanApproval?: boolean
  humanApprovalThreshold?: number  // amount above which human must confirm
}

export interface CommercePreflightResult {
  permitted: boolean
  checks: CommercePreflightCheck[]
  delegation?: CommerceDelegation
  warnings: string[]
  blockedReason?: string
  existingReceiptId?: string
}

export interface CommercePreflightCheck {
  check: string
  passed: boolean
  detail: string
}

export interface CommerceActionReceipt {
  receiptId: string
  version: string
  timestamp: string
  agentId: string
  delegationId: string
  action: {
    type: 'commerce:create_checkout' | 'commerce:update_checkout' | 'commerce:complete_checkout' | 'commerce:cancel_checkout'
    target: string           // merchant URL
    method: string           // HTTP method
    scopeUsed: string        // 'commerce:checkout'
    spend: {
      amount: number
      currency: string
    }
  }
  checkout: {
    sessionId: string
    merchantName: string
    items: { skuId: string; name: string; quantity: number; unitPrice: number }[]
    totalAmount: number
    totalCurrency: string
    status: string
  }
  delegationChain: string[]
  beneficiary: string        // human principal traced via delegation chain
  valuesFloorVersion?: string
  idempotencyKey?: string    // content-addressed dedup key (excludes timestamp)
  signature: string
}

export interface IdempotencyCheck {
  idempotencyKey: string
  windowSeconds: number
  action: 'reject' | 'return_existing'
}

export interface IdempotencyStore {
  check(key: string, windowSeconds: number): Promise<{ duplicate: boolean; existingReceiptId?: string }>
  record(key: string, receiptId: string): Promise<void>
}

export interface HumanApprovalRequest {
  requestId: string
  agentId: string
  merchantName: string
  items: ACPLineItem[]
  totalAmount: ACPMoney
  delegationId: string
  reason: string             // why approval is needed
  createdAt: string
  expiresAt: string
  status: 'pending' | 'approved' | 'denied'
}
