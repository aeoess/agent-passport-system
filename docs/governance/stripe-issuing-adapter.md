# Stripe Issuing Adapter — Architecture

This document specifies how the public reference Stripe Issuing
adapter implements the `PaymentRail` contract for agent-scoped
purchases. The adapter ships in
[`src/v2/payment-rails/stripe-issuing/`](../../src/v2/payment-rails/stripe-issuing/)
and is exported from the SDK root. It is `sk_test_` only — the
constructor refuses `sk_live_` keys so the open-source surface
cannot be confused for a production credential layer.

## Why a Stripe Issuing rail at all

Most payment rails settle a transaction the agent already chose. A
card rail is different: the agent presents card credentials at a
merchant, the merchant calls its acquirer, and the acquirer asks
Stripe to authorize. APS gets to vote on that authorization in a
~2 second window via the
[`issuing_authorization.request`](https://docs.stripe.com/issuing/authorizations)
webhook. The adapter sits in that window. Either the spend matches
the delegation and Stripe is told to approve, or the gates fail and
Stripe is told to decline — and either way an APS receipt or denial
is emitted with a verifiable Ed25519 signature.

That gap — between "agent has a card" and "money has moved" — is
where the policy engine has to live for cards to be safe in agentic
contexts. The Nano rail enforces at invoice creation; the x402 rail
enforces at facilitator submission; this rail enforces at the
authorization webhook.

## End-to-end flow

```
   APS                      Gateway                     Stripe                  Merchant
    │                          │                          │                       │
    │  V2Delegation issued     │                          │                       │
    │─────────────────────────▶│                          │                       │
    │                          │  POST /v1/issuing/cards  │                       │
    │                          │  (mapped controls)       │                       │
    │                          │─────────────────────────▶│                       │
    │                          │  ic_... VirtualCard      │                       │
    │                          │◀─────────────────────────│                       │
    │                          │                          │                       │
    │                          │                          │  agent presents card ◀│
    │                          │                          │  acquirer sends auth │
    │                          │   issuing_authorization  │                       │
    │                          │   .request webhook       │                       │
    │                          │◀─────────────────────────│                       │
    │                          │                          │                       │
    │                          │  preAuthorize gates      │                       │
    │                          │  (wallet/scope/window/   │                       │
    │                          │   spend_limit)           │                       │
    │                          │                          │                       │
    │                          │  /approve OR /decline    │                       │
    │                          │─────────────────────────▶│                       │
    │  PaymentReceipt          │                          │                       │
    │  OR PaymentDenial        │                          │                       │
    │◀─────────────────────────│                          │                       │
```

## Components

### 1. Provisioning — `provisionAgentCard(delegation: V2Delegation)`

The adapter maps the APS delegation to a Stripe `SpendingControls`
object, then `POST /v1/issuing/cards` with `type=virtual`. The
default mapping (`defaultMapDelegationToSpendingControls`) is
deliberately conservative:

| APS field                                            | Stripe field                              |
| ---------------------------------------------------- | ----------------------------------------- |
| `scope.resource_limits.spend_limit_cents`            | `spending_limits[0].amount` (`all_time`)  |
| `scope.constraints.allowed_merchant_categories` CSV  | `spending_controls.allowed_categories[]`  |
| `scope.constraints.allowed_merchant_countries` CSV   | `allowed_merchant_countries[]`            |
| `policy_context.valid_until`                         | `metadata.aps_cancel_at_iso` (advisory)   |
| `id`                                                 | `metadata.aps_delegation_ref`             |

Three points worth noting:

1. **APS scope categories are not Stripe MCCs.** APS scopes like
   `commerce.purchase` are taxonomically orthogonal to Stripe's MCC
   categories (`computers_peripherals_software`, etc). The mapper
   does not invent an MCC translation; callers that need MCC
   restrictions declare them explicitly under
   `constraints.allowed_merchant_categories`. Gateway implementations
   with a richer mapping pass their own `spendingControlsMapper`.
2. **`cancel_at` is metadata, not a native Stripe field.** Stripe
   does not support scheduled card cancellation natively. The
   delegation's `valid_until` is recorded as `metadata.aps_cancel_at_iso`
   so a gateway-side scheduler (or revocation cascade) can act on it.
3. **The cardholder is shared.** `provisionAgentCard` requires a
   pre-existing `ich_...` cardholder id. The adapter does not do
   KYC/KYB onboarding; that lives in the gateway. Production
   typically runs one cardholder per principal, with one card per
   delegation issued under that cardholder.

### 2. Webhook handling — `handleAuthorizationWebhook(event)`

When Stripe POSTs an `issuing_authorization.request` event, the
gateway calls the adapter:

1. **Verify signature first.** Use `verifyWebhookSignature(rawBody,
   header)` against the configured `whsec_...` secret. The default
   tolerance is 300 seconds (Stripe's recommended replay window)
   with constant-time HMAC-SHA256 comparison. The adapter does NOT
   verify signatures inside `handleAuthorizationWebhook` — that is
   the caller's contract, so the parsed event can come from any
   trusted source (proxy, queue, replay tool).
2. **Resolve delegation.** Look up the `DelegationView` for
   `event.data.object.card.id`. The default lookup is the in-memory
   map populated by `provisionAgentCard`; gateways override
   `delegationLookup` with a DB-backed implementation.
3. **Run `preAuthorize`** (from the foundation `hooks.ts`) with the
   ordered checks: `wallet_revoked → no_commerce_scope →
   time_window_violation → spend_limit_exceeded`.
4. **Approve or decline at Stripe**, then emit the matching APS
   PaymentReceipt or PaymentDenial. The Stripe call and the APS
   emission are paired: a receipt is never emitted for an
   authorization that Stripe didn't approve, and a denial is
   always emitted when Stripe is declined (including for
   `rail_error` paths like a Stripe API failure on the approve call).

### 3. Revocation — `revokeWallet(cardId)`

`POST /v1/issuing/cards/:id` with `status=canceled`. Idempotent at
two layers: the in-memory `revokedCards` set short-circuits repeat
calls, and Stripe's "already canceled" 400 response is treated as
success. The card↔delegation map is intentionally retained after
revocation so subsequent webhooks for the canceled card resolve to
a `wallet_revoked` denial rather than a misleading `rail_error`.

### 4. The PaymentRail contract on a card rail

`createInvoice` and `checkStatus` throw with a guidance message
pointing callers to `provisionAgentCard` and `verifyTransaction`
respectively. There is no useful invoice abstraction for an issuing
rail — the authorization itself is the settlement event. The
remaining `PaymentRail` methods behave as expected:

- `verifyTransaction(authId, expectedAmount?)` fetches
  `/v1/issuing/authorizations/:id` and reports `verified=true` only
  when `approved && status === 'closed'` and the on-chain (well, on-
  Stripe) amount matches.
- `revokeWallet(cardId)` cancels the Stripe card.
- `isWalletRevoked(cardId)` reads the in-memory set.

## Failure modes and what they mean

| denial_reason            | Cause                                                                                                                                         |
| ------------------------ | --------------------------------------------------------------------------------------------------------------------------------------------- |
| `wallet_revoked`         | The card has been canceled. APS denies before Stripe is consulted on /decline.                                                                |
| `no_commerce_scope`      | The delegation's `scope.action_categories` does not include the rail's `requiredScope` (default `commerce.purchase`).                         |
| `time_window_violation`  | The webhook arrived outside `[policy_context.valid_from, policy_context.valid_until]`.                                                        |
| `spend_limit_exceeded`   | The pending authorization amount exceeds `spend_limit_cents`. Currency mismatch (delegation in `EUR`, auth in `USD`) maps here too.           |
| `rail_error`             | The card had no registered delegation, OR the Stripe approve call failed and the rail fell back to the deny path. Reason detail explains.    |

Every denial is a signed `PaymentDenial` with one of these closed-
taxonomy reasons. Auditors verifying offline check the signature with
`verifyPaymentDenial(denial)`.

## Security boundary

What this adapter does NOT do, by design:

- **No webhook routing.** Callers hand the parsed event to
  `handleAuthorizationWebhook`. Verifying the signature, deduping,
  and queueing for retry are the gateway's job.
- **No cardholder onboarding.** The cardholder id must exist before
  `provisionAgentCard` is called.
- **No persistent card↔delegation store.** The in-memory map is for
  test convenience and single-process gateways. Production replaces
  it with a DB-backed `delegationLookup`.
- **No live keys.** Constructor refuses `sk_live_`. The reference
  adapter is a pedagogical artifact and a test fixture; the
  production gateway runs its own hardened version.

## Test coverage

- [`tests/v2/payment-rails/stripe-issuing.test.ts`](../../tests/v2/payment-rails/stripe-issuing.test.ts)
  — 31 mocked tests covering the constructor gate, mapping function,
  approve/decline paths, signature verification, revocation
  idempotency, and fixture exercises. No live Stripe contact.
- [`tests/v2/payment-rails/stripe-issuing-live.test.ts`](../../tests/v2/payment-rails/stripe-issuing-live.test.ts)
  — gated smoke test. Skips when `STRIPE_API_KEY` is unset; aborts
  on `sk_live_`; provisions a real test cardholder + card and
  exercises both webhook paths against `api.stripe.com` when
  `sk_test_` is present. Cleans up cardholder + card on exit.

## Fixtures

All fixtures are deterministic and regenerated by
[`src/v2/payment-rails/stripe-issuing/fixtures/_generate.ts`](../../src/v2/payment-rails/stripe-issuing/fixtures/_generate.ts):

- `spending-controls-derived.fixture.json` — sample
  `V2Delegation` and the `SpendingControls` it produces.
- `authorization-approve.fixture.json` — synthetic
  `issuing_authorization.request` payload that passes APS gates.
- `authorization-decline-overbudget.fixture.json` — synthetic
  payload that fails `spend_limit_exceeded`.

The test suite reads these fixtures and exercises the rail to prove
the on-disk shape stays in sync with the live mapper output.
