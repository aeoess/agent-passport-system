// Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// ══════════════════════════════════════════════════════════════════
// Trust Root Policy (W2-B1): public surface
// ══════════════════════════════════════════════════════════════════
// A signed, versioned trust-root-policy artifact (trusted issuers,
// pinned keys, resolver rules, rotation tolerance, stale + offline
// behavior, anti-rollback version), a verifier that turns a receipt's
// mechanical signer facts into a relying-party verdict, and the did:web
// .well-known/aps-agents.json discovery convention + generator.
//
// It EXTENDS, never duplicates:
//   - v2/mutual-auth TrustAnchor/verifyBundle/checkAnchor (root-signed
//     bundle + anchor binding model),
//   - v2/key-resolution (M3) KeyResolver for live key confirmation,
//   - canonicalizeJCS + crypto/keys for sign-over-canonical,
//   - ScopeOfClaim for honest scope on the receipt-carried reference.
//
// PROOF BOX
// ─────────
// PROVES:    A trust-policy verdict shows that a receipt's signer was
//            evaluated against a SPECIFIC, SIGNED policy version with the
//            keys that version pins. The verdict names the policy_id and
//            policy_version it was computed against and which pinned key
//            (if any) matched. The anti-rollback gate shows the policy
//            version was at or above the verifier's known minimum.
//
// DOES NOT PROVE:
//            - that the policy author chose trustworthy issuers (the
//              policy expresses a relying party's CHOICE, not a fact
//              about the issuers);
//            - that a pinned key is uncompromised or under sole control
//              of the named issuer;
//            - that the live endpoint asserts the same key at any later
//              time (resolution is point-in-time; keys rotate).
//            A 'degraded'/'unknown' verdict under fail-open carries NO
//            acceptance. The default posture is fail-closed.
//
// This is the ARTIFACT + the VERIFIER + the CONVENTION + a GENERATOR. It
// is NOT a hosted resolution service: no registry, no endpoint, no
// cross-tenant aggregation, no policy-template library, no dashboard.
//
// The verdict is a verifier-derived OUTPUT. It is never written onto a
// receipt and never read back from one. The only receipt-carried slot is
// trust_policy_ref: an OPTIONAL, additive string pointer to WHICH policy
// a producer evaluated against. It is not an assurance and not read as
// acceptance; a verifier re-derives the verdict itself.
// ══════════════════════════════════════════════════════════════════

export {
  TRUST_ROOT_POLICY_SPEC_VERSION,
} from './types.js'

export type {
  PinnedKey,
  TrustedIssuer,
  ResolverRule,
  RotationRule,
  StaleBehavior,
  OfflineBehavior,
  TrustRootPolicyBody,
  TrustRootPolicy,
  PolicyVerifyReason,
  PolicyVerifyOutcome,
  TrustPolicyVerdictReason,
  TrustPolicyStatus,
  TrustPolicyVerdict,
} from './types.js'

export {
  buildTrustRootPolicy,
  signTrustRootPolicy,
  verifyTrustRootPolicy,
} from './policy.js'

export type {
  BuildTrustRootPolicyInput,
  VerifyTrustRootPolicyOptions,
} from './policy.js'

export { evaluateReceiptAgainstPolicy } from './verdict.js'

export type { ReceiptSignerFacts, EvaluateOptions } from './verdict.js'

export {
  WELL_KNOWN_APS_AGENTS_PATH,
  APS_AGENTS_DOC_SPEC_VERSION,
  generateApsAgentsDoc,
  apsAgentsUrl,
} from './well-known.js'

export type {
  ApsAgentEntry,
  ApsAgentsDoc,
  GenerateApsAgentsInput,
} from './well-known.js'
