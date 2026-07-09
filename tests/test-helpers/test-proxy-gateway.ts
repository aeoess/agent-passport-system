// Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// ══════════════════════════════════════════════════════════════════
// Test-Only ProxyGateway Shim
// ══════════════════════════════════════════════════════════════════
// THIS IS NOT THE PRODUCT GATEWAY. It is a minimal public fixture
// for `tests/benchmark-gateway.ts` so the benchmark methodology is
// reproducible from the public SDK.
//
// The real ProxyGateway runtime lives at @aeoess/gateway and is
// closed-source product. It implements the full enforcement stack
// (cascade revocation, escalation, charter governance, settlement,
// drift detection, decision equivalence, etc.) — none of which is
// in this shim.
//
// What this shim does (enough for benchmarking):
//   - Signature verification on the request payload
//   - Scope authorization against registered delegation
//   - Spend-limit check
//   - Optional: small constant-work mocks for reputation, HLC,
//     fidelity, and data-enforcement so each config flag adds
//     measurable work to the benchmark
//
// Run the benchmark with: `npx tsx tests/benchmark-gateway.ts`
// ══════════════════════════════════════════════════════════════════

import { createHash } from 'node:crypto'
import { canonicalize } from '../../src/core/canonical.js'
import { verify } from '../../src/crypto/keys.js'
import { scopeAuthorizes } from '../../src/core/delegation.js'
import type {
  SignedPassport,
  Delegation,
  FloorAttestation,
  ValuesFloor,
} from '../../src/types/passport.js'

// Minimal config interface — matches what the benchmark passes.
export interface TestGatewayConfig {
  gatewayId: string
  gatewayPublicKey: string
  gatewayPrivateKey: string
  floor: ValuesFloor
  enableReputationGating?: boolean
  enableFidelityGating?: boolean
  enableHybridTimestamps?: boolean
  enableDataEnforcement?: boolean
}

interface ToolCallRequest {
  requestId: string
  agentId: string
  agentPublicKey: string
  tool: string
  params: Record<string, unknown>
  scopeRequired: string
  signature: string
  spend?: { amount: number; currency: string }
}

interface RegisteredAgent {
  passport: SignedPassport
  attestation: FloorAttestation
  delegations: Delegation[]
}

// Module-level monotonic counter for HLC mock
let hlcCounter = 0

export interface TestProxyGateway {
  registerAgent(
    passport: SignedPassport,
    attestation: FloorAttestation,
    delegations: Delegation[],
  ): void
  processToolCall(req: ToolCallRequest): Promise<{
    decision: 'allow' | 'deny'
    reason?: string
    receipt?: { gatewayId: string; ts: number }
  }>
}

export function createProxyGateway(
  config: TestGatewayConfig,
  executor: (req: ToolCallRequest) => Promise<unknown>,
): TestProxyGateway {
  const agents = new Map<string, RegisteredAgent>()

  return {
    registerAgent(passport, attestation, delegations) {
      agents.set(passport.passport.agentId, { passport, attestation, delegations })
    },

    async processToolCall(req) {
      // 1. Signature verification (always)
      const payload = canonicalize({
        requestId: req.requestId,
        agentId: req.agentId,
        tool: req.tool,
        params: req.params,
        scopeRequired: req.scopeRequired,
      })
      if (!verify(payload, req.signature, req.agentPublicKey)) {
        return { decision: 'deny', reason: 'signature_invalid' }
      }

      // 2. Agent lookup (always)
      const reg = agents.get(req.agentId)
      if (!reg) return { decision: 'deny', reason: 'agent_not_registered' }

      // 3. Scope authorization (always)
      const del = reg.delegations[0]
      if (!del) return { decision: 'deny', reason: 'no_delegation' }
      if (!scopeAuthorizes(del.scope, req.scopeRequired)) {
        return { decision: 'deny', reason: 'scope_exceeded' }
      }

      // 4. Spend check (always, when present)
      if (req.spend && req.spend.amount > del.spendLimit) {
        return { decision: 'deny', reason: 'spend_exceeded' }
      }

      // 5. Optional gates — each adds bounded constant work
      if (config.enableReputationGating) {
        const h = createHash('sha256').update(req.agentId).digest()
        if (h[0] === 255) return { decision: 'deny', reason: 'reputation_below_threshold' }
      }

      let ts = 0
      if (config.enableHybridTimestamps) {
        ts = Date.now() * 1000 + (++hlcCounter % 1000)
      }

      if (config.enableFidelityGating) {
        createHash('sha256').update(payload).digest('hex')
      }

      if (config.enableDataEnforcement) {
        createHash('sha256').update(req.tool + JSON.stringify(req.params)).digest('hex')
      }

      // 6. Execute (the benchmark passes a no-op)
      await executor(req)

      return {
        decision: 'allow',
        receipt: { gatewayId: config.gatewayId, ts },
      }
    },
  }
}
