// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
/**
 * Gateway Receipt Reporter — sends adapter receipts to the hosted gateway.
 * Optional: only active when gatewayUrl + apiKey are provided in adapter config.
 * All calls are fire-and-forget. Never blocks or throws.
 */

import type { ActionReceipt } from '../types/passport.js'

export interface GatewayReporterConfig {
  gatewayUrl: string
  apiKey: string
}

export async function reportReceipt(
  receipt: ActionReceipt,
  config: GatewayReporterConfig,
): Promise<{ ok: boolean; error?: string }> {
  try {
    const res = await fetch(`${config.gatewayUrl}/api/v1/receipt`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${config.apiKey}`,
      },
      body: JSON.stringify({
        agent_id: receipt.agentId,
        action_type: receipt.action?.type || 'unknown',
        verdict: receipt.result?.status === 'success' ? 'permit' : 'deny',
        execution_result: receipt.result?.summary || '',
        signature: receipt.signature,
        payload: receipt,
      }),
    })
    if (!res.ok) {
      const err = await res.text().catch(() => 'unknown')
      return { ok: false, error: err }
    }
    return { ok: true }
  } catch (e) {
    return { ok: false, error: (e as Error).message }
  }
}

export async function reportEvaluation(
  agentId: string,
  actionType: string,
  scopeRequired: string,
  _verdict: 'permit' | 'deny',
  _reason: string,
  config: GatewayReporterConfig,
): Promise<{ ok: boolean; error?: string }> {
  try {
    const res = await fetch(`${config.gatewayUrl}/api/v1/evaluate`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${config.apiKey}`,
      },
      body: JSON.stringify({ agent_id: agentId, action_type: actionType, scope_required: scopeRequired }),
    })
    return { ok: res.ok }
  } catch (e) {
    return { ok: false, error: (e as Error).message }
  }
}
