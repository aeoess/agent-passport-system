// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
/**
 * DEPRECATED — the hosted gateway receipt reporter has moved.
 *
 * `reportReceipt` / `reportEvaluation` were product-integration glue, not
 * protocol primitives, and now live at @aeoess/gateway
 * (src/sdk-migrated/gateway-reporter.ts). Adapter callers that want
 * gateway telemetry should supply their own reporter via the adapter's
 * `onReceipt` callback.
 *
 * See MIGRATION.md.
 */

const MOVED = 'reportReceipt/reportEvaluation have moved to @aeoess/gateway. See MIGRATION.md'

export async function reportReceipt(): Promise<never> {
  throw new Error(MOVED)
}

export async function reportEvaluation(): Promise<never> {
  throw new Error(MOVED)
}

export type GatewayReporterConfig = never
