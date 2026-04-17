// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
const MOVED = "ProxyGateway class moved to @aeoess/gateway. " +
  "The SDK now ships only the gateway interface types (src/types/gateway.ts). " +
  "See MIGRATION.md#gateway"
export class ProxyGateway {
  constructor(..._args: unknown[]) { throw new Error(MOVED) }
}
