// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0
const MOVED = "ProxyGateway class moved to @aeoess/gateway. " +
  "The SDK now ships only the gateway interface types (src/types/gateway.ts). " +
  "See MIGRATION.md#gateway"
export class ProxyGateway {
  constructor(..._args: unknown[]) { throw new Error(MOVED) }
}
