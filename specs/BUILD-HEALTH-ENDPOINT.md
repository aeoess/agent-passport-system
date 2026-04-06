# Build Spec: Agent Health Endpoint

## What
Add a health-check endpoint type to the gateway that returns an agent's governance posture. Enterprise monitoring tools (Datadog, Grafana) poll this to verify agents are operating within bounds.

## Where
- Types: `src/types/health.ts` (new)
- Implementation: private gateway (`~/aeoess-gateway`) — NOT public SDK
- SDK contribution: export the `AgentHealthStatus` type from the public SDK so consumers know the shape

## Type (public SDK)

```typescript
interface AgentHealthStatus {
  agentId: string
  timestamp: string
  passport: {
    valid: boolean
    expiresAt: string
    grade: number  // 0-3
  }
  delegation: {
    active: boolean
    scopeCount: number
    spendUtilization: number  // 0.0-1.0
    expiresAt: string | null
  }
  behavioral: {
    continuityScore: number  // from context_continuity
    lastActionTimestamp: string
    actionsInWindow: number  // last 24h
    driftDetected: boolean
  }
  recovery: {
    activeRecoveryPolicy: string | null
    recentRecoveryEvents: number  // last 1h
    currentStrategy: RecoveryStrategy | null
  }
  status: 'healthy' | 'degraded' | 'suspended' | 'expired'
}
```

## Gateway endpoint (private)

```
GET /api/v1/agents/:agentId/health
Authorization: Bearer <tenant-api-key>

Response: AgentHealthStatus (JWS-signed)
```

## Tests needed
- Healthy agent returns status 'healthy'
- Expired passport returns status 'expired'
- Agent with recent recovery events returns status 'degraded'
- Suspended agent returns status 'suspended'
- Response is JWS-signed and verifiable against gateway JWKS

## Why
Nate B Jones identifies scheduling/lifecycle/health-checking as a missing orchestration primitive. This is the health-checking piece. Enterprise buyers need to monitor agent fleet health via existing observability tools.
