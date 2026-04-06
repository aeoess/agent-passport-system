# BUILD-A2A-ADAPTER — Passport ↔ A2A Agent Card bridge

## Context

A2A (Agent-to-Agent) protocol uses Agent Cards for discovery. APS uses passports
for identity. This adapter converts between them for seamless interop.

## Deliverables

### 1. `src/adapters/a2a.ts` (~140 lines)

```typescript
interface A2AAgentCard {
  name: string
  description?: string
  url?: string
  provider?: { organization: string; url?: string }
  version?: string
  capabilities?: {
    streaming?: boolean
    pushNotifications?: boolean
    stateTransitionHistory?: boolean
  }
  skills?: Array<{
    id: string
    name: string
    description?: string
    inputModes?: string[]
    outputModes?: string[]
  }>
  securitySchemes?: Record<string, unknown>
  security?: unknown[]
  defaultInputModes?: string[]
  defaultOutputModes?: string[]
}

// Convert APS passport to A2A Agent Card
export function passportToAgentCard(
  passport: SignedPassport,
  opts?: {
    delegation?: Delegation
    url?: string
    skills?: A2AAgentCard['skills']
    capabilities?: A2AAgentCard['capabilities']
  }
): A2AAgentCard

// Convert A2A Agent Card to APS passport metadata
export function agentCardToPassportMeta(
  card: A2AAgentCard
): { agentId: string; metadata: Record<string, unknown> }

// Verify an A2A agent has valid APS identity
export function verifyA2AAgent(
  card: A2AAgentCard,
  passport: SignedPassport
): { valid: boolean; errors: string[] }

// Extract delegation scope from A2A skills
export function a2aSkillsToScope(
  skills: A2AAgentCard['skills']
): string[]

// Embed APS trust signal in Agent Card extensions
export function embedTrustSignal(
  card: A2AAgentCard,
  passport: SignedPassport,
  trustEndpoint?: string
): A2AAgentCard & { extensions?: { aps_trust?: unknown } }
```

Key logic:
- `passportToAgentCard`: agentId → name, publicKey → securitySchemes, 
  delegation scope → skills mapping
- `agentCardToPassportMeta`: name → agentId, skills → scope hints
- `verifyA2AAgent`: checks card.name matches passport.agentId pattern
- `a2aSkillsToScope`: skill.id → `a2a:{skillId}` scope strings
- `embedTrustSignal`: adds aps_trust extension with governance attestation URL

### 2. Export from `src/index.ts`

### 3. Tests: `tests/a2a-adapter.test.ts` (~16 tests)

- passport → agent card conversion
- agent card → passport metadata
- round-trip: passport → card → metadata preserves identity
- delegation scope → skills mapping
- skills → scope extraction
- verify matching passport + card
- verify mismatched passport + card
- embed trust signal with endpoint
- embed trust signal without endpoint
- card with no skills → empty scope
- card with capabilities preserved
- provider info from passport metadata
- security schemes from public key
- empty card handling
- special characters in agent name
- multiple skills scope aggregation

## Build Rules
- No A2A SDK dependency (interface types only)
- `npm run build && npm test` must pass
- Report test count delta
