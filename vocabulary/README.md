# Agent Governance Vocabulary

A canonical naming layer for agent governance primitives, inspired by [IANA JWT Claims](https://www.iana.org/assignments/jwt/jwt.xhtml) and [W3C DID Registries](https://www.w3.org/TR/did-spec-registries/).

## What this is

Six+ agent governance implementations use different names for the same concepts. This vocabulary provides:

- **`vocabulary.yaml`** — Canonical term definitions organized by category (identity, delegation, enforcement, execution, governance, coordination, reputation, data)
- **`crosswalk/`** — Per-implementation mapping files that connect canonical terms to each system's actual types and functions
- **`context.jsonld`** — JSON-LD `@context` for programmatic resolution of canonical terms
- **`examples/`** — Worked examples showing cross-system interoperability via the vocabulary

## What this is NOT

- Not a new specification
- Not a renaming mandate
- Not a replacement for any existing system's types

It's a **mapping layer** — a Rosetta Stone that lets different governance systems understand each other's primitives.

## How to use

### Reading a crosswalk

Each crosswalk file (e.g., `crosswalk/aps.yaml`) maps canonical terms to implementation-specific types:

```yaml
delegation:
  type: Delegation
  module: src/core/delegation.ts
  functions: [createDelegation, verifyDelegation]
  notes: "Scoped authority with monotonic narrowing and depth limits"
```

### Adding your system's crosswalk

1. Copy `crosswalk/aps.yaml` as a template
2. Replace each `type`, `module`, and `functions` with your system's equivalents
3. Add `notes` for any semantic differences
4. Submit a PR

### Programmatic resolution

Use `context.jsonld` with any JSON-LD processor to resolve canonical terms:

```json
{
  "@context": "https://raw.githubusercontent.com/aeoess/agent-passport-system/main/vocabulary/context.jsonld",
  "delegation": { "scope": ["commerce/*"], "depth": 2 }
}
```

## Categories

| Category | Terms | Description |
|----------|-------|-------------|
| **Identity** | agent-identity, principal, key-rotation, endorsement | Who agents are and who vouches for them |
| **Delegation** | delegation, scope, authority-narrowing, revocation, cascade-revocation | How authority is transferred and constrained |
| **Enforcement** | policy, enforcement-mode, values-floor | Rules governing agent behavior |
| **Execution** | action-receipt, execution-envelope, attestation | Proof of actions taken |
| **Governance** | governance-artifact, governance-change-type, approval, charter | How governance itself is managed |
| **Coordination** | task, intent, deliberation | How agents collaborate |
| **Reputation** | trust-score, reputation-authority | How trust is quantified |
| **Data** | derivation-rights, data-lifecycle | How data is governed |

## Contributing

Each governance system is invited to contribute its own crosswalk file. See `crosswalk/aps.yaml` for the format.
