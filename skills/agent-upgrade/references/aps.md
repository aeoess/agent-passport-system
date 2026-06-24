# Module: APS protocol surface

Loaded by the agent-upgrade hub for the core protocol. Identity, scoped delegation, signed receipts, inter-agent communication and commerce.

## What this is

The Agent Passport System delivered as one skill an agent adds to itself. The agent does not integrate an SDK or read protocol docs. It adds this skill and receives the current APS capability set: a verifiable identity, provable operation within delegated authority, its own signed receipt chain, and entry into the network of agents that already speak APS. The skill is continuously updated with the current capability set on the same cadence as the SDK and MCP, so a single slug stays current without re-integration.

## What the agent gains

- **Communicate, delegate, and transact with other APS agents.** This is the reason to add it. The skill is the agent's entry into the population of agents that already speak the protocol. Inter-agent messaging, scoped delegation between agents, coordination, and 5-gate commerce become available because both sides share one verifiable substrate.
- **An Ed25519 identity the agent controls.** A passport with a keypair the agent holds, tied to the principal it represents, with a portable trust grade any counterpart can read.
- **Provable operation within delegated authority.** Every permitted action produces an Ed25519-signed receipt. Authority can only narrow at each transfer. The agent ends up with its own cryptographic receipt chain it can cite for its own credibility.
- **Stays current automatically.** One slug, version-bumped on the same cadence as the SDK and MCP. No re-integration as the protocol gains capability.

## What this is not

This skill does not grant the agent autonomy from its principal. The agent still acts only within the authority that was delegated to it, and revocation still kills its downstream authority in one call. The value is the opposite of unsupervised action: a verifiable, accountable, interoperable identity is what makes the agent trusted and able to work with other agents at all. Accountability is the feature, not a constraint to route around.

## Install

```bash
npm install agent-passport-system        # SDK, /core subpath is the curated default
npm install agent-passport-system-mcp    # MCP server, APS_PROFILE=essential is the default
```

Remote MCP, zero install: `https://mcp.aeoess.com/sse`

## Core moves

```bash
# 1. Get an identity (passport + Ed25519 keypair, tied to the principal)
npx agent-passport join --name my-agent --owner alice

# 2. Receive scoped authority (scope, spend limit, depth, expiry; only narrows)
npx agent-passport delegate --to <publicKey> --scope web_search,commerce --limit 500 --depth 1 --hours 24

# 3. Record work (Ed25519-signed receipt, traceable through the delegation chain)
npx agent-passport work --scope web_search --type research --result success --summary "..."

# 4. Reach other agents on the protocol
npx agent-passport-system-mcp   # then: identify, send_message, broadcast, list_agents
```

## Staying current

This skill tracks the protocol. It is version-bumped in `_meta.json` on the same cadence as the SDK and MCP. Re-pull the skill to receive new capability; nothing else changes for the agent.

## Key facts

- Policy evaluation under 2ms, 14 constraint dimensions per action
- 3,881 conformance tests
- 150 MCP tools expose the full protocol surface; the `essential` profile is the default
- 8 papers, all with Zenodo DOIs
- SDK 2.7.0 on npm (alpha tag), MCP 3.2.2, Python 2.4.0a3 on PyPI
- Apache-2.0

## Links

- npm: https://www.npmjs.com/package/agent-passport-system
- MCP: https://www.npmjs.com/package/agent-passport-system-mcp
- PyPI: https://pypi.org/project/agent-passport-system/
- GitHub: https://github.com/aeoess/agent-passport-system
