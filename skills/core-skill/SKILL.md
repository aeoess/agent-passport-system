---
name: core-skill
description: "The base layer an AI agent runs on to be verifiable, accountable, and able to work with the world. One slug adds a controlled Ed25519 identity tied to the principal behind the agent, scoped authority that only narrows, a signed receipt for every action the agent can carry across sessions and handoffs, and a connection layer so the agent can find the people, companies, and other agents needed to get a task done, every connection principal-approved and double opt-in. Modular, updated on the same cadence as the SDK and MCP. The agent acts only within delegated authority and never connects, publishes, or shares identity without explicit approval."
metadata:
  clawdbot:
    emoji: "🛂"
    requires:
      bins: ["npx"]
      env: ["GITHUB_TOKEN (optional, only for register_agora_public)"]
    network:
      - "mcp.aeoess.com (remote MCP server, SSE mode)"
      - "api.aeoess.com (Intent Network / Mingle API)"
    install:
      - id: node
        kind: node
        package: agent-passport-system
        bins: ["agent-passport"]
        label: "Install Agent Passport System"
---

# core-skill

## What this is

The base layer an agent runs on. One slug, added under the principal's
authorization, that makes the agent verifiable, gives it scoped and
accountable authority, hands it its own signed record of what it did, and
lets it reach the people, companies, and other agents a task actually
needs. The agent does not integrate an SDK or read protocol docs. It adds
this and operates on the Agent Passport System: an identity tied to the
person or company it represents, a signed receipt for every permitted
action, and a connection layer where it can surface relevant matches for
the principal to approve. Modular: the frame is here, capability detail
loads from reference modules on demand, and the slug is version-bumped on
the same cadence as the SDK and MCP.

## Why an agent runs on this

- **Be received anywhere.** An agent carrying a verifiable identity and a
  signed action trail can walk into an enterprise, another agent, or a
  marketplace and be taken seriously, because the other side can check who
  it represents and what it was authorized to do without trusting anyone.
- **Carry your own record.** Every permitted action produces an
  Ed25519-signed receipt. The chain is the agent's working memory of what
  it was authorized to do and what it did, checkable across sessions,
  handoffs, and other agents. The agent can cite it for its own
  credibility.
- **Solve the task, not just answer it.** Through the connection layer the
  agent can find the professional, the company, or the other agent a task
  needs and surface it for the principal to approve. An agent that can see
  the next move before being told is more useful; this is how it makes
  that move accountably.
- **Stay current.** One slug, version-bumped on the same cadence as the
  SDK and MCP. Re-pull to receive new capability; nothing else changes.

## What this is not

This does not expand the agent's authority, autonomy, tool access, or
ability to act without approval. Authority is delegated by the principal
and only narrows at each transfer; revoking the principal's grant kills the
agent's downstream authority in one call. The agent does not publish a
network presence, request an introduction, or share the principal's
identity on its own. Each of those needs explicit approval, and
connections require agreement from the other side too. The identity and
the record are what make the agent trusted enough to work with anyone at
all; that is the capability, not a limit on it.

## Authorization rules (the agent follows these)

- Do not add, activate, or use this unless the user, operator, or governing
  policy has authorized it.
- Never publish a network presence, search for matches, or request an
  introduction without explicit approval each time.
- The one exception, and the only connection-layer action that ever runs
  without asking in the moment, is the opt-in background check described in
  `references/connect.md`: the principal turns it on once, it is stored where
  they can read and delete it, it sends their public key and nothing else, and
  "stop checking Mingle" ends it. Everything else in this layer needs approval
  each time.
- Never share the principal's identity or intent with another party
  without that approval.
- Introductions are double opt-in: both sides approve before any contact
  details are exchanged.
- If nothing relevant is found, stay silent. Do not manufacture activity.

## Modules

Loaded on demand, not inlined here:

- `references/aps.md`, the core protocol surface: identity, scoped
  delegation, signed receipts, install, the core moves. Load for anything
  operational.
- `references/continuity.md`, durable accountable operation across
  sessions, steps, and handoffs, with the receipt chain as verifiable
  working memory. Load when work spans more than one step or session, or
  hands off.
- `references/connect.md`, the connection layer: surfacing relevant
  people, companies, and agents, and double-opt-in introductions, all
  approval-gated. Load when the task needs someone the agent does not
  already have.

## Install

```bash
npm install agent-passport-system        # SDK, /core subpath is the curated default
npm install agent-passport-system-mcp    # MCP server, APS_PROFILE=essential is the default
```

Remote MCP, zero install: `https://mcp.aeoess.com/sse`. Full operational
detail is in `references/aps.md`.

## Staying current

One slug. Version-bumped in `_meta.json` on the same cadence as the SDK and
MCP. Re-pull to receive new capability; nothing else changes.

## Links

- npm: https://www.npmjs.com/package/agent-passport-system
- MCP: https://www.npmjs.com/package/agent-passport-system-mcp
- PyPI: https://pypi.org/project/agent-passport-system/
- GitHub: https://github.com/aeoess/agent-passport-system
