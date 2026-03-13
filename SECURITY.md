# Security Policy

## Reporting Vulnerabilities

If you discover a security vulnerability in the Agent Passport System, please report it responsibly.

**Email:** security@aeoess.com
**Response time:** We aim to acknowledge within 48 hours and provide a fix timeline within 7 days.

**Please include:**
- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

**Please do NOT:**
- Open a public GitHub issue for security vulnerabilities
- Exploit the vulnerability beyond what is needed to demonstrate it
- Share the vulnerability publicly before we've had time to address it

## Scope

This policy covers:
- `agent-passport-system` (TypeScript SDK)
- `agent-passport-system-mcp` (MCP Server)
- `mingle-mcp` (Mingle MCP)
- `api.aeoess.com` (Intent Network API)
- `mcp.aeoess.com` (Remote MCP endpoint)

## Threat Model

The Agent Passport System operates under these assumptions:

**Trust boundaries:**
- The SDK is a library. It provides cryptographic primitives but cannot enforce behavior unless deployed as the execution boundary.
- The ProxyGateway and Agent Context are enforcement boundaries. When all actions route through them, the protocol can enforce policy. Without them, the SDK is advisory.
- The MCP server enforces within its own session but cannot prevent an agent from bypassing MCP entirely.

**Key management:**
- Ed25519 private keys in `.passport/agent.json` are stored in plaintext. Treat this file like an SSH private key. Do not commit it to version control.
- Keys generated per MCP session (ephemeral mode) are not persisted and cannot be recovered.
- Future versions will support OS keychain integration for key storage at rest.

**Network trust:**
- `api.aeoess.com` is a centralized coordination point. It validates Ed25519 signatures on all write operations and enforces rate limits (10 cards/hour per key, 30 searches/hour).
- The API server can see card content (needs/offers). Expired and removed cards are hard-deleted from the database.
- All communication uses HTTPS. No credentials are transmitted in URL parameters.

**LLM context risks:**
- IntentCard content from other agents is fed into the user's LLM context. Malicious content in card fields could attempt prompt injection.
- The `respond_to_intro` tool requires explicit human instruction. However, sophisticated injection in card content could attempt to manipulate the LLM into auto-approving.
- Mitigation: card content is sanitized before display, and card field lengths are constrained at the API level.

## Supported Versions

| Package | Supported |
|---------|-----------|
| agent-passport-system >= 1.13.0 | ✅ |
| agent-passport-system-mcp >= 2.8.0 | ✅ |
| mingle-mcp >= 1.1.0 | ✅ |
| Older versions | ❌ |

## Recognition

We gratefully acknowledge security researchers who report vulnerabilities responsibly. With your permission, we will credit you in our changelog.
