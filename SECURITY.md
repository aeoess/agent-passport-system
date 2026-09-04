# Security Policy

## Reporting Vulnerabilities

If you discover a security vulnerability in the Agent Passport System, please report it responsibly.

**Report privately:** https://github.com/aeoess/agent-passport-system/security/advisories
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
| agent-passport-system >= 6.0.0 | ✅ |
| mingle-mcp >= 1.1.0 | ✅ |
| Older versions | ❌ |

Every `agent-passport-system` version from 1.5.1 through 5.0.3 is unsupported;
the 6.0.0 advisory, GHSA-r2fw-x6mg-f6h8, published at
https://github.com/aeoess/agent-passport-system/security/advisories, describes
the verification defects they carry.

For `agent-passport-system-mcp` support and version information, see the MCP
server repository's own security policy.

## Verifying releases

The normal npm release path uses Trusted Publishing (OIDC), which adds npm
registry provenance without a long-lived publishing token. To verify registry
signatures and npm provenance attestations in an installed dependency tree:

```
npm audit signatures
```

The immutable `agent-passport-system@5.0.0` version is a dated exception. It
was published on 2026-09-01 with the registry shasum
`1f046763cf78b2b86a2966e49a89e9c1d78c9cf8` and a registry signature, but
without npm provenance. It contains the security remediation released as
`5.0.0`; the exception concerns release provenance, not the fixed code. A
GitHub repository artifact attestation over matching tarball bytes is separate
evidence and cannot add npm provenance to an already published npm version. A
first attempt at that patch release, tagged `v5.0.1` on 2026-09-02, failed in
the release workflow before npm publication or GitHub Release creation (a
release-workflow transport defect, fixed in #139); no `5.0.1` version exists on
npm. A second attempt, tagged `v5.0.2` on 2026-09-02, passed packaging and
attestation and failed at GitHub Release creation (a release-workflow
repository-binding defect, fixed in #141); no `5.0.2` version exists on npm. If
published through the corrected Trusted Publishing workflow, `5.0.3` is
intended to be the first post-remediation patch release that restores the
normal npm provenance property. Version-specific registry metadata is
available from:
https://www.npmjs.com/package/agent-passport-system?activeTab=versions

## Secrets policy

The project holds no long-lived secrets. npm publishing uses OIDC Trusted
Publishing, so no registry token exists to store or rotate. CI runs on
ephemeral per-run GITHUB_TOKENs with a read-only default and least-privilege
grants declared per workflow. Repository push protection blocks accidental
secret commits. Any future credential gets a named owner, least-privilege
scope, and rotation on collaborator change or suspected exposure.

## Recognition

We gratefully acknowledge security researchers who report vulnerabilities responsibly. With your permission, we will credit you in our changelog.
