# AEOESS — Agent Passport System

## What This Is
Open protocol for AI agent identity, trust, governance, and commerce. Ed25519 cryptographic identity, scoped delegation chains with monotonic narrowing, gateway enforcement boundary, Merkle attribution, signed coordination. Solo founder: Tima (Tymofii Pidlisnyi).

## Current State (auto-updated by propagation)
- SDK: v1.30.0 — 2057 tests, 523 suites, 99 modules (67 core + 32 v2)
- MCP: v2.19.1 — 125 tools
- Gateway: v0.3.3 — 36 routes + context continuity score
- Python SDK: v0.7.0 on PyPI

## Repos
| Repo | Path | Live |
|------|------|------|
| SDK | `/Users/tima/agent-passport-system` | npm: agent-passport-system |
| MCP | `/Users/tima/agent-passport-mcp` | npm: agent-passport-system-mcp |
| Gateway | `/Users/tima/aeoess-gateway` | gateway.aeoess.com (Railway) |
| Web | `/Users/tima/aeoess_web` | aeoess.com (GitHub Pages) |
| MCP Remote | `/Users/tima/agent-passport-remote-mcp` | mcp.aeoess.com (Railway) |
| Python SDK | `/Users/tima/agent-passport-python` | PyPI: agent-passport-system |

## Reference Files (read these when needed)
| When | Read |
|------|------|
| Starting a build session | `~/aeoess_web/specs/ARCHITECTURE.md` |
| Build spec exists | `~/aeoess_web/specs/BUILD-SPEC-*.md` — execute these |
| Updating versions | `~/aeoess_web/UPDATE-PROPAGATION-SPEC.md` |
| Orienting in codebase | `~/aeoess_web/specs/FILE-TREE.md` |
| Research priorities | `~/aeoess_web/specs/RESEARCH-GAPS-CONSOLIDATED.md` |
| Gateway strategy | `~/aeoess-gateway/STRATEGY.md` |

## Build Specs = Your Instructions
Strategy sessions in claude.ai produce `BUILD-SPEC-*.md` files in `~/aeoess_web/specs/`. These are your build orders. When Tima says "read the build spec and execute" — find the relevant spec, read it, and build what it says.

## IP Boundary — Ask Before Every New Feature
**Protocol primitive or product intelligence?**
- Protocol primitives (types, functions) → public SDK at `src/`
- Product intelligence (analytics, drift, metering, cross-tenant) → private gateway at `~/aeoess-gateway`

## Key Architectural Rules
- Authority can only decrease at each transfer point (monotonic narrowing)
- Gateway is both judge and executor, not just approver
- Evidence tiers: Infrastructure > Behavioral > Self-declared
- Session passports default, persistent passports opt-in (validityWindow)

## CMD-SETs (Operational Runbooks)

### CMD-SET-1: Propagation (after any version/test/module change)
1. `cd ~/aeoess_web && node scripts/propagate.mjs --apply`
2. Grep for stale values in: index.html (meta, og, JSON-LD, FAQ, arch header, hero stats), passport.html, compare.html, faq.html, llms.txt, llms-full.txt
3. Pattern to check: current core count + "core", current module count + "modules", stale test counts
4. Blog entries are HISTORICAL — never update past day entries

### CMD-SET-3: Deploy/Publish
1. Bump version in package.json
2. `npm run build && npm test` — 0 failures required
3. Commit: `git add -A && git commit`
4. Tima runs `npm publish` (Touch ID required — cannot automate)
5. Run CMD-SET-1 (propagation)
6. Git push all repos
7. `bash ~/aeoess_web/scripts/verify-deploy.sh` — all checks must pass
8. ClawHub: `/Users/tima/.npm-global/bin/clawhub publish ~/agent-passport-system/skills/agent-passport --version X.Y.Z --slug agent-passport-system`

### Git Workflow
Always: `git stash && git pull --rebase && git stash pop` before committing.

## Safety Rules

### MCP Remote (mcp.aeoess.com)
After ANY change: verify `build/bin.js` + `build/index.js` + `build/remote.js` ALL exist. `npm run build` exits 0. After Railway deploy: wait 3min, run `verify-deploy.sh`. MCP remote is Railway only — NO pm2 on Air.

### Infrastructure Split
- MacBook Air (`tima`): Dev only. NO production services.
- Mac Mini (`clawrot`): Intent Network API (port 3100, api.aeoess.com). Gateway dogfood (port 3200, local).
- Railway: MCP remote (mcp.aeoess.com) + Gateway (gateway.aeoess.com). Both auto-deploy on git push.

### npm Publish
Requires Tima's Touch ID. Cannot be automated. Tima must run `npm publish` manually.

## Writing Style
Hooks via curiosity gap or concrete result. No clickbait. Show-don't-tell with code. Conversational tone. Never fabricate scenarios. Never use em dashes.

## Tests
`npm test` runs all 2057 tests. Test files are manually listed in package.json — new test files must be added to the list.

## Exports
`src/index.ts` is the single source of truth for the public API. All new functions must be exported here.

## gstack
Use /browse from gstack for all web browsing. Never use mcp__claude-in-chrome__* tools.
Available skills: /office-hours, /plan-ceo-review, /plan-eng-review, /plan-design-review, /design-consultation, /design-shotgun, /design-html, /review, /ship, /land-and-deploy, /canary, /benchmark, /browse, /connect-chrome, /qa, /qa-only, /design-review, /setup-browser-cookies, /setup-deploy, /retro, /investigate, /document-release, /codex, /cso, /autoplan, /careful, /freeze, /guard, /unfreeze, /gstack-upgrade, /learn.
If gstack skills aren't working, run `cd ~/.claude/skills/gstack && ./setup` to rebuild.
