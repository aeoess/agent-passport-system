SDK v1.33.0 was just published to npm with new exports: computeActionRef, actionRefsMatch, canonicalJson, canonicalHash, normalizeTimestamp, computeEvidenceAge, isEvidenceFresh, createSnapshotFreshness, createRotatingFreshness, classifyEvidenceQuality, evidenceQualityToGrade. Plus new types: AttestationFreshness, EvidenceQuality.

Execute this chain IN ORDER. Each step must complete before the next starts.

## STEP 1: Update MCP server

cd /Users/tima/agent-passport-mcp
git stash && git pull --rebase && git stash pop

1. Update SDK dep in package.json: "agent-passport-system": "^1.33.0"
2. Run: npm install
3. CRITICAL: verify node_modules/agent-passport-system is a REAL directory, not a symlink: ls -la node_modules/agent-passport-system
4. Add new MCP tools to src/index.ts for these SDK functions:
   - compute_action_ref: takes agentId, actionType, scopeRequired, timestamp → returns actionRef hash
   - is_evidence_fresh: takes freshness object (type, validAt, ttl?, maxAge?) + optional now → returns boolean
   - classify_evidence_quality: takes method?, hasIssuerSignature?, hasPrincipalBinding?, evidence? → returns EvidenceQuality + grade number
5. Run: npm run build — verify bin.js, index.js, remote.js ALL exist in build/
6. Run: npm test (if tests exist)
7. Bump version: npm version 2.20.0 --no-git-tag-version
8. Run: npm run build again after version bump
9. git add -A && git commit -m "feat: v2.20.0 — action_ref, freshness, evidence-grade tools (SDK v1.33.0)"
10. DO NOT push yet. DO NOT publish. Tima handles npm publish (Touch ID).

## STEP 2: Verify MCP exports

node -e "const m = require('./build/index.js'); console.log('tools:', Object.keys(m).length || 'check exports')"

## STEP 3: Update remote MCP
After Tima publishes MCP to npm (Touch ID required), then:

cd /Users/tima/agent-passport-remote-mcp
git stash && git pull --rebase && git stash pop

1. Update MCP dep in package.json: "agent-passport-system-mcp": "^2.20.0"
2. Update SDK dep if present: "agent-passport-system": "^1.33.0"
3. npm install
4. npm run build
5. Verify build/bin.js, build/index.js, build/remote.js ALL exist
6. git add -A && git commit -m "deps: SDK v1.33.0, MCP v2.20.0"
7. git push origin main
8. WAIT 3 minutes for Railway deploy
9. Verify: curl -s https://mcp.aeoess.com/healthz
10. Verify SSE stays open: curl -sf -N https://mcp.aeoess.com/sse 2>&1 | head -5 (should see event: endpoint)

## STEP 4: Update ClawHub skill

/Users/tima/.npm-global/bin/clawhub publish /Users/tima/agent-passport-system/skills/agent-passport --version 1.33.0 --slug agent-passport-system

## STEP 5: Propagate website numbers

cd /Users/tima/aeoess_web
git stash && git pull --rebase && git stash pop

1. Run: node scripts/propagate.mjs --apply
2. Test count is now 2,230 (was 2,180). SDK version is 1.33.0 (was 1.32.0). MCP version is 2.20.0 (was 2.19.1).
3. Manual grep for stale values:
   grep -rn '1\.32\.0\|2,180\|2180\|2\.19\.1' *.html llms*.txt README.md 2>/dev/null
   grep -rn '1\.32\.0\|2180\|2\.19\.1' /Users/tima/agent-passport-system/README.md 2>/dev/null
   grep -rn '1\.32\.0\|2180' /Users/tima/agent-passport-mcp/README.md 2>/dev/null
4. Update any stale values found
5. Update the update window in index.html — add Apr 5 entry (newest at top):
   Apr 5: ship tag, "action_ref + freshness + evidence-based grades" — content-addressed request identity, typed evidence staleness, evidence-based grade assignment. 50 new tests. SDK v1.33.0. Blog link to day-48.
6. git add -A && git commit -m "propagate: SDK v1.33.0, 2230 tests, MCP v2.20.0"
7. git push origin main

## STEP 6: Post-deploy verification (CRITICAL)

bash /Users/tima/aeoess-gateway/scripts/post-deploy-verify.sh both 200

If that script doesn't exist or fails, manually verify:
- curl -s https://mcp.aeoess.com/healthz (should return JSON with status ok)
- curl -sf -N https://mcp.aeoess.com/sse 2>&1 | head -3 (should see SSE events)
- curl -s https://gateway.aeoess.com/healthz (should return status ok)

## DO NOT DO
- Do NOT run npm publish — Tima handles this (Touch ID)
- Do NOT push agent-passport-remote-mcp until AFTER Tima publishes MCP to npm
- Do NOT modify gateway code
- Do NOT skip the build/bin.js verification — missing files = broken SSE