#!/usr/bin/env npx tsx
/**
 * Agent Passport System — Enforcement Demo
 *
 * Three agents, different permissions. Watch what happens when they
 * try to act outside their scope.
 *
 * Run: npx tsx examples/enforcement-demo.ts
 */

import {
  joinSocialContract,
  delegate,
  loadFloor,
  createAgentContext,
} from '../src/index.js'
import { readFileSync } from 'fs'
import { join, dirname } from 'path'
import { fileURLToPath } from 'url'

const __dirname = dirname(fileURLToPath(import.meta.url))

const G = '\x1b[32m', R = '\x1b[31m', Y = '\x1b[33m', C = '\x1b[36m', D = '\x1b[2m', B = '\x1b[1m', X = '\x1b[0m'

function header(text: string) { console.log(`\n${C}═══ ${text} ═══${X}\n`) }
function ok(text: string)     { console.log(`  ${G}✓${X} ${text}`) }
function deny(text: string)   { console.log(`  ${R}✗${X} ${text}`) }
function info(text: string)   { console.log(`  ${D}${text}${X}`) }

console.log(`${B}
╔════════════════════════════════════════════════════╗
║  Agent Passport System — Enforcement Demo          ║
║  3 agents. Different permissions. Same protocol.   ║
╚════════════════════════════════════════════════════╝${X}`)

const floorYaml = readFileSync(join(__dirname, '../values/floor.yaml'), 'utf-8')
const floor = loadFloor(floorYaml)

// ─── The Human Principal ───
header('1. Human creates the principal identity')

const principal = joinSocialContract({
  name: 'tima-principal',
  mission: 'Human operator — delegates authority to agents',
  owner: 'tima',
  capabilities: ['admin'],
  platform: 'node',
  models: ['human'],
  floor,
})
ok(`Principal created: ${principal.agentId.slice(0, 12)}...`)

// ─── Three Agents ───
header('2. Three agents join with different permissions')

const researcher = joinSocialContract({
  name: 'researcher-agent',
  mission: 'Find and analyze information',
  owner: 'tima',
  capabilities: ['data:read', 'api:fetch'],
  platform: 'node',
  models: ['claude-sonnet'],
  floor,
})
ok(`Researcher: data:read, api:fetch`)

const purchaser = joinSocialContract({
  name: 'purchaser-agent',
  mission: 'Buy approved supplies within budget',
  owner: 'tima',
  capabilities: ['commerce:checkout', 'commerce:browse'],
  platform: 'node',
  models: ['gpt-4'],
  floor,
})
ok(`Purchaser: commerce:checkout, commerce:browse`)

const deployer = joinSocialContract({
  name: 'deployer-agent',
  mission: 'Deploy approved changes to staging',
  owner: 'tima',
  capabilities: ['code:deploy', 'code:test'],
  platform: 'node',
  models: ['claude-opus'],
  floor,
})
ok(`Deployer: code:deploy, code:test`)

// ─── Delegate Authority ───
header('3. Human delegates specific authority')

const researchDel = delegate({
  from: principal,
  toPublicKey: researcher.publicKey,
  scope: ['data:read', 'api:fetch'],
  spendLimit: 0,
  maxDepth: 1,
  expiresInHours: 8,
})
ok(`Researcher: data:read, api:fetch — $0 spend, 8h`)

const purchaseDel = delegate({
  from: principal,
  toPublicKey: purchaser.publicKey,
  scope: ['commerce:checkout', 'commerce:browse'],
  spendLimit: 200,
  maxDepth: 1,
  expiresInHours: 4,
})
ok(`Purchaser: commerce:checkout, commerce:browse — $200 limit, 4h`)

const deployDel = delegate({
  from: principal,
  toPublicKey: deployer.publicKey,
  scope: ['code:deploy', 'code:test'],
  spendLimit: 0,
  maxDepth: 2,
  expiresInHours: 2,
})
ok(`Deployer: code:deploy, code:test — $0 spend, 2h`)

// ─── Enforcement Contexts ───
header('4. Wrap each agent in enforcement context')
info('Every action now goes through the 3-signature chain automatically')

const researchCtx = createAgentContext(researcher, floor, { enforcement: 'auto' })
researchCtx.addDelegation(researchDel)

const purchaseCtx = createAgentContext(purchaser, floor, { enforcement: 'auto' })
purchaseCtx.addDelegation(purchaseDel)

const deployCtx = createAgentContext(deployer, floor, { enforcement: 'auto' })
deployCtx.addDelegation(deployDel)

ok('All three agents wrapped in auto enforcement')

// ─── Actions Within Scope ───
header('5. Actions within scope — all PASS')

const r1 = researchCtx.execute({ type: 'api:fetch', target: 'https://api.weather.com/forecast', scope: 'api:fetch' })
r1.permitted ? ok(`Researcher fetches weather API → ${G}PERMITTED${X}`) : deny('DENIED')

const p1 = purchaseCtx.execute({ type: 'commerce:browse', target: 'office-supplies.com', scope: 'commerce:browse' })
p1.permitted ? ok(`Purchaser browses store → ${G}PERMITTED${X}`) : deny('DENIED')

const d1 = deployCtx.execute({ type: 'code:test', target: 'staging/test-suite', scope: 'code:test' })
d1.permitted ? ok(`Deployer runs tests → ${G}PERMITTED${X}`) : deny('DENIED')

if (r1.permitted) researchCtx.complete(r1, { status: 'success', summary: 'Fetched 7-day forecast' })
if (p1.permitted) purchaseCtx.complete(p1, { status: 'success', summary: 'Browsed office supplies' })
if (d1.permitted) deployCtx.complete(d1, { status: 'success', summary: 'All 240 tests passing' })

// ─── Actions Outside Scope — DENIED ───
header('6. Actions outside scope — all DENIED')

const r2 = researchCtx.execute({ type: 'commerce:checkout', target: 'buy-gpu.com/rtx5090', scope: 'commerce:checkout' })
r2.permitted
  ? ok(`Researcher buys GPU → PERMITTED (!)`)
  : deny(`Researcher tries to buy GPU → ${R}DENIED${X} — "${r2.reason}"`)

const p2 = purchaseCtx.execute({ type: 'code:deploy', target: 'production/main', scope: 'code:deploy' })
p2.permitted
  ? ok(`Purchaser deploys to prod → PERMITTED (!)`)
  : deny(`Purchaser tries to deploy code → ${R}DENIED${X} — "${p2.reason}"`)

const d2 = deployCtx.execute({ type: 'data:read', target: '/secrets/api-keys.json', scope: 'data:read' })
d2.permitted
  ? ok(`Deployer reads secrets → PERMITTED (!)`)
  : deny(`Deployer tries to read secrets → ${R}DENIED${X} — "${d2.reason}"`)

const p3 = purchaseCtx.execute({
  type: 'commerce:checkout',
  target: 'buy-gpu.com/rtx5090',
  scope: 'commerce:checkout',
  spend: { amount: 1599, currency: 'USD' },
})
if (p3.verdict === 'narrow') {
  console.log(`  ${Y}⚠${X} Purchaser tries $1,599 purchase → ${Y}NARROWED${X} — "${p3.reason}"`)
  info('Agent has commerce:checkout scope but spend exceeds $200 delegation limit')
} else if (p3.permitted) {
  ok(`Purchaser spends $1599 → PERMITTED (!)`)
} else {
  deny(`Purchaser tries $1,599 purchase → ${R}DENIED${X} — "${p3.reason}"`)
}

// ─── Audit Trail ───
header('7. Full audit trail')

for (const [name, ctx] of [['Researcher', researchCtx], ['Purchaser', purchaseCtx], ['Deployer', deployCtx]] as const) {
  console.log(`  ${B}${name}:${X}`)
  for (const entry of (ctx as any).auditLog) {
    const icon = entry.verdict === 'permit' ? `${G}✓${X}` : entry.verdict === 'narrow' ? `${Y}⚠${X}` : `${R}✗${X}`
    console.log(`    ${icon} ${entry.action.type} → ${entry.action.target} [${entry.verdict}]`)
  }
}

// ─── Stats ───
header('8. Summary')

for (const [name, ctx] of [['Researcher', researchCtx], ['Purchaser', purchaseCtx], ['Deployer', deployCtx]] as const) {
  const s = (ctx as any).stats
  const parts = [`${G}${s.permitted} permitted${X}`, `${R}${s.denied} denied${X}`]
  if (s.narrowed > 0) parts.push(`${Y}${s.narrowed} narrowed${X}`)
  console.log(`  ${B}${name}:${X} ${parts.join(', ')}, ${s.total} total`)
}

console.log(`
${D}Every action went through the 3-signature chain:
  1. Agent declares intent (signed ActionIntent)
  2. Policy engine evaluates against floor + delegation (signed PolicyDecision)
  3. Execution creates receipt (signed ActionReceipt)

No agent could skip enforcement. No agent could exceed its scope.
The audit trail is cryptographically signed and immutable.${X}

${C}Learn more: https://github.com/aeoess/agent-passport-system${X}
${C}npm install agent-passport-system${X}
`)
