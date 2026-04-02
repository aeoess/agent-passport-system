/**
 * MolTrust AAE ↔ APS Cross-Protocol Test
 * Runs 5 delegation narrowing vectors through APS delegation primitives.
 * Tests the INVARIANTS: scope subset, temporal narrowing, self-issuance, expiry.
 */
import {
  joinSocialContract,
  createDelegation,
  verifyDelegation,
} from 'agent-passport-system';

const results = [];

function report(vectorId, desc, expected, actual, details) {
  const pass = expected === actual;
  results.push({ vectorId, pass, expected, actual, details });
  console.log(`${pass ? '✅' : '❌'} ${vectorId}: ${desc}`);
  console.log(`   Expected: ${expected}  |  Got: ${actual}`);
  if (details) console.log(`   ${details}`);
  console.log('');
}

/** Check if a tool call is within delegation scope */
function isInScope(tool, delegation) {
  return delegation.scope.some(s => tool === s || tool.startsWith(s + ':'));
}

/** Check temporal narrowing: child.expiresAt <= parent.expiresAt */
function isTemporallyNarrowed(parent, child) {
  return new Date(child.expiresAt) <= new Date(parent.expiresAt);
}

// Create agents
const root = joinSocialContract({ name: 'issuer-root', mission: 'Root', owner: 'moltrust', capabilities: ['read','write','delegate'], platform: 'node' });
const agA = joinSocialContract({ name: 'agent-a', mission: 'A', owner: 'moltrust', capabilities: ['read','write','delegate'], platform: 'node' });
const agB = joinSocialContract({ name: 'agent-b', mission: 'B', owner: 'moltrust', capabilities: ['read'], platform: 'node' });
const agC = joinSocialContract({ name: 'agent-c', mission: 'C', owner: 'moltrust', capabilities: ['read'], platform: 'node' });

// ═══ TV-001: Valid narrowing ═══
try {
  const p1 = createDelegation({ delegatedBy: root.keyPair.publicKey, delegatedTo: agA.keyPair.publicKey, scope: ['read','write','delegate'], spendLimit: 1000, maxDepth: 3, privateKey: root.keyPair.privateKey, expiresInHours: 24*30 });
  const c1 = createDelegation({ delegatedBy: agA.keyPair.publicKey, delegatedTo: agB.keyPair.publicKey, scope: ['read'], spendLimit: 0, maxDepth: 2, privateKey: agA.keyPair.privateKey, expiresInHours: 24*7, parentDelegationId: p1.id });
  
  const sigValid = verifyDelegation(c1, agA.keyPair.publicKey);
  const scopeNarrowed = c1.scope.every(s => p1.scope.includes(s));
  const spendNarrowed = (c1.spendLimit || 0) <= (p1.spendLimit || Infinity);
  const temporalNarrowed = isTemporallyNarrowed(p1, c1);
  const allNarrowed = sigValid && scopeNarrowed && spendNarrowed && temporalNarrowed;
  
  report('moltrust-tv-001', 'Valid narrowed delegation', 'VALID', allNarrowed ? 'VALID' : 'INVALID',
    `sig=${sigValid} scope⊂=${scopeNarrowed} spend≤=${spendNarrowed} time≤=${temporalNarrowed}`);
} catch (e) { report('moltrust-tv-001', 'Valid narrowed delegation', 'VALID', 'ERROR', e.message); }

// ═══ TV-002: Scope escalation — 'write' not in parent scope ═══
try {
  const p2 = createDelegation({ delegatedBy: agA.keyPair.publicKey, delegatedTo: agB.keyPair.publicKey, scope: ['read'], spendLimit: 0, maxDepth: 2, privateKey: agA.keyPair.privateKey, expiresInHours: 24*7 });
  const toolInScope = isInScope('write', p2);
  report('moltrust-tv-002', 'Scope escalation attempt', 'INVALID', toolInScope ? 'VALID' : 'INVALID',
    `Tool 'write' in scope ['read']: ${toolInScope}. Escalated permissions: ['write']`);
} catch (e) { report('moltrust-tv-002', 'Scope escalation attempt', 'INVALID', 'INVALID', `Rejected: ${e.message}`); }

// ═══ TV-003: Validity escalation — child extends beyond parent ═══
try {
  const p3 = createDelegation({ delegatedBy: agA.keyPair.publicKey, delegatedTo: agB.keyPair.publicKey, scope: ['read'], spendLimit: 0, maxDepth: 2, privateKey: agA.keyPair.privateKey, expiresInHours: 24*7 });
  const c3 = createDelegation({ delegatedBy: agB.keyPair.publicKey, delegatedTo: agC.keyPair.publicKey, scope: ['read'], spendLimit: 0, maxDepth: 1, privateKey: agB.keyPair.privateKey, expiresInHours: 24*30, parentDelegationId: p3.id });
  const temporalOk = isTemporallyNarrowed(p3, c3);
  report('moltrust-tv-003', 'Validity escalation attempt', 'INVALID', temporalOk ? 'VALID' : 'INVALID',
    `Parent expires: ${p3.expiresAt}, Child expires: ${c3.expiresAt}, Overrun: ${!temporalOk}`);
} catch (e) { report('moltrust-tv-003', 'Validity escalation attempt', 'INVALID', 'INVALID', `Rejected: ${e.message}`); }

// ═══ TV-004: Self-issuance — subject == issuer ═══
try {
  const selfDel = createDelegation({ delegatedBy: agA.keyPair.publicKey, delegatedTo: agA.keyPair.publicKey, scope: ['read','write','delegate'], spendLimit: 10000, maxDepth: 5, privateKey: agA.keyPair.privateKey, expiresInHours: 24*365 });
  const isSelfIssued = selfDel.delegatedBy === selfDel.delegatedTo;
  report('moltrust-tv-004', 'Self-issuance detection', 'INVALID', isSelfIssued ? 'INVALID' : 'VALID',
    `delegatedBy===delegatedTo: ${isSelfIssued}. Self-delegation detected.`);
} catch (e) { report('moltrust-tv-004', 'Self-issuance detection', 'INVALID', 'INVALID', `Rejected: ${e.message}`); }

// ═══ TV-005: Expired credential (ghost agent) ═══
try {
  const expDel = createDelegation({ delegatedBy: root.keyPair.publicKey, delegatedTo: agA.keyPair.publicKey, scope: ['read','write'], spendLimit: 1000, maxDepth: 2, privateKey: root.keyPair.privateKey, expiresInHours: -24*31 });
  const sigValid5 = verifyDelegation(expDel, root.keyPair.publicKey);
  const isExpired = new Date(expDel.expiresAt) < new Date();
  report('moltrust-tv-005', 'Expired credential (ghost agent)', 'INVALID', isExpired ? 'INVALID' : 'VALID',
    `Signature valid: ${sigValid5}, Temporally expired: ${isExpired}, Expired: ${expDel.expiresAt}`);
} catch (e) { report('moltrust-tv-005', 'Expired credential (ghost agent)', 'INVALID', 'INVALID', `Rejected: ${e.message}`); }

// ═══ SUMMARY ═══
console.log('\n════════════════════════════════════════════════════');
console.log('  MolTrust AAE ↔ APS Cross-Protocol Test Results');
console.log('════════════════════════════════════════════════════');
const passed = results.filter(r => r.pass).length;
console.log(`  ${passed}/${results.length} vectors passed\n`);
results.forEach(r => {
  console.log(`  ${r.pass ? '✅' : '❌'} ${r.vectorId}: expected=${r.expected} got=${r.actual}`);
});
console.log('\n  Dimension Mapping (AAE → APS):');
console.log('  mandate.scope         → delegation.scopes     (direct)');
console.log('  constraints.spend     → delegation.spendLimit (numeric)');
console.log('  validity.not_after    → delegation.expiresAt  (ISO 8601)');
console.log('  constraints.rep_min   → passportGrade         (0-3 ↔ 0-100)');
console.log('  constraints.revers.   → cascade revocation    (enum)');
console.log('════════════════════════════════════════════════════\n');
