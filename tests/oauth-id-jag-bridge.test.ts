/**
 * oauth-id-jag-bridge.test.ts
 * BUILD 3 v2 (Track B candidate): OAuth ID-JAG to APS delegation binding.
 * Verifier-first. Phase 1 soundness verifier exercised on a valid descriptor;
 * Phase 2 adversarial vectors (each would pass a naive binding and must fail the
 * sound one); plus adapter tests. The binding is pure projection: it imports a
 * caller-verified grant, anchors two separate roots, signs a verification
 * attestation, and invents nothing. Pinned to draft-04.
 * Run: npx tsx --test tests/oauth-id-jag-bridge.test.ts
 */
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
  bindIdJagGrant, verifiedIdJagGrant, verifyIdJagDescriptor, IDJAG_DRAFT, IdJagBindingError,
  generateKeyPair, createDelegation, subDelegate, sign,
} from '../src/index.js';
import type { IdJagClaims, Delegation } from '../src/index.js';

const NOW = Math.floor(Date.now() / 1000);
const VERIFIED_AT = '2026-06-19T12:00:00.000Z';

function baseClaims(over: Partial<IdJagClaims> = {}): IdJagClaims {
  return {
    iss: 'https://idp.example', sub: 'did:example:enduser-1', aud: 'https://rs.example',
    client_id: 'client-app-1', jti: 'jti-0001', exp: NOW + 3600, iat: NOW,
    scope: 'read write', ...over,
  };
}

/** A small APS-signed chain bound under the grant (client then one actor hop). */
function buildChain(scope: string[], hops = 1): Delegation[] {
  const root = generateKeyPair(), client = generateKeyPair();
  const rootDel = createDelegation({
    delegatedTo: client.publicKey, delegatedBy: root.publicKey, scope,
    maxDepth: 6, currentDepth: 0, expiresInHours: 1, privateKey: root.privateKey,
  });
  const chain: Delegation[] = [rootDel];
  let parent = rootDel, parentKey = client;
  for (let i = 0; i < hops; i++) {
    const next = generateKeyPair();
    const hop = subDelegate({ parentDelegation: parent, delegatedTo: next.publicKey, scope, privateKey: parentKey.privateKey });
    chain.push(hop);
    parent = hop; parentKey = next;
  }
  return chain;
}

function bind(claims: IdJagClaims, chain: Delegation[] = buildChain(['read'])) {
  const caller = generateKeyPair();
  const verified = verifiedIdJagGrant(claims, { status: 'caller_verified', verifiedAt: VERIFIED_AT });
  return { descriptor: bindIdJagGrant(verified, chain, caller.privateKey), caller };
}

describe('ID-JAG binding: Phase 1 soundness verifier', () => {
  it('a valid descriptor is structurally sound with unchecked external constraints', () => {
    const { descriptor } = bind(baseClaims());
    const r = verifyIdJagDescriptor(descriptor);
    assert.equal(r.ok, true);
    assert.equal(r.status, 'structurally_valid_with_unchecked_external_constraints');
    assert.deepEqual(Object.values(r.checks).every(Boolean), true);
    // it never returns a bare safe-for-execution boolean
    assert.notEqual(r.status as string, 'safe');
  });
});

describe('ID-JAG binding: Phase 2 vectors', () => {
  it('V1 happy path; sourceGrantRef traces to the grant and recomputes', () => {
    const { descriptor } = bind(baseClaims());
    assert.equal(descriptor.draft, IDJAG_DRAFT);
    assert.equal(descriptor.rootRef.type, 'did');
    assert.equal((descriptor.rootRef as { did: string }).did, 'did:example:enduser-1');
    assert.equal(verifyIdJagDescriptor(descriptor).checks.sourceGrantRefRecomputes, true);
    // a different jti yields a different grant anchor (traces to the grant)
    const other = bind(baseClaims({ jti: 'jti-9999' }));
    assert.notEqual(other.descriptor.sourceGrantRef, descriptor.sourceGrantRef);
  });

  it('V2 the binding maps the grant exp to the descriptor expiresAt (the grant window)', () => {
    const { descriptor } = bind(baseClaims({ exp: NOW + 3600 }));
    // The binding's job: exp becomes the descriptor window, deterministically.
    assert.equal(descriptor.expiresAt, new Date((NOW + 3600) * 1000).toISOString());
    // The chain is carried and its content anchor recomputes.
    assert.equal(verifyIdJagDescriptor(descriptor).checks.delegationChainRootRecomputes, true);
    // NOTE: asserting that subDelegate caps every chain hop within the grant
    // window is intentionally NOT done here. During this build subDelegate was
    // found to produce a child that can outlive a near-expired parent:
    // createDelegation treats expiresInHours 0 as falsy and defaults to 24h, so a
    // child whose computed remaining window rounds to 0 hours via setHours gets a
    // fresh 24h expiry. That is a pre-existing primitive defect (expiry-dimension
    // narrowing) outside this binding, flagged in the build report rather than
    // asserted around here.
  });

  it('V3 a chain hop that widens scope beyond the grant is rejected by existing narrowing', () => {
    const root = generateKeyPair(), client = generateKeyPair(), actor = generateKeyPair();
    const rootDel = createDelegation({
      delegatedTo: client.publicKey, delegatedBy: root.publicKey, scope: ['read'],
      maxDepth: 4, currentDepth: 0, expiresInHours: 1, privateKey: root.privateKey,
    });
    assert.throws(
      () => subDelegate({ parentDelegation: rootDel, delegatedTo: actor.publicKey, scope: ['admin'], privateKey: client.privateKey }),
      /Scope violation/,
    );
  });

  it('V4 audience is carried, not enforced; the verifier never reports safe-for-execution', () => {
    const { descriptor } = bind(baseClaims({ aud: 'https://rs.example', resource: 'https://api.rs.example' }));
    assert.equal(descriptor.carriedAudience.enforcement, 'not_enforced_by_binding');
    assert.deepEqual(descriptor.carriedAudience.recipients, ['https://rs.example', 'https://api.rs.example']);
    assert.equal(verifyIdJagDescriptor(descriptor).status, 'structurally_valid_with_unchecked_external_constraints');
  });

  it('V5 act is advisory: absent, same-literal, and different-literal are flagged, never enforced', () => {
    const chain = buildChain(['read']);
    const leafActor = chain[chain.length - 1].delegatedTo;
    assert.equal(bind(baseClaims(), chain).descriptor.actReconciliation.status, 'absent');
    const same = bind(baseClaims({ act: { sub: leafActor } }), chain);
    assert.equal(same.descriptor.actReconciliation.status, 'same_literal_identifier');
    const diff = bind(baseClaims({ act: { sub: 'did:example:other-actor' } }), chain);
    assert.equal(diff.descriptor.actReconciliation.status, 'different_literal_identifier_not_enforced');
    assert.deepEqual(diff.descriptor.actReconciliation.advisoryAct, { sub: 'did:example:other-actor' });
  });

  it('V6 a grant missing a required claim, or missing verifiedAt, is refused', () => {
    const noClient = baseClaims();
    delete (noClient as Partial<IdJagClaims>).client_id;
    const caller = generateKeyPair();
    assert.throws(
      () => bindIdJagGrant(verifiedIdJagGrant(noClient as IdJagClaims, { status: 'caller_verified', verifiedAt: VERIFIED_AT }), buildChain(['read']), caller.privateKey),
      (e: unknown) => e instanceof IdJagBindingError && e.code === 'missing_required_claim',
    );
    assert.throws(
      () => bindIdJagGrant(verifiedIdJagGrant(baseClaims(), { status: 'caller_verified' }), buildChain(['read']), caller.privateKey),
      (e: unknown) => e instanceof IdJagBindingError && e.code === 'missing_verified_at',
    );
  });

  it('a unitless RAR amount is never stamped with a unit, across a 3-hop chain', () => {
    const chain = buildChain(['payment'], 2); // 3 nodes, none given a spend unit
    const { descriptor } = bind(baseClaims({ scope: 'payment', authorization_details: [{ type: 'payment', amount: 500 }] }), chain);
    assert.equal(descriptor.spendLimit, undefined);
    assert.equal(descriptor.spendLimitUnit, undefined);
    assert.ok(descriptor.diagnostics.some((d) => d.code === 'UNITLESS_AMOUNT_NOT_STAMPED'));
    for (const hop of descriptor.chain) assert.equal(hop.spendLimitUnit, undefined);
    assert.equal(verifyIdJagDescriptor(descriptor).checks.noSilentSpendUnit, true);
  });

  it('a tampered grant fails to recompute sourceGrantRef', () => {
    const { descriptor } = bind(baseClaims());
    descriptor.sourceGrantRefPreimage.aud = 'https://evil.example'; // tamper after binding
    const r = verifyIdJagDescriptor(descriptor);
    assert.equal(r.checks.sourceGrantRefRecomputes, false);
    assert.equal(r.ok, false);
    assert.equal(r.status, 'unsound');
  });

  it('a forged attestation fails to verify under the caller key', () => {
    const { descriptor } = bind(baseClaims());
    const attacker = generateKeyPair();
    // re-sign the same message with a different key; signerPublicKey stays the caller
    descriptor.callerVerification.signature = sign(descriptor.callerVerification.message, attacker.privateKey);
    const r = verifyIdJagDescriptor(descriptor);
    assert.equal(r.checks.attestationSignatureValid, false);
    assert.equal(r.ok, false);
  });

  it('an opaque RAR constraint is preserved verbatim and is immutable through the chain', () => {
    // BUILD-1 interaction rule: opaque RAR is not an APS delegation field, so
    // subDelegate neither narrows nor rejects it; strict equality is preserved.
    const rar = [{ type: 'read', constraint: { region: 'eu', tags: ['a', 'b'] } }];
    const chain = buildChain(['read'], 2);
    const { descriptor } = bind(baseClaims({ scope: 'read', authorization_details: rar }), chain);
    assert.deepEqual(descriptor.rawAuthorizationDetails, rar);
    assert.ok(descriptor.diagnostics.some((d) => d.code === 'OPAQUE_RAR_CARRIED_IMMUTABLE'));
  });

  it('RAR that would widen scope is conflict-flagged and never applied', () => {
    const { descriptor } = bind(baseClaims({ scope: 'read', authorization_details: [{ type: 'admin', amount: 1 }] }));
    assert.deepEqual(descriptor.scope, ['read']); // admin not added
    assert.ok(descriptor.diagnostics.some((d) => d.code === 'RAR_SCOPE_CONFLICT_NOT_APPLIED'));
  });

  it('the external root is labeled imported trust', () => {
    const { descriptor } = bind(baseClaims());
    assert.deepEqual(descriptor.externalRoot, { type: 'external_identity_assertion', protocol: 'id-jag', verifiedBy: 'caller' });
  });

  it('a descriptor missing the draft pin fails the verifier', () => {
    const { descriptor } = bind(baseClaims());
    assert.equal(descriptor.draft, IDJAG_DRAFT); // bind always sets it
    descriptor.draft = '';
    const r = verifyIdJagDescriptor(descriptor);
    assert.equal(r.checks.draftPinned, false);
    assert.equal(r.ok, false);
  });
});

describe('ID-JAG binding: adapter tests', () => {
  it('maps iat to createdAt and omits notBefore (no nbf in draft-04)', () => {
    const { descriptor } = bind(baseClaims());
    assert.equal(descriptor.createdAt, new Date(NOW * 1000).toISOString());
    assert.equal(Object.prototype.hasOwnProperty.call(descriptor, 'notBefore'), false);
  });

  it('a recognized RAR currency bound maps to the spend fields', () => {
    const { descriptor } = bind(baseClaims({ scope: 'pay', authorization_details: [{ type: 'pay', amount: 500, currency: 'USD' }] }));
    assert.equal(descriptor.spendLimit, 500);
    assert.equal(descriptor.spendLimitUnit, 'currency');
  });

  it('carries acr/amr/tenant and, by default, email/sub_id/aud_sub; minimize omits the sensitive ones', () => {
    const claims = baseClaims({ tenant: 't-1', acr: 'urn:acr:mfa', amr: ['pwd'], email: 'u@example', sub_id: 's-2', aud_sub: 'rs-9' });
    const { descriptor } = bind(claims);
    assert.equal(descriptor.opaqueContext.tenant, 't-1');
    assert.equal(descriptor.opaqueContext.email, 'u@example');
    assert.equal(descriptor.opaqueContext.sub_id, 's-2');
    const caller = generateKeyPair();
    const min = bindIdJagGrant(verifiedIdJagGrant(claims, { status: 'caller_verified', verifiedAt: VERIFIED_AT }), buildChain(['read']), caller.privateKey, { minimizeSensitive: true });
    assert.equal(min.opaqueContext.email, undefined);
    assert.equal(min.opaqueContext.sub_id, undefined);
    assert.equal(min.opaqueContext.aud_sub, undefined);
    assert.equal(min.opaqueContext.tenant, 't-1'); // non-sensitive still carries
  });

  it('marks revocation not checked and cnf/dpop not carried', () => {
    const { descriptor } = bind(baseClaims());
    assert.equal(descriptor.externalState.revocation, 'not_checked_by_binding');
    assert.deepEqual(descriptor.notCarried, { cnf: 'not_carried', dpop: 'not_carried' });
  });
});

/** Imported lazily so the forged-attestation vector can re-sign with an attacker key. */
async function importKeys(): Promise<{ sign: (m: string, k: string) => string }> {
  const mod = await import('../src/index.js');
  return { sign: mod.sign };
}
