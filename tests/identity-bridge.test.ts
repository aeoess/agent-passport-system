import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import {
  parseSPIFFEID, importSPIFFESVID,
  mapOAuthScopes, importOAuthToken,
} from '../src/core/identity-bridge.js';

// ═══ SPIFFE ═══

describe('parseSPIFFEID', () => {
  it('parses standard SPIFFE ID', () => {
    const parsed = parseSPIFFEID('spiffe://cluster.example.com/ns/default/sa/web-api');
    assert.equal(parsed.trustDomain, 'cluster.example.com');
    assert.equal(parsed.workloadPath, '/ns/default/sa/web-api');
  });

  it('parses single-segment workload path', () => {
    const parsed = parseSPIFFEID('spiffe://prod.acme.io/frontend');
    assert.equal(parsed.trustDomain, 'prod.acme.io');
    assert.equal(parsed.workloadPath, '/frontend');
  });

  it('rejects missing spiffe:// prefix', () => {
    assert.throws(() => parseSPIFFEID('https://example.com/path'), /must start with spiffe:\/\//);
  });

  it('rejects empty string', () => {
    assert.throws(() => parseSPIFFEID(''), /must start with spiffe:\/\//);
  });

  it('rejects SPIFFE ID without workload path', () => {
    assert.throws(() => parseSPIFFEID('spiffe://domain/'), /workload path must not be empty/);
  });

  it('rejects SPIFFE ID with no slash after domain', () => {
    assert.throws(() => parseSPIFFEID('spiffe://domain-only'), /missing trust domain or workload/);
  });
});

describe('importSPIFFESVID', () => {
  const validSVID = {
    spiffeId: 'spiffe://cluster.example.com/ns/prod/sa/trading-agent',
    expiresAt: '2026-12-31T23:59:59.000Z',
  };

  it('returns a ProviderAttestation', () => {
    const att = importSPIFFESVID(validSVID);
    assert.equal(att.provider, 'cluster.example.com');
    assert.equal(att.subjectClass, 'workload');
    assert.equal(att.verificationMethod, 'spiffe_bundle');
    assert.equal(att.expiresAt, '2026-12-31T23:59:59.000Z');
  });

  it('subjectIdHash is SHA-256 of the full SPIFFE ID', () => {
    const att = importSPIFFESVID(validSVID);
    const expected = crypto.createHash('sha256').update(validSVID.spiffeId).digest('hex');
    assert.equal(att.subjectIdHash, expected);
  });

  it('sets verificationMethod to x509 when cert provided', () => {
    const att = importSPIFFESVID({
      ...validSVID,
      x509Cert: 'MIIBdjCCAR...base64cert...',
    });
    assert.equal(att.verificationMethod, 'x509');
  });

  it('sets issuedAt to current time', () => {
    const before = Date.now();
    const att = importSPIFFESVID(validSVID);
    const after = Date.now();
    const issued = new Date(att.issuedAt).getTime();
    assert.ok(issued >= before && issued <= after);
  });

  it('rejects invalid SPIFFE ID', () => {
    assert.throws(
      () => importSPIFFESVID({ spiffeId: 'not-spiffe', expiresAt: '2026-01-01T00:00:00Z' }),
      /must start with spiffe:\/\//,
    );
  });

  it('rejects missing expiresAt', () => {
    assert.throws(
      () => importSPIFFESVID({ spiffeId: validSVID.spiffeId, expiresAt: '' }),
      /expiresAt is required/,
    );
  });

  it('deterministic: same SPIFFE ID produces same subjectIdHash', () => {
    const a = importSPIFFESVID(validSVID);
    const b = importSPIFFESVID(validSVID);
    assert.equal(a.subjectIdHash, b.subjectIdHash);
  });

  it('different SPIFFE IDs produce different subjectIdHash', () => {
    const a = importSPIFFESVID(validSVID);
    const b = importSPIFFESVID({
      spiffeId: 'spiffe://other.example.com/ns/prod/sa/other-agent',
      expiresAt: '2026-12-31T23:59:59.000Z',
    });
    assert.notEqual(a.subjectIdHash, b.subjectIdHash);
  });
});

// ═══ OAuth Scope Mapper ═══

describe('mapOAuthScopes', () => {
  it('maps default wildcards', () => {
    const result = mapOAuthScopes(['read:users', 'write:posts', 'admin:settings', 'pay:invoices']);
    assert.deepEqual(result, ['data_read', 'data_write', 'governance', 'commerce']);
  });

  it('deduplicates mapped scopes', () => {
    const result = mapOAuthScopes(['read:users', 'read:posts', 'read:comments']);
    assert.deepEqual(result, ['data_read']);
  });

  it('passes through unmapped scopes', () => {
    const result = mapOAuthScopes(['read:users', 'custom_scope', 'another:thing']);
    assert.deepEqual(result, ['data_read', 'custom_scope', 'another:thing']);
  });

  it('custom mapping overrides defaults', () => {
    const result = mapOAuthScopes(['read:users'], { 'read:*': 'full_access' });
    assert.deepEqual(result, ['full_access']);
  });

  it('custom mapping adds new patterns', () => {
    const result = mapOAuthScopes(['deploy:prod'], { 'deploy:*': 'infrastructure' });
    assert.deepEqual(result, ['infrastructure']);
  });

  it('exact match takes priority over wildcard', () => {
    const result = mapOAuthScopes(['read:sensitive'], {
      'read:sensitive': 'restricted_read',
      'read:*': 'data_read',
    });
    assert.deepEqual(result, ['restricted_read']);
  });

  it('returns empty array for empty input', () => {
    assert.deepEqual(mapOAuthScopes([]), []);
  });

  it('handles scopes without colon (no wildcard match)', () => {
    const result = mapOAuthScopes(['openid', 'profile', 'email']);
    assert.deepEqual(result, ['openid', 'profile', 'email']);
  });
});

// ═══ OAuth Token Import ═══

describe('importOAuthToken', () => {
  const validToken = {
    sub: 'client-agent-42',
    scope: 'read:data write:logs admin:config',
    iss: 'https://auth.example.com',
    exp: Math.floor(Date.now() / 1000) + 3600,
  };

  it('produces deterministic agentId from iss+sub', () => {
    const result = importOAuthToken(validToken);
    const expectedHash = crypto
      .createHash('sha256')
      .update(`${validToken.iss}:${validToken.sub}`)
      .digest('hex')
      .slice(0, 16);
    assert.equal(result.agentId, `agent-oauth-${expectedHash}`);
  });

  it('same iss+sub always produces same agentId', () => {
    const a = importOAuthToken(validToken);
    const b = importOAuthToken({ ...validToken, scope: 'different:scope', exp: validToken.exp + 999 });
    assert.equal(a.agentId, b.agentId);
  });

  it('different sub produces different agentId', () => {
    const a = importOAuthToken(validToken);
    const b = importOAuthToken({ ...validToken, sub: 'other-client' });
    assert.notEqual(a.agentId, b.agentId);
  });

  it('maps OAuth scopes to APS delegation scopes', () => {
    const result = importOAuthToken(validToken);
    assert.deepEqual(result.delegationScope, ['data_read', 'data_write', 'governance']);
  });

  it('converts exp to ISO 8601 expiresAt', () => {
    const result = importOAuthToken(validToken);
    const expected = new Date(validToken.exp * 1000).toISOString();
    assert.equal(result.expiresAt, expected);
  });

  it('accepts custom scope mapping', () => {
    const result = importOAuthToken(validToken, { 'read:*': 'analysis', 'write:*': 'research' });
    assert.deepEqual(result.delegationScope, ['analysis', 'research', 'governance']);
  });

  it('handles empty scope string', () => {
    const result = importOAuthToken({ ...validToken, scope: '' });
    assert.deepEqual(result.delegationScope, []);
  });

  it('rejects missing sub', () => {
    assert.throws(
      () => importOAuthToken({ ...validToken, sub: '' }),
      /must have a sub claim/,
    );
  });

  it('rejects missing iss', () => {
    assert.throws(
      () => importOAuthToken({ ...validToken, iss: '' }),
      /must have an iss claim/,
    );
  });

  it('rejects invalid exp', () => {
    assert.throws(
      () => importOAuthToken({ ...validToken, exp: 0 }),
      /must have a valid exp claim/,
    );
  });
});
