import { describe, it, expect } from 'vitest';
import { isActiveAt, instantMillis } from '../core/time.js';
import { freshStore, findFinding, request } from './helpers.js';
import { evaluateImage } from '../server/service.js';

const window = { validFrom: '2026-12-01T00:00:00Z', validUntil: '2026-12-31T23:59:59+09:00' };

describe('exception time semantics (half-open interval, explicit zones)', () => {
  it('is active at validFrom itself', () => {
    expect(isActiveAt(window, '2026-12-01T00:00:00Z')).toBe(true);
  });
  it('is active one minute before the cutoff in the stated zone', () => {
    expect(isActiveAt(window, '2026-12-31T23:58:59+09:00')).toBe(true);
  });
  it('is EXPIRED exactly at validUntil (boundary fixed)', () => {
    expect(isActiveAt(window, '2026-12-31T23:59:59+09:00')).toBe(false);
  });
  it('treats the same instant in different zones identically', () => {
    expect(instantMillis('2026-12-31T23:59:59+09:00')).toBe(instantMillis('2026-12-31T14:59:59Z'));
    expect(isActiveAt(window, '2026-12-31T14:59:59Z')).toBe(false);
  });
  it('is active after validFrom in another timezone', () => {
    expect(isActiveAt(window, '2026-12-01T09:00:00+09:00')).toBe(true);
  });
});

describe('exception binding', () => {
  it('waives the deny finding for v1 while the license finding stays open after expiry', async () => {
    const store = await freshStore();
    const data = await evaluateImage(store, { imageId: 'img-shop-api-2026-09', policyVersion: '2026.09', at: '2026-09-21T03:00:00Z' });
    const deny = findFinding(data.result, 'R-DEN-LEFT-PAD-130');
    const gpl = findFinding(data.result, 'R-LIC-GPL', 'pkg:npm/left-pad@1.3.0');
    expect(deny.waivedBy).toBe('EX-001');
    expect(gpl.waivedBy).toBeUndefined();
  });

  it('had waived the GPL finding historically while EX-002 was in force', async () => {
    const store = await freshStore();
    const data = await evaluateImage(store, { imageId: 'img-shop-api-2026-09', policyVersion: '2026.09', at: '2026-09-10T00:00:00Z' });
    const gpl = findFinding(data.result, 'R-LIC-GPL', 'pkg:npm/left-pad@1.3.0');
    expect(gpl.waivedBy).toBe('EX-002');
  });

  it('does not carry the v1 exception onto the upgraded v2 image (fingerprint)', async () => {
    const store = await freshStore();
    const data = await evaluateImage(store, { imageId: 'img-shop-api-2026-10', policyVersion: '2026.09', at: '2026-09-21T03:00:00Z' });
    expect(data.result.findings.some((f) => f.waivedBy === 'EX-001')).toBe(false);
  });

  it('does not match when the policy version changes', async () => {
    const store = await freshStore();
    const data = await evaluateImage(store, { imageId: 'img-shop-api-2026-09', policyVersion: '2026.10', at: '2026-09-21T03:00:00Z' });
    const deny = findFinding(data.result, 'R-DEN-LEFT-PAD-130');
    expect(deny.policyVersion).toBe('2026.10');
    expect(deny.waivedBy).toBeUndefined();
  });

  it('requires reason and rejects inverted time windows through the API', async () => {
    const store = await freshStore();
    const image = store.getImage('img-shop-api-2026-09');
    const res = await request(store, '/api/exceptions', {
      componentId: 'pkg:npm/rogue-source-vendor@1.0.0',
      ruleId: 'R-SRC-UNTRUSTED-MIRROR',
      policyVersion: '2026.09',
      imageFingerprint: image.imageFingerprint,
      validFrom: '2026-12-31T00:00:00Z',
      validUntil: '2026-12-01T00:00:00Z',
      reason: 'x',
      operator: 'tester',
      at: '2026-09-21T03:00:00Z'
    }, 'POST');
    expect(res.status).toBe(400);
  });

  it('binds to saved paths: a path-only waiver does not match new routes', async () => {
    const store = await freshStore();
    const image = store.getImage('img-shop-api-2026-09');
    const evalData = await evaluateImage(store, { imageId: image.id, at: '2026-09-21T03:00:00Z' });
    const rogue = findFinding(evalData.result, 'R-SRC-UNTRUSTED-MIRROR');
    const res = await request(store, '/api/exceptions', {
      exceptionId: 'EX-PATH-1',
      componentId: rogue.componentId,
      ruleId: rogue.ruleId,
      policyVersion: '2026.09',
      imageFingerprint: image.imageFingerprint,
      boundPaths: [['pkg:oci/shop-api?repository_url=registry.internal&tag=2026.09', 'pkg:npm/nonexistent@9.9.9']],
      validFrom: '2026-09-01T00:00:00Z',
      validUntil: '2027-01-01T00:00:00Z',
      reason: 'bound to a route that does not exist',
      operator: 'tester',
      at: '2026-09-21T03:00:00Z'
    }, 'POST');
    expect(res.status).toBe(201);
    const approve = await request(store, '/api/exceptions/EX-PATH-1/approve', { reason: 'ok' }, 'POST');
    expect(approve.status).toBe(200);
    const reeval = await evaluateImage(store, { imageId: image.id, at: '2026-09-21T03:00:00Z' });
    expect(findFinding(reeval.result, 'R-SRC-UNTRUSTED-MIRROR').waivedBy).toBeUndefined();
  });
});
