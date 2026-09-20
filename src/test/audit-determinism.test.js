import { describe, it, expect } from 'vitest';
import { freshStore, request } from './helpers.js';
import { exportAuditPack, verifyPack } from '../server/service.js';
import { verifyAuditPack } from '../core/audit.js';
import { canonicalJson, stableCompare } from '../core/canonical.js';
import { buildGraph, allPaths } from '../core/graph.js';
import { evaluate } from '../core/policy.js';
import { parseManifest } from '../core/sbom.js';
import { computeFingerprints } from '../core/fingerprint.js';
import { shopApiV1 } from '../../data/sbom/shop-api-v1.js';

describe('audit pack', () => {
  const options = { imageId: 'img-shop-api-2026-09', policyVersion: '2026.09', createdAt: '2026-09-21T03:00:00Z' };

  it('verifies on a clean export', async () => {
    const store = await freshStore();
    const pack = await exportAuditPack(store, options);
    const result = await verifyPack(pack);
    expect(result.ok).toBe(true);
    expect(result.errors).toEqual([]);
  });

  it('detects tampered manifest bytes even if only timestamp changed', async () => {
    const store = await freshStore();
    const pack = await exportAuditPack(store, options);
    const parsed = JSON.parse(pack.files['manifest.json'].bytes);
    parsed.metadata.timestamp = '2099-01-01T00:00:00Z';
    pack.files['manifest.json'].bytes = JSON.stringify(parsed);
    const result = await verifyAuditPack(pack);
    expect(result.ok).toBe(false);
    expect(result.errors.join(' ')).toMatch(/Tampered file: manifest.json/);
  });

  it('detects a modified policy document revision', async () => {
    const store = await freshStore();
    const pack = await exportAuditPack(store, options);
    pack.files['policy.json'].value.document.rules[0].message = 'changed';
    const result = await verifyAuditPack(pack);
    expect(result.ok).toBe(false);
    expect(result.errors.some((error) => error.includes('policy.json'))).toBe(true);
  });

  it('contains complete exception revisions and versions', async () => {
    const store = await freshStore();
    const pack = await exportAuditPack(store, options);
    const ids = pack.files['exceptions.json'].value.map((entry) => entry.exceptionId);
    expect(ids).toContain('EX-001');
    for (const entry of pack.files['exceptions.json'].value) {
      expect(entry.revision).toBeTruthy();
      expect(entry.document.policyVersion).toBeTruthy();
    }
    expect(pack.summary.eventChainDigest).toMatch(/^[0-9a-f]{64}$/);
  });

  it('exposes verify over HTTP', async () => {
    const store = await freshStore();
    const exported = await request(store, '/api/audit/export', options, 'POST');
    const res = await request(store, '/api/audit/verify', { pack: exported.data.pack }, 'POST');
    expect(res.status).toBe(200);
    expect(res.data.ok).toBe(true);
  });
});

describe('determinism / reproducibility', () => {
  it('evaluation is identical regardless of component traversal order', async () => {
    const model = parseManifest(shopApiV1);
    const fingerprints = await computeFingerprints(JSON.stringify(shopApiV1), model);
    const store = await freshStore();
    const policy = store.getPolicy('2026.09');
    const exceptions = store.listExceptions();
    const run = () =>
      evaluate({
        model: {
          ...model,
          components: [...model.components].sort(() => Math.random() - 0.5),
          edges: [...model.edges].sort(() => Math.random() - 0.5)
        },
        policy,
        exceptions,
        at: '2026-09-21T03:00:00Z',
        fingerprint: fingerprints.imageFingerprint
      });
    const first = canonicalJson(await run());
    for (let index = 0; index < 5; index += 1) {
      expect(canonicalJson(await run())).toBe(first);
    }
  });

  it('path ordering is stable and does not depend on insertion order', async () => {
    const model = parseManifest(shopApiV1);
    const shuffledComponents = [...model.components].reverse();
    const shuffledEdges = [...model.edges].reverse();
    const graphA = buildGraph(model.components, model.edges, model.rootIds);
    const graphB = buildGraph(shuffledComponents, shuffledEdges, model.rootIds);
    const pathsA = allPaths(graphA, 'pkg:npm/ms@2.1.2').map((path) => path.join('>'));
    const pathsB = allPaths(graphB, 'pkg:npm/ms@2.1.2').map((path) => path.join('>'));
    expect(pathsA).toEqual(pathsB);
  });

  it('canonical JSON sorts object keys recursively across platforms', () => {
    expect(canonicalJson({ b: 1, a: { d: 2, c: 3 } })).toBe('{"a":{"c":3,"d":2},"b":1}');
    const keys = ['z', 'a', 'm', 'B', 'A'];
    expect([...keys].sort(stableCompare)).toEqual(['A', 'B', 'a', 'm', 'z']);
  });

  it('audit pack digest is reproducible from the same saved inputs', async () => {
    const storeA = await freshStore();
    const storeB = await freshStore();
    const packA = await exportAuditPack(storeA, { imageId: 'img-shop-api-2026-09', policyVersion: '2026.09', createdAt: '2026-09-21T03:00:00Z' });
    const packB = await exportAuditPack(storeB, { imageId: 'img-shop-api-2026-09', policyVersion: '2026.09', createdAt: '2026-09-21T03:00:00Z' });
    expect(packB.packDigest).toBe(packA.packDigest);
  });
});
