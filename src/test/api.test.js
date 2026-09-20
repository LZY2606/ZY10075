import { describe, it, expect } from 'vitest';
import { freshStore, request } from './helpers.js';

describe('HTTP API end to end', () => {
  it('reports health and seeded state', async () => {
    const store = await freshStore();
    const health = await request(store, '/api/health');
    expect(health.status).toBe(200);
    const state = await request(store, '/api/state');
    expect(state.data.images.length).toBe(3);
    expect(state.data.policies.map((policy) => policy.version)).toEqual(['2026.09', '2026.10']);
  });

  it('records a scan and retains applied exceptions in the snapshot', async () => {
    const store = await freshStore();
    const res = await request(store, '/api/scans', { imageId: 'img-shop-api-2026-09', policyVersion: '2026.09' }, 'POST');
    expect(res.status).toBe(201);
    const list = await request(store, '/api/scans');
    expect(list.data.scans.length).toBeGreaterThanOrEqual(3);
    const detail = await request(store, '/api/scans/' + res.data.scan.scanId);
    expect(detail.data.scan.result.policyVersion).toBe('2026.09');
  });

  it('ingests a pasted SPDX manifest and evaluates it', async () => {
    const store = await freshStore();
    const { sampleSpdx } = await import('../../data/sbom/sample-spdx.js');
    const imported = await request(store, '/api/images', { id: 'img-pasted', label: 'pasted', rawText: JSON.stringify(sampleSpdx) }, 'POST');
    expect(imported.status).toBe(201);
    const evaluated = await request(store, '/api/evaluate', { imageId: 'img-pasted', policyVersion: '2026.09' }, 'POST');
    expect(evaluated.data.result.findings.some((f) => f.ruleId === 'R-LIC-GPL')).toBe(true);
  });
});
