import { describe, it, expect } from 'vitest';
import { freshStore, findFinding } from './helpers.js';
import { comparePlan } from '../server/service.js';

describe('candidate plans never mutate the original manifest', () => {
  it('removing a node only affects the candidate', async () => {
    const store = await freshStore();
    const imageId = 'img-shop-api-2026-09';
    const before = store.getImage(imageId).rawManifest;
    const plan = await comparePlan(store, {
      imageId,
      at: '2026-09-21T03:00:00Z',
      actions: [{ action: 'remove', id: 'pkg:npm/rogue-source-vendor@1.0.0' }]
    });
    expect(plan.diff.disappeared.map((f) => f.ruleId)).toContain('R-SRC-UNTRUSTED-MIRROR');
    expect(store.getImage(imageId).rawManifest).toBe(before);
    const still = findFinding(plan.baseline, 'R-SRC-UNTRUSTED-MIRROR');
    expect(still).toBeTruthy();
  });

  it('upgrading left-pad removes both findings on it without moving the waiver', async () => {
    const store = await freshStore();
    const plan = await comparePlan(store, {
      imageId: 'img-shop-api-2026-09',
      at: '2026-09-21T03:00:00Z',
      actions: [{ action: 'upgrade', id: 'pkg:npm/left-pad@1.3.0', toVersion: '1.3.1' }]
    });
    const goneRules = plan.diff.disappeared.map((f) => f.componentId + '|' + f.ruleId);
    expect(goneRules).toContain('pkg:npm/left-pad@1.3.0|R-DEN-LEFT-PAD-130');
    expect(goneRules).toContain('pkg:npm/left-pad@1.3.0|R-LIC-GPL');
    // fingerprint-bound waiver is absent from the candidate
    expect(plan.candidate.findings.every((f) => !f.waivedBy)).toBe(true);
    // depth/source findings remain
    expect(plan.diff.remaining.map((f) => f.ruleId)).toContain('R-SRC-UNTRUSTED-MIRROR');
  });

  it('introduces a new finding when upgrading into a blocked license via supplied license', async () => {
    const store = await freshStore();
    const plan = await comparePlan(store, {
      imageId: 'img-shop-api-2026-09',
      at: '2026-09-21T03:00:00Z',
      actions: [{ action: 'upgrade', id: 'pkg:npm/ms@2.1.2', toVersion: '2.1.3', license: 'GPL-3.0-only' }]
    });
    expect(plan.diff.introduced.some((f) => f.ruleId === 'R-LIC-GPL')).toBe(true);
  });
});
