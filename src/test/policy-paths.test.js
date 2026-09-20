import { describe, it, expect } from 'vitest';
import { freshStore, findFinding } from './helpers.js';
import { evaluateImage } from '../server/service.js';
import { allPaths, buildGraph } from '../core/graph.js';

describe('policy evaluation and supporting paths', () => {
  it('rejects the v1 image with multiple open findings', async () => {
    const store = await freshStore();
    const data = await evaluateImage(store, { imageId: 'img-shop-api-2026-09', policyVersion: '2026.09', at: '2026-09-21T03:00:00Z' });
    expect(data.result.conclusion).toBe('REJECT');
    const ids = data.result.findings.map((f) => f.ruleId + ':' + f.componentId).sort();
    expect(ids).toContain('R-DEN-LEFT-PAD-130:pkg:npm/left-pad@1.3.0');
    expect(ids).toContain('R-LIC-GPL:pkg:npm/left-pad@1.3.0');
    expect(ids).toContain('R-SRC-UNTRUSTED-MIRROR:pkg:npm/rogue-source-vendor@1.0.0');
    expect(ids).toContain('R-DEPTH-3:pkg:npm/ms@2.1.2');
  });

  it('expands ALL supporting paths and distinguishes multi-path introduction', async () => {
    const store = await freshStore();
    const data = await evaluateImage(store, { imageId: 'img-shop-api-2026-09', at: '2026-09-21T03:00:00Z' });
    const ms = findFinding(data.result, 'R-DEPTH-3', 'pkg:npm/ms@2.1.2');
    expect(ms.paths).toHaveLength(2);
    const joined = ms.paths.map((path) => path.join(' > '));
    expect(joined[0]).toContain('body-parser@1.20.2');
    expect(joined[1]).toContain('send@0.18.0');
    for (const path of ms.paths) expect(path.at(-1)).toBe('pkg:npm/ms@2.1.2');
  });

  it('reports depth 4 for ms and direct scope for express', async () => {
    const store = await freshStore();
    const image = store.getImage('img-shop-api-2026-09');
    const graph = buildGraph(image.model.components, image.model.edges, image.model.rootIds);
    const paths = allPaths(graph, 'pkg:npm/ms@2.1.2');
    expect(Math.min(...paths.map((path) => path.length - 1))).toBe(4);
    const expressPaths = allPaths(graph, 'pkg:npm/express@4.19.2');
    expect(expressPaths[0].length - 1).toBe(1);
  });

  it('the patched v2 image is ALLOW under policy v1', async () => {
    const store = await freshStore();
    const data = await evaluateImage(store, { imageId: 'img-shop-api-2026-10', policyVersion: '2026.09', at: '2026-09-21T03:00:00Z' });
    expect(data.result.conclusion).toBe('ALLOW');
  });

  it('does not fire depth rule on direct/root components', async () => {
    const store = await freshStore();
    const data = await evaluateImage(store, { imageId: 'img-shop-api-2026-09', at: '2026-09-21T03:00:00Z' });
    expect(data.result.findings.some((f) => f.componentId.startsWith('pkg:oci/'))).toBe(false);
  });
});
