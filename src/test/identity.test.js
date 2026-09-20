import { describe, it, expect } from 'vitest';
import { parseManifest } from '../core/sbom.js';
import { shopApiV1 } from '../../data/sbom/shop-api-v1.js';
import { sampleSpdx } from '../../data/sbom/sample-spdx.js';
import { canonicalPurl, purlCoordinate } from '../core/purl.js';

describe('component identity', () => {
  const model = parseManifest(shopApiV1);

  it('keeps same-named components in different ecosystems as separate nodes', () => {
    const ids = model.components.map((component) => component.id);
    expect(ids).toContain('pkg:npm/left-pad@1.3.0');
    expect(ids).toContain('pkg:pypi/left-pad@0.1.4');
    expect(purlCoordinate('pkg:npm/left-pad@1.3.0')).toBe('pkg:npm/left-pad');
    expect(purlCoordinate('pkg:pypi/left-pad@0.1.4')).toBe('pkg:pypi/left-pad');
  });

  it('normalizes purl type and name case but preserves the case-sensitive namespace', () => {
    expect(canonicalPurl('pkg:NPM/%40Acme/Utils@2.0.0')).toBe('pkg:npm/%40Acme/utils@2.0.0');
    expect(canonicalPurl('not-a-purl')).toBeNull();
  });

  it('establishes an alias only with explicit evidence AND equal hash', () => {
    expect(model.aliases).toHaveLength(1);
    const alias = model.aliases[0];
    expect(alias.sharedHashes[0].value).toBe('abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234');
    expect([alias.from, alias.to].sort()).toEqual(['pkg:npm/%40acme/utils@2.0.0', 'pkg:npm/acme-utils@2.0.0']);
  });

  it('parses SPDX documents and keeps ecosystems distinct there too', () => {
    const spdx = parseManifest(sampleSpdx);
    expect(spdx.rootIds).toEqual(['pkg:oci/shop-api?repository_url=registry.internal&tag=2026.09-spdx']);
    const edge = spdx.edges.find((edge) => edge.to === 'pkg:npm/left-pad@1.3.0');
    expect(edge).toBeTruthy();
    expect(edge.from).toBe('pkg:npm/express@4.19.2');
  });

  it('rejects unknown manifest formats', () => {
    expect(() => parseManifest({ hello: 'world' })).toThrow(/Unrecognized manifest/);
  });
});
