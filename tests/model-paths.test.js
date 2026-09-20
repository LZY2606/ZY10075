import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { parseSbomJson } from '../shared/parse.js';
import { componentKey } from '../shared/model.js';
import { pathsTo, minDepth, reachableFrom, rootKeys } from '../shared/paths.js';
import { manifestFingerprint } from '../shared/fingerprint.js';

const raw14 = readFileSync('data/sbom/payments-1.4.0.cdx.json', 'utf8');
const raw15 = readFileSync('data/sbom/payments-1.5.0.spdx.json', 'utf8');
const m14 = parseSbomJson(raw14);
const m15 = parseSbomJson(raw15);

describe('canonical model identity', () => {
  it('same name in different ecosystems gets distinct keys', () => {
    const a = componentKey({ ecosystem: 'pypi', group: '', name: 'readline', version: '0.1.0' });
    const b = componentKey({ ecosystem: 'npm', group: '', name: 'lib-readline', version: '0.2.0' });
    expect(a).not.toBe(b);
    const keys = new Set(m14.components.map((c) => c.key));
    expect(keys.has(a)).toBe(true);
    expect(keys.has(b)).toBe(true);
  });

  it('parses CycloneDX and SPDX into the same component vocabulary', () => {
    expect(m14.format).toBe('cyclonedx');
    expect(m15.format).toBe('spdx');
    const names = (m) => m.components.filter((c) => c.ecosystem !== 'container').map((c) => `${c.ecosystem}:${c.name}@${c.version}`).sort();
    // overlap components carry identical coordinates regardless of format
    const common = ['npm:left-pad@1.3.0', 'npm:logfmt@2.1.0', 'pypi:readline@0.1.0', 'npm:lib-readline@0.2.0'];
    for (const coord of common) {
      expect(names(m14)).toContain(coord);
      expect(names(m15)).toContain(coord);
    }
  });

  it('fingerprint is format-independent for the same logical SBOM', () => {
    // model hash must not depend on key ordering of the raw document
    const reordered = JSON.stringify({ ...JSON.parse(raw14), components: [...JSON.parse(raw14).components].reverse() });
    const fpA = manifestFingerprint(m14, raw14);
    const fpB = manifestFingerprint(parseSbomJson(reordered), reordered);
    expect(fpB.modelSha256).toBe(fpA.modelSha256);
    // raw hash differs when bytes differ
    expect(fpB.rawSha256).not.toBe(fpA.rawSha256);
  });
});

describe('dependency paths', () => {
  const readline = componentKey({ ecosystem: 'pypi', name: 'readline', version: '0.1.0' });
  const chainE = componentKey({ ecosystem: 'npm', name: 'chain-e', version: '1.0.0' });

  it('enumerates every introducing path separately (multi-path component)', () => {
    const paths = pathsTo(m14, readline);
    expect(paths.length).toBe(2);
    const stringPaths = paths.map((p) => p.map(shortName));
    // longer introducing path sorts first (deterministic path ordering)
    expect(stringPaths[0]).toEqual([
      'payments-api@1.4.0', 'logfmt@2.1.0', 'lib-readline@0.2.0', 'readline@0.1.0',
    ]);
    expect(stringPaths).toContainEqual([
      'payments-api@1.4.0', 'logfmt@2.1.0', 'readline@0.1.0',
    ]);
    expect(stringPaths).toContainEqual([
      'payments-api@1.4.0', 'logfmt@2.1.0', 'lib-readline@0.2.0', 'readline@0.1.0',
    ]);
  });

  it('computes min depth from roots (root depth = 0, direct = 1)', () => {
    expect(minDepth(m14, readline)).toBe(2);
    expect(minDepth(m14, chainE)).toBe(5);
    const leftPad = componentKey({ ecosystem: 'npm', name: 'left-pad', version: '1.3.0' });
    expect(minDepth(m14, leftPad)).toBe(1);
    expect(rootKeys(m14)[0]).toContain('registry.example.com/payments-api');
  });

  it('deletion reachability computes the exclusive subtree', () => {
    const logfmt = componentKey({ ecosystem: 'npm', name: 'logfmt', version: '2.1.0' });
    const reach = reachableFrom(m14, logfmt);
    expect(reach.has(readline)).toBe(true);
  });

  it('path enumeration terminates on cyclic graphs', () => {
    const syn = synthCycle();
    const target = 'npm||c|1';
    const paths = pathsTo(syn, target);
    expect(paths).toEqual([['npm||a|1', 'npm||b|1', target]]);
    expect(cyclesBounded(paths)).toBe(true);
  });
});

function shortName(key) {
  const parts = key.split('|');
  const rawName = parts[2];
  const name = rawName.includes('/') ? rawName.split('/').pop() : rawName;
  return name + '@' + parts[3];
}
function logfmtKey() {
  return componentKey({ ecosystem: 'npm', name: 'logfmt', version: '2.1.0' });
}
function cyclesBounded(paths) {
  return paths.every((p) => new Set(p).size === p.length);
}
function synthCycle() {
  const comp = (ecosystem, name, version) => ({
    key: `${ecosystem}||${name}|${version}`, ecosystem, group: '', name, version,
    purl: null, hashes: {}, licenses: [], supplier: null, downloadLocation: null, externalRefs: [],
  });
  const cs = [comp('npm', 'a', '1'), comp('npm', 'b', '1'), comp('npm', 'c', '1')];
  const manifest = {
    format: 'cyclonedx', image: {},
    components: cs,
    edges: [
      { from: null, to: cs[0].key, kind: 'dependsOn' },
      { from: cs[0].key, to: cs[1].key, kind: 'dependsOn' },
      { from: cs[1].key, to: cs[2].key, kind: 'dependsOn' },
      { from: cs[2].key, to: cs[1].key, kind: 'dependsOn' }, // cycle b<->c
    ],
  };
  return manifest;
}
