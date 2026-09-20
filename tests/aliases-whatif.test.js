import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { parseSbomJson } from '../shared/parse.js';
import { buildEquivalence, canonicalPurl } from '../shared/aliases.js';
import { applyScenario, evaluateScenario } from '../shared/plan.js';
import { normalizePolicy, evaluate } from '../shared/policy.js';
import { componentKey } from '../shared/model.js';
import { manifestFingerprint } from '../shared/fingerprint.js';
import { pathsTo } from '../shared/paths.js';

const raw = readFileSync('data/sbom/payments-1.4.0.cdx.json', 'utf8');
const manifest = parseSbomJson(raw);
const policy = normalizePolicy(JSON.parse(readFileSync('data/policies/policy-v1.json', 'utf8')));
const fp = manifestFingerprint(manifest, raw);

describe('alias evidence gating', () => {
  it('never merges same names across ecosystems by default', () => {
    const { groups, rejected } = buildEquivalence([manifest], []);
    const flat = groups.flat();
    const pypiReadline = 'pypi||readline|0.1.0';
    const npmReadline = 'npm||lib-readline|0.2.0';
    expect(flat).not.toContain(pypiReadline);
    expect(flat).not.toContain(npmReadline);
    expect(rejected.length).toBe(0);
  });

  it('rejects a single medium evidence claim as insufficient', () => {
    const ev = [{
      kind: 'vcs-locator', confidence: 'medium',
      aKey: 'npm||chain-a|1.0.0', bKey: 'npm||chain-b|1.0.0',
      source: 'x',
    }];
    const { groups, rejected } = buildEquivalence([manifest], ev);
    expect(groups.length).toBe(0);
    expect(rejected[0].reason).toMatch(/insufficient/);
  });

  it('accepts two medium claims but rejects cross-ecosystem claims without hash', () => {
    const ev = [
      { id: 'm1', kind: 'advisory', confidence: 'medium', aKey: 'npm||chain-a|1.0.0', bKey: 'npm||chain-b|1.0.0', source: 's1' },
      { id: 'm2', kind: 'vcs-locator', confidence: 'medium', aKey: 'npm||chain-a|1.0.0', bKey: 'npm||chain-b|1.0.0', source: 's2' },
      { id: 'xeco', kind: 'advisory', confidence: 'high', aKey: 'pypi||readline|0.1.0', bKey: 'npm||lib-readline|0.2.0', source: 's3' },
    ];
    const { groups, rejected } = buildEquivalence([manifest], ev);
    expect(groups.length).toBe(1);
    expect(groups[0]).toContain('npm||chain-a|1.0.0');
    expect(rejected.some((r) => r.id === 'xeco' && /different ecosystems/.test(r.reason))).toBe(true);
  });

  it('implicit same-ecosystem hash equality merges; cross-ecosystem hash needs an explicit record', () => {
    // construct a tiny synthetic case
    const mk = (eco, name, ver, hash) => ({
      format: 'cyclonedx', image: {},
      components: [{
        key: `${eco}||${name}|${ver}`, ecosystem: eco, group: '', name, version: ver,
        purl: `pkg:${eco}/${name}@${ver}`, hashes: hash ? { SHA256: hash } : {},
        licenses: [], supplier: null, downloadLocation: null, externalRefs: [],
      }],
      edges: [],
    });
    const a = mk('npm', 'dup', '1.0.0', 'abab'.repeat(16));
    const b = mk('npm', 'dup', '2.0.0', 'abab'.repeat(16));
    const py = mk('pypi', 'dup', '1.0.0', 'abab'.repeat(16));
    const { groups } = buildEquivalence([a, b], []);
    expect(groups[0].length).toBe(2);
    const cross = buildEquivalence([a, py], []);
    expect(cross.groups.length).toBe(0);
    const crossOk = buildEquivalence([a, py], [{
      kind: 'hash-equality', confidence: 'high', sha256: 'abab'.repeat(16),
      aKey: a.components[0].key, bKey: py.components[0].key, source: 'attestation',
    }]);
    expect(crossOk.groups[0].length).toBe(2);
  });

  it('canonical purl comparison is percent-encoding/order safe', () => {
    expect(canonicalPurl('pkg:NPM/%40scope/pkg@1')).toBe(canonicalPurl('pkg:npm/@scope/pkg@1'));
  });
});

describe('what-if scenarios never mutate the source', () => {
  const readline = componentKey({ ecosystem: 'pypi', name: 'readline', version: '0.1.0' });
  const before = JSON.stringify(manifest);

  it('deleting a node removes only the exclusively reachable subtree', () => {
    // delete logfmt: readline and lib-readline exclusively depend on it
    const logfmt = componentKey({ ecosystem: 'npm', name: 'logfmt', version: '2.1.0' });
    const { candidate, effects } = applyScenario(manifest, [{ action: 'delete-node', componentKey: logfmt }]);
    const keys = candidate.components.map((c) => c.key);
    expect(keys).not.toContain(logfmt);
    expect(keys).not.toContain(readline);
    expect(keys).toContain(componentKey({ ecosystem: 'npm', name: 'left-pad', version: '1.3.0' }));
    expect(effects[0].type).toBe('deleted');
    // original untouched
    expect(JSON.stringify(manifest)).toBe(before);
  });

  it('deleting a shared leaf removes only that leaf', () => {
    const log4j = componentKey({ ecosystem: 'maven', group: 'org.apache.logging.log4j', name: 'log4j-core', version: '2.14.0' });
    const { candidate } = applyScenario(manifest, [{ action: 'delete-node', componentKey: log4j }]);
    const keys = candidate.components.map((c) => c.key);
    expect(keys).not.toContain(log4j);
    // recalled-pkg exclusively under log4j goes too
    expect(keys).not.toContain(componentKey({ ecosystem: 'pypi', name: 'recalled-pkg', version: '0.9.0' }));
  });

  it('upgrading a node changes identity and rewrites edges, original unchanged', () => {
    const log4j = componentKey({ ecosystem: 'maven', group: 'org.apache.logging.log4j', name: 'log4j-core', version: '2.14.0' });
    const { candidate, effects } = applyScenario(manifest, [{
      action: 'upgrade-node', componentKey: log4j,
      to: { version: '2.17.1', hashes: { 'SHA-256': 'd499' + '0'.repeat(60) } },
    }]);
    const upgraded = componentKey({ ecosystem: 'maven', group: 'org.apache.logging.log4j', name: 'log4j-core', version: '2.17.1' });
    expect(candidate.components.some((c) => c.key === upgraded)).toBe(true);
    expect(effects[0]).toMatchObject({ type: 'upgraded', from: log4j, to: upgraded });
    expect(JSON.stringify(manifest)).toBe(before);
  });

  it('scenario comparison reports risks removed vs added; exceptions are not carried', () => {
    const baseScan = {
      scanId: 'base', decision: 'deny', evaluatedAt: '2026-09-15T12:00:00+09:00',
      findings: evaluate(manifest, policy).findings,
      activeFindings: evaluate(manifest, policy).findings.map((f) => f.findingKey),
      appliedExceptions: [],
    };
    // deleting log4j removes its exclusive subtree incl. recalled hash
    const log4j = componentKey({ ecosystem: 'maven', group: 'org.apache.logging.log4j', name: 'log4j-core', version: '2.14.0' });
    const scenario = evaluateScenario(baseScan, manifest, policy, [{
      action: 'delete-node', componentKey: log4j,
    }], { evaluatedAt: '2026-09-15T12:00:00+09:00' });
    const removedRules = scenario.comparison.risksRemoved.map((r) => r.ruleId);
    expect(removedRules).toContain('R-HASH-DENY');
    // GPL readline is reached via logfmt (independent of log4j) and remains
    const still = scenario.comparison.stillPresent.map((r) => r.ruleId);
    expect(still).toContain('R-LIC-GPL');
  });
});

describe('determinism', () => {
  it('path enumeration and evaluation are identical across repeated runs', () => {
    const a = evaluate(manifest, policy);
    const reordered = parseSbomJson(raw);
    reordered.components.reverse();
    const b = evaluate(reordered, policy);
    expect(b.findings.map((f) => f.findingKey)).toEqual(a.findings.map((f) => f.findingKey));
    const readline = componentKey({ ecosystem: 'pypi', name: 'readline', version: '0.1.0' });
    expect(pathsTo(manifest, readline)).toEqual(pathsTo(reordered, readline));
  });
});
