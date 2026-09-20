import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { parseSbomJson } from '../shared/parse.js';
import { normalizePolicy, evaluate, exceptionCovers, pathKeyOf } from '../shared/policy.js';
import { evaluateScan } from '../shared/scan.js';
import { manifestFingerprint, bindFingerprint } from '../shared/fingerprint.js';
import { createException, applyDecision } from '../shared/exceptions.js';

const manifest = parseSbomJson(readFileSync('data/sbom/payments-1.4.0.cdx.json', 'utf8'));
const fp = manifestFingerprint(manifest, readFileSync('data/sbom/payments-1.4.0.cdx.json', 'utf8'));
const policy = normalizePolicy(JSON.parse(readFileSync('data/policies/policy-v1.json', 'utf8')));
const result = evaluate(manifest, policy);
const findingsByRule = new Map(result.findings.map((f) => [f.ruleId, f]));

const baseCtx = {
  policyId: policy.policyId,
  policyVersion: policy.version,
  bindFingerprint: bindFingerprint(fp),
  evaluatedAt: '2026-09-15T12:00:00+09:00',
};

function makeExc(finding, overrides = {}) {
  return createException({
    componentKey: finding.component,
    ruleId: finding.ruleId,
    policyId: policy.policyId,
    policyVersion: policy.version,
    bindFingerprint: bindFingerprint(fp),
    pathKey: pathKeyOf(finding.paths[0]),
    reason: 'justified test exception',
    requestedBy: 'tester',
    createdAt: '2026-09-01T00:00:00+09:00',
    notBefore: '2026-09-01T00:00:00+09:00',
    notAfter: '2026-09-30T23:59:59+09:00',
    ...overrides,
  });
}

function approved(finding, overrides) {
  const exc = makeExc(finding, overrides);
  return applyDecision(exc, {
    decision: 'approve', actor: 'boss', reason: 'ok',
    at: '2026-09-01T01:00:00+09:00', expectedVersion: 1,
  }).exception;
}

describe('policy evaluation scopes', () => {
  it('flags GPL selected transitively, hash denylist, blocked provenance and depth', () => {
    expect(findingsByRule.has('R-LIC-GPL')).toBe(true);
    expect(findingsByRule.has('R-HASH-DENY')).toBe(true);
    expect(findingsByRule.has('R-PROV-SUPPLIER')).toBe(true);
    expect(findingsByRule.has('R-DEPTH')).toBe(true);
  });

  it('records all supporting paths for multi-path findings', () => {
    const gpl = findingsByRule.get('R-LIC-GPL');
    expect(gpl.pathCount).toBe(2);
    expect(gpl.paths.length).toBe(2);
    const hash = findingsByRule.get('R-HASH-DENY');
    expect(hash.pathCount).toBe(2);
  });

  it('treats a direct vs transitive component differently by depth', () => {
    const gpl = findingsByRule.get('R-LIC-GPL');
    expect(gpl.depth).toBeGreaterThan(1);
  });
});

describe('exception validity window — explicit timezone and boundary semantics', () => {
  const finding = findingsByRule.get('R-HASH-DENY');

  // WINDOW: [2026-09-30T00:00:00+09:00, 2026-09-30T23:59:59+09:00] (inclusive both ends)
  const window = {
    notBefore: '2026-09-30T00:00:00+09:00',
    notAfter: '2026-09-30T23:59:59+09:00',
  };

  it('covers exactly at notBefore (boundary inclusive)', () => {
    const exc = approved(finding, window);
    const ctx = { ...baseCtx, evaluatedAt: '2026-09-30T00:00:00+09:00' };
    expect(exceptionCovers(finding, exc, ctx)).toBe(true);
  });

  it('covers exactly at notAfter (boundary inclusive) — fixed semantics', () => {
    const exc = approved(finding, window);
    const ctx = { ...baseCtx, evaluatedAt: '2026-09-30T23:59:59+09:00' };
    expect(exceptionCovers(finding, exc, ctx)).toBe(true);
  });

  it('does not cover one second after notAfter', () => {
    const exc = approved(finding, window);
    const ctx = { ...baseCtx, evaluatedAt: '2026-10-01T00:00:00+09:00' };
    expect(exceptionCovers(finding, exc, ctx)).toBe(false);
  });

  it('does not cover one second before notBefore', () => {
    const exc = approved(finding, window);
    const ctx = { ...baseCtx, evaluatedAt: '2026-09-29T23:59:59+09:00' };
    expect(exceptionCovers(finding, exc, ctx)).toBe(false);
  });

  it('timezone is honored: same wall time in UTC is a different instant', () => {
    const exc = approved(finding, window);
    // 2026-09-29T14:59:59Z is 2026-09-29T23:59:59+09:00 -> before notBefore
    const ctx = { ...baseCtx, evaluatedAt: '2026-09-29T14:59:59Z' };
    expect(exceptionCovers(finding, exc, ctx)).toBe(false);
    // 2026-09-29T15:00:00Z == 2026-09-30T00:00:00+09:00 -> boundary covered
    const ctx2 = { ...baseCtx, evaluatedAt: '2026-09-29T15:00:00Z' };
    expect(exceptionCovers(finding, exc, ctx2)).toBe(true);
  });
});

describe('exception bindings prevent "slipping through" after change', () => {
  const finding = findingsByRule.get('R-HASH-DENY');

  it('does not cover a different image fingerprint', () => {
    const exc = approved(finding);
    expect(exceptionCovers(finding, exc, { ...baseCtx, bindFingerprint: 'sha256:different' })).toBe(false);
  });

  it('does not cover under a different policy version', () => {
    const exc = approved(finding);
    expect(exceptionCovers(finding, exc, { ...baseCtx, policyVersion: '9.9.9' })).toBe(false);
  });

  it('does not cover a different component coordinate', () => {
    const exc = approved(findingsByRule.get('R-LIC-GPL'));
    expect(exceptionCovers(finding, exc, baseCtx)).toBe(false);
  });

  it('does not cover when the bound introducing path disappears', () => {
    const exc = approved(finding, { pathKey: 'container||x@1>npm||ghost@9' });
    expect(exceptionCovers(finding, exc, baseCtx)).toBe(false);
  });

  it('only approved exceptions can cover', () => {
    const pending = makeExc(finding);
    expect(exceptionCovers(finding, pending, baseCtx)).toBe(false);
  });

  it('scan reports unmatched exception with reason when path/content changes', () => {
    // bound a path that exists in v1.4.0, then scan at an expired instant
    const exc = approved(finding, { notAfter: '2026-09-01T00:00:00+09:00' });
    const scan = evaluateScan({
      manifest, fingerprint: fp, policy, aliasEvidence: [],
      exceptions: [exc], evaluatedAt: '2026-09-15T12:00:00+09:00',
    });
    expect(scan.decision).toBe('deny');
    expect(scan.appliedExceptions.length).toBe(0);
    expect(scan.unmatchedExceptions[0].reason).toMatch(/expired/);
  });
});

describe('exception lifecycle and OCC', () => {
  it('rejects decisions with a stale expected version and returns current state', () => {
    const exc = approved(findingsByRule.get('R-PROV-SUPPLIER')); // v2
    expect(() =>
      applyDecision(exc, {
        decision: 'revoke', actor: 'a', reason: 'r',
        at: '2026-09-16T00:00:00+09:00', expectedVersion: 1,
      }),
    ).toThrowError(/version conflict/);
  });

  it('revocation increments version and is a distinct state, history untouched', () => {
    const exc = approved(findingsByRule.get('R-DEPTH'));
    const next = applyDecision(exc, {
      decision: 'revoke', actor: 'a', reason: 'no longer needed',
      at: '2026-09-16T00:00:00+09:00', expectedVersion: 2,
    });
    expect(next.exception.version).toBe(3);
    expect(next.exception.status).toBe('revoked');
    expect(next.event.type).toBe('exception.revoked');
    expect(next.event.fromVersion).toBe(2);
    expect(next.event.toVersion).toBe(3);
  });

  it('validates required bindings and explicit timezone instants', () => {
    expect(() => createException({ componentKey: 'x', ruleId: 'r' })).toThrow();
    expect(() => makeExc(findingsByRule.get('R-HASH-DENY'), { notBefore: 'not-a-date' })).toThrow();
  });
});
