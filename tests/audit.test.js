import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { buildAuditPackage, verifyAuditPackage } from '../shared/audit.js';
import { createZip, readZip } from '../shared/zip.js';
import { canonicalize } from '../shared/canonical.js';
import { sha256Hex } from '../shared/id.js';

const raw14 = readFileSync('data/sbom/payments-1.4.0.cdx.json', 'utf8');
const raw15 = readFileSync('data/sbom/payments-1.5.0.spdx.json', 'utf8');
const policy1 = JSON.parse(readFileSync('data/policies/policy-v1.json', 'utf8'));
const policy2 = JSON.parse(readFileSync('data/policies/policy-v2.json', 'utf8'));

import { parseSbomJson } from '../shared/parse.js';
import { manifestFingerprint } from '../shared/fingerprint.js';
import { normalizePolicy } from '../shared/policy.js';
import { evaluateScan } from '../shared/scan.js';

const m14 = parseSbomJson(raw14);
const m15 = parseSbomJson(raw15);
const fp14 = manifestFingerprint(m14, raw14);
const fp15 = manifestFingerprint(m15, raw15);

function buildBundle({ tamperManifest = false, dropPolicy = false, createdAt = '2026-09-15T12:00:00+09:00' } = {}) {
  const policy = normalizePolicy(policy1);
  const scan = evaluateScan({
    manifest: m14, fingerprint: fp14, policy,
    aliasEvidence: [], exceptions: [], evaluatedAt: '2026-09-02T10:00:00+09:00',
  });
  return {
    createdAt,
    manifests: [{ manifestId: 'sbom_1-4-0', fileName: 'payments-1.4.0.cdx.json', rawText: tamperManifest ? raw14 + '\n' : raw14, fingerprint: fp14 }],
    policies: dropPolicy ? [] : [{ policyId: policy1.policyId, version: policy1.version, document: policy1 }],
    evidence: [],
    exceptions: [],
    events: [],
    scans: [{ scan, manifestId: 'sbom_1-4-0' }],
  };
}

describe('zip writer/reader round trip', () => {
  it('round-trips unicode names and content, sorted deterministically', () => {
    const entries = [
      { path: 'b/file.txt', data: 'hello' },
      { path: 'a/dir/z.txt', data: Buffer.from([0, 1, 2, 255]) },
      { path: 'a/日本語.txt', data: 'data' },
    ];
    const zip = createZip(entries);
    const read = readZip(zip);
    expect(read.map((e) => e.path)).toEqual(['a/dir/z.txt', 'a/日本語.txt', 'b/file.txt']);
    expect(read[1].data.toString('utf8')).toBe('data');
  });
});

describe('audit package verification', () => {
  it('builds and verifies a complete, reproducible package', () => {
    const pkg = buildAuditPackage(buildBundle());
    const result = verifyAuditPackage(pkg.zip, {
      manifests: [{ manifestId: 'sbom_1-4-0', rawText: raw14 }],
      policies: [{ policyId: policy1.policyId, version: policy1.version, document: policy1 }],
      evidence: [], exceptions: [],
    });
    expect(result.ok).toBe(true);
    expect(result.issues).toEqual([]);
    expect(result.scans).toBe(1);
  });

  it('detects a single-byte change to the raw manifest', () => {
    const pkg = buildAuditPackage(buildBundle());
    const result = verifyAuditPackage(pkg.zip, {
      manifests: [{ manifestId: 'sbom_1-4-0', rawText: raw14 + '\n' }],
      policies: [{ policyId: policy1.policyId, version: policy1.version, document: policy1 }],
      evidence: [], exceptions: [],
    });
    expect(result.ok).toBe(false);
    expect(result.issues.join(' ')).toMatch(/not reproducible|rawSha256|raw bytes differ/);
  });

  it('fails when a policy version referenced by a scan is missing', () => {
    const pkg = buildAuditPackage(buildBundle({ dropPolicy: true }));
    const result = verifyAuditPackage(pkg.zip, {
      manifests: [{ manifestId: 'sbom_1-4-0', rawText: raw14 }],
      policies: [], evidence: [], exceptions: [],
    });
    expect(result.ok).toBe(false);
    expect(result.issues.join(' ')).toMatch(/policy.*missing/);
  });

  it('package bytes are independent of creation timestamp apart from audit files', () => {
    // two packages built at different instants: only audit/created-at.txt and
    // digest differ; all evidence-bearing files hash identically
    const a = buildAuditPackage(buildBundle({ createdAt: '2026-09-01T00:00:00+09:00' }));
    const b = buildAuditPackage(buildBundle({ createdAt: '2026-09-02T00:00:00+09:00' }));
    const mapA = new Map(readZip(a.zip).map((e) => [e.path, e.data]));
    const mapB = new Map(readZip(b.zip).map((e) => [e.path, e.data]));
    for (const path of mapA.keys()) {
      if (path === 'audit/created-at.txt' || path === 'audit/digest.txt' || path === 'audit/files.json') continue;
      expect(sha256Hex(mapB.get(path))).toBe(sha256Hex(mapA.get(path)));
    }
  });

  it('file ordering is canonical code-unit order, identical on every platform', () => {
    const pkg = buildAuditPackage(buildBundle());
    const paths = readZip(pkg.zip).map((e) => e.path);
    const sorted = [...paths].sort((x, y) => (x < y ? -1 : x > y ? 1 : 0));
    expect(paths).toEqual(sorted);
  });

  it('recomputes the same decision and findings from saved inputs', () => {
    const pkg = buildAuditPackage(buildBundle());
    const result = verifyAuditPackage(pkg.zip, {
      manifests: [{ manifestId: 'sbom_1-4-0', rawText: raw14 }],
      policies: [{ policyId: policy1.policyId, version: policy1.version, document: policy1 }],
      evidence: [], exceptions: [],
    });
    expect(result.ok).toBe(true);
  });

  it('cross-format bundle carries both manifests and policy versions', () => {
    const policyV1 = normalizePolicy(policy1);
    const policyV2 = normalizePolicy(policy2);
    const s1 = evaluateScan({ manifest: m14, fingerprint: fp14, policy: policyV1, aliasEvidence: [], exceptions: [], evaluatedAt: '2026-09-02T10:00:00+09:00' });
    const s2 = evaluateScan({ manifest: m15, fingerprint: fp15, policy: policyV2, aliasEvidence: [], exceptions: [], evaluatedAt: '2026-09-15T12:00:00+09:00' });
    const bundle = {
      createdAt: '2026-09-15T12:00:00+09:00',
      manifests: [
        { manifestId: 'sbom_1-4-0', fileName: 'payments-1.4.0.cdx.json', rawText: raw14, fingerprint: fp14 },
        { manifestId: 'sbom_1-5-0', fileName: 'payments-1.5.0.spdx.json', rawText: raw15, fingerprint: fp15 },
      ],
      policies: [
        { policyId: policy1.policyId, version: policy1.version, document: policy1 },
        { policyId: policy2.policyId, version: policy2.version, document: policy2 },
      ],
      evidence: [], exceptions: [], events: [],
      scans: [{ scan: s1, manifestId: 'sbom_1-4-0' }, { scan: s2, manifestId: 'sbom_1-5-0' }],
    };
    const pkg = buildAuditPackage(bundle);
    const result = verifyAuditPackage(pkg.zip, {
      manifests: [
        { manifestId: 'sbom_1-4-0', rawText: raw14 },
        { manifestId: 'sbom_1-5-0', rawText: raw15 },
      ],
      policies: [
        { policyId: policy1.policyId, version: policy1.version, document: policy1 },
        { policyId: policy2.policyId, version: policy2.version, document: policy2 },
      ],
      evidence: [], exceptions: [],
    });
    expect(result.ok).toBe(true);
    expect(result.scans).toBe(2);
  });
});
