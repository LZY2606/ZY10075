import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { server } from '../server/main.js';
import { seed } from '../server/seed.js';

let base;

beforeAll(async () => {
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const port = server.address().port;
  base = `http://127.0.0.1:${port}`;
  await seed(true);
});

afterAll(() => new Promise((r) => server.close(r)));

async function api(method, path, body, raw = false) {
  const headers = body !== undefined
    ? { 'content-type': raw ? 'application/zip' : 'application/json' }
    : undefined;
  const res = await fetch(base + path, {
    method,
    headers,
    body: body !== undefined ? (raw ? body : JSON.stringify(body)) : undefined,
  });
  const text = await res.text();
  let json;
  try { json = JSON.parse(text); } catch { json = text; }
  return { status: res.status, json, headers: res.headers, text };
}

describe('end-to-end HTTP API', () => {
  it('lists seeded manifests, policies, exceptions and historical scans', async () => {
    const { status, json } = await api('GET', '/api/meta');
    expect(status).toBe(200);
    expect(json.manifests.length).toBe(2);
    expect(json.policies.map((p) => p.version).sort()).toEqual(['1.0.0', '2.0.0']);
    expect(json.exceptions.length).toBe(4);
    expect(json.scans.length).toBeGreaterThanOrEqual(2);
    // historical scan shows the applied exception used at that time
    const historical = json.scans.find((s) => s.appliedExceptions.length === 1);
    expect(historical).toBeTruthy();
  });

  it('rejects naive timezones: evaluatedAt must carry explicit offset', async () => {
    const r = await api('POST', '/api/scans', {
      manifestId: 'sbom_1-4-0', policyId: 'acme-supply-chain',
      policyVersion: '1.0.0', evaluatedAt: '2026-09-15 12:00:00',
    });
    expect(r.status).toBe(400);
    expect(r.json.error).toMatch(/timezone/);
  });

  it('is idempotent: same inputs produce the same scanId and decision', async () => {
    const payload = { manifestId: 'sbom_1-4-0', policyId: 'acme-supply-chain', policyVersion: '1.0.0', evaluatedAt: '2026-09-15T12:00:00+09:00' };
    const a = await api('POST', '/api/scans', payload);
    const b = await api('POST', '/api/scans', payload);
    expect(a.status).toBe(201);
    expect(b.json.scan.scanId).toBe(a.json.scan.scanId);
    expect(b.json.scan.decision).toBe(a.json.scan.decision);
  });

  it('expands a denial into every supporting path and marks multi-path components', async () => {
    const scan = (await api('POST', '/api/scans', {
      manifestId: 'sbom_1-4-0', policyId: 'acme-supply-chain', policyVersion: '1.0.0',
      evaluatedAt: '2026-09-15T12:00:00+09:00',
    })).json;
    const gplFinding = scan.scan.findings.find((f) => f.ruleId === 'R-LIC-GPL');
    const r = await api('POST', '/api/explain/paths', { scanId: scan.scan.scanId, componentKey: gplFinding.component });
    expect(r.status).toBe(200);
    expect(r.json.pathCount).toBe(2);
    expect(r.json.paths.length).toBe(2);
    expect(r.json.findings[0].paths.length).toBe(2);
  });

  it('batch approval is atomic: one stale version fails the whole batch with diffs and no partial writes', async () => {
    const meta = (await api('GET', '/api/meta')).json;
    const pending = meta.exceptions.filter((e) => e.status === 'pending');
    expect(pending.length).toBe(2);
    const versionsBefore = Object.fromEntries(pending.map((e) => [e.exceptionId, e.version]));

    const r = await api('POST', '/api/exceptions/batch', {
      actor: 'security-bob',
      at: '2026-09-15T12:00:00+09:00',
      decisions: [
        { exceptionId: pending[0].exceptionId, decision: 'approve', expectedVersion: 1, reason: 'batch ok a' },
        { exceptionId: pending[1].exceptionId, decision: 'approve', expectedVersion: 99, reason: 'batch ok b' },
      ],
    });
    expect(r.status).toBe(409);
    expect(r.json.applied).toBe(0);
    expect(r.json.conflicts.length).toBe(1);
    expect(r.json.conflicts[0].error).toBe('version-conflict');
    expect(r.json.conflicts[0].current.version).toBe(versionsBefore[pending[1].exceptionId]);

    // no visible partial results: both still pending at original versions
    const after = (await api('GET', '/api/meta')).json.exceptions;
    for (const e of pending) {
      const now = after.find((x) => x.exceptionId === e.exceptionId);
      expect(now.status).toBe('pending');
      expect(now.version).toBe(versionsBefore[e.exceptionId]);
    }
  });

  it('batch succeeds atomically when all expected versions match, then events recorded', async () => {
    const meta = (await api('GET', '/api/meta')).json;
    const pending = meta.exceptions.filter((e) => e.status === 'pending');
    const r = await api('POST', '/api/exceptions/batch', {
      actor: 'security-bob',
      at: '2026-09-15T12:05:00+09:00',
      decisions: pending.map((e) => ({ exceptionId: e.exceptionId, decision: 'approve', expectedVersion: 1, reason: 'batch accept' })),
    });
    expect(r.status).toBe(200);
    expect(r.json.applied).toBe(2);
    const events = (await api('GET', '/api/events')).json.events;
    const approvals = events.filter((e) => e.type === 'exception.approved');
    expect(approvals.length).toBeGreaterThanOrEqual(4); // seed approvals + batch
  });

  it('creates a what-if plan and compares risks removed without touching the manifest', async () => {
    const scan = (await api('POST', '/api/scans', {
      manifestId: 'sbom_1-4-0', policyId: 'acme-supply-chain', policyVersion: '1.0.0',
      evaluatedAt: '2026-09-15T13:00:00+09:00',
    })).json;
    const plan = await api('POST', '/api/plans', {
      baseScanId: scan.scan.scanId,
      actions: [{ action: 'delete-node', componentKey: 'npm||dark-mirror-lib|1.0.0' }],
      evaluatedAt: '2026-09-15T13:00:00+09:00',
    });
    expect(plan.status).toBe(201);
    expect(plan.json.comparison.risksRemoved.map((r) => r.ruleId)).toContain('R-PROV-SUPPLIER');
    // stored original manifest still contains the node
    const manifest = (await api('GET', '/api/manifests/sbom_1-4-0')).json;
    expect(manifest.components.some((c) => c.key === 'npm||dark-mirror-lib|1.0.0')).toBe(true);
  });

  it('compares two image versions (manifest diff + scan risk delta)', async () => {
    const diff = await api('POST', '/api/compare/manifests', {
      baseManifestId: 'sbom_1-4-0', candidateManifestId: 'sbom_1-5-0',
    });
    expect(diff.status).toBe(200);
    expect(diff.json.added).toContain('npm||pdf-tool|3.0.0');
    expect(diff.json.removed.some((k) => k.includes('recalled-pkg'))).toBe(true);

    const s14 = await api('POST', '/api/scans', { manifestId: 'sbom_1-4-0', policyId: 'acme-supply-chain', policyVersion: '1.0.0', evaluatedAt: '2026-09-15T12:00:00+09:00' });
    const s15 = await api('POST', '/api/scans', { manifestId: 'sbom_1-5-0', policyId: 'acme-supply-chain', policyVersion: '2.0.0', evaluatedAt: '2026-09-15T12:00:00+09:00' });
    const cmp = await api('POST', '/api/compare/scans', { baseScanId: s14.json.scan.scanId, candidateScanId: s15.json.scan.scanId });
    expect(cmp.json.risksAdded.map((r) => r.component)).toContain('npm||pdf-tool|3.0.0');
  });

  it('exports an audit package and verifies it round trip', async () => {
    const created = await api('POST', '/api/audit/export', { createdAt: '2026-09-15T18:00:00+09:00' });
    expect(created.status).toBe(201);
    const id = created.json.exportId;
    const dl = await fetch(`${base}/api/audit/exports/${id}/download`);
    expect(dl.status).toBe(200);
    const buf = Buffer.from(await dl.arrayBuffer());
    const verified = await api('POST', '/api/audit/verify', buf, true);
    expect(verified.status).toBe(200);
    expect(verified.json.ok).toBe(true);
    expect(verified.json.fileCount).toBeGreaterThan(0);
    expect(verified.json.digest).toBe(created.json.digest);
  });

  it('uploads a new SBOM and fingerprints it', async () => {
    const fs = await import('node:fs');
    const content = fs.readFileSync('data/sbom/payments-1.5.0.spdx.json', 'utf8');
    const r = await api('POST', '/api/manifests', { content, fileName: 'spdx.json', uploadedAt: '2026-09-15T12:00:00+09:00' });
    // identity derived from content hash; re-upload of identical bytes is deduplicated
    expect([200, 201]).toContain(r.status);
    const again = await api('POST', '/api/manifests', { content, fileName: 'spdx.json', uploadedAt: '2026-09-15T12:00:00+09:00' });
    expect(again.json.manifestId).toBe(r.json.manifestId);
    expect(again.status).toBe(200);
    expect(again.json.duplicated).toBe(true);
    expect(again.json.fingerprint.modelSha256).toBe(r.json.fingerprint.modelSha256);
  });
});
