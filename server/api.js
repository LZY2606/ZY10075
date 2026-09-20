// HTTP API: framework-free, deterministic. Every decision instant comes from
// the request body or the fixed demo clock (DEMO_NOW), never Date.now().
import { parseSbomJson } from '../shared/parse.js';
import { manifestFingerprint, bindFingerprint } from '../shared/fingerprint.js';
import { normalizePolicy, pathKeyOf } from '../shared/policy.js';
import { evaluateScan, evidenceHash } from '../shared/scan.js';
import { compareManifests, compareScans } from '../shared/compare.js';
import { applyScenario, evaluateScenario } from '../shared/plan.js';
import { evaluate } from '../shared/policy.js';
import { createException, applyDecision, validateExceptionInput } from '../shared/exceptions.js';
import { buildEquivalence } from '../shared/aliases.js';
import { buildAuditPackage, verifyAuditPackage } from '../shared/audit.js';
import { hashCanonical, sha256Hex } from '../shared/id.js';
import {
  listManifests, getManifest, saveManifest,
  listPolicies, getPolicy,
  getEvidence,
  listExceptions, getException, saveException,
  getEvents, appendEvents,
  listScans, getScan, saveScan,
  savePlan, listPlans, getPlan,
  saveExport, listExports, getExportZip, getExportMeta,
  txn,
} from './store.js';
import { seed } from './seed.js';

// Fixed demo clock (Asia/Tokyo). The whole app treats time as explicit input;
// this constant only supplies the UI default.
export const DEMO_NOW = '2026-09-15T12:00:00+09:00';

async function readBody(req) {
  const chunks = [];
  for await (const c of req) chunks.push(c);
  const raw = Buffer.concat(chunks);
  if (!raw.length) return {};
  const ct = req.headers['content-type'] || '';
  if (ct.includes('application/json')) {
    try {
      return { __json: JSON.parse(raw.toString('utf8')), __raw: raw };
    } catch (err) {
      throw httpError(400, 'invalid JSON body: ' + err.message);
    }
  }
  return { __raw: raw };
}

function httpError(status, message, extra = {}) {
  const err = new Error(message);
  err.status = status;
  err.extra = extra;
  return err;
}

async function loadPolicyRef(policyId, version) {
  const rec = await getPolicy(policyId, version);
  if (!rec) throw httpError(404, `policy not found: ${policyId}@${version}`);
  return rec.normalized || normalizePolicy(rec.document);
}

export async function handle(req, res) {
  const url = new URL(req.url, 'http://localhost');
  const path = url.pathname;
  const method = req.method;

  await seed(false);

  try {
    // ---- meta ----
    if (method === 'GET' && path === '/api/meta') {
      const [manifests, policies, exceptions, scans, events, evidence] = await Promise.all([
        listManifests(), listPolicies(), listExceptions(), listScans(), getEvents(), getEvidence(),
      ]);
      return json(res, 200, {
        demoNow: DEMO_NOW,
        evidenceVersion: evidenceHash(evidence),
        manifests: manifests.map(manifestSummary),
        policies: policies.map((p) => ({ policyId: p.policyId, version: p.version, addedAt: p.addedAt })),
        exceptions: exceptions.map((e) => ({ ...e })),
        scans: scans.map(scanSummary),
        eventCount: events.length,
      });
    }

    // ---- manifests ----
    if (method === 'GET' && path === '/api/manifests') {
      const manifests = await listManifests();
      return json(res, 200, { manifests: manifests.map(manifestSummary) });
    }
    if (method === 'GET' && path.startsWith('/api/manifests/')) {
      const id = decodeURIComponent(path.split('/').pop());
      const rec = await getManifest(id);
      if (!rec) throw httpError(404, 'manifest not found');
      const parsed = parseSbomJson(rec.rawText);
      return json(res, 200, { ...manifestSummary(rec), componentCount: parsed.components.length, edgeCount: parsed.edges.length, components: parsed.components, edges: parsed.edges, image: parsed.image });
    }
    if (method === 'POST' && path === '/api/manifests') {
      const body = (await readBody(req)).__json;
      const rawText = typeof body.content === 'string' ? body.content : null;
      if (!rawText) throw httpError(400, 'content must be the raw SBOM JSON text');
      let parsed;
      try {
        parsed = parseSbomJson(rawText);
      } catch (err) {
        throw httpError(400, err.message);
      }
      const fp = manifestFingerprint(parsed, rawText);
      const manifestId = 'sbom_' + fp.modelSha256.slice(0, 10);
      const existing = await getManifest(manifestId);
      if (existing) return json(res, 200, { ...manifestSummary(existing), duplicated: true });
      const rec = {
        manifestId,
        fileName: body.fileName || `${manifestId}.json`,
        rawText,
        format: parsed.format,
        fingerprint: fp,
        image: parsed.image,
        uploadedAt: requireInstant(body.uploadedAt, 'uploadedAt'),
      };
      await saveManifest(rec);
      return json(res, 201, manifestSummary(rec));
    }

    // ---- policies ----
    if (method === 'GET' && path === '/api/policies') {
      const policies = await listPolicies();
      return json(res, 200, { policies: policies.map((p) => ({ policyId: p.policyId, version: p.version, addedAt: p.addedAt, rules: (p.normalized || normalizePolicy(p.document)).rules })) });
    }

    // ---- evidence / aliases ----
    if (method === 'GET' && path === '/api/evidence') {
      const records = await getEvidence();
      return json(res, 200, { evidence: records, evidenceVersion: evidenceHash(records) });
    }

    // ---- scans ----
    if (method === 'GET' && path === '/api/scans') {
      const scans = await listScans();
      return json(res, 200, { scans: scans.map(scanSummary) });
    }
    if (method === 'GET' && path.startsWith('/api/scans/')) {
      const id = decodeURIComponent(path.split('/').pop());
      const rec = await getScan(id);
      if (!rec) throw httpError(404, 'scan not found');
      return json(res, 200, rec);
    }
    if (method === 'POST' && path === '/api/scans') {
      const body = (await readBody(req)).__json;
      const evaluatedAt = requireInstant(body.evaluatedAt || DEMO_NOW, 'evaluatedAt');
      const manifestRec = await requireManifest(body.manifestId);
      const policy = await loadPolicyRef(body.policyId, body.policyVersion);
      const evidence = await getEvidence();
      const exceptions = await listExceptions();
      const parsed = parseSbomJson(manifestRec.rawText);
      const scan = evaluateScan({
        manifest: parsed,
        fingerprint: manifestRec.fingerprint,
        policy,
        aliasEvidence: evidence,
        exceptions,
        evaluatedAt,
      });
      const record = {
        scan,
        manifestId: manifestRec.manifestId,
        refs: { policyId: policy.policyId, policyVersion: policy.version, evidenceVersion: evidenceHash(evidence) },
        savedAt: evaluatedAt,
      };
      await saveScan(record);
      return json(res, 201, record);
    }

    // ---- exceptions ----
    if (method === 'GET' && path === '/api/exceptions') {
      const exceptions = await listExceptions();
      return json(res, 200, { exceptions });
    }
    if (method === 'GET' && path.startsWith('/api/exceptions/')) {
      const id = decodeURIComponent(path.split('/')[3]);
      const rec = await getException(id);
      if (!rec) throw httpError(404, 'exception not found');
      return json(res, 200, rec);
    }
    if (method === 'POST' && path === '/api/exceptions') {
      const body = (await readBody(req)).__json;
      const createdAt = requireInstant(body.createdAt || DEMO_NOW, 'createdAt');
      const manifestRec = await requireManifest(body.manifestId);
      const policy = await loadPolicyRef(body.policyId, body.policyVersion);
      const parsed = parseSbomJson(manifestRec.rawText);
      if (!parsed.components.some((c) => c.key === body.componentKey)) {
        throw httpError(400, 'componentKey is not present in the bound manifest');
      }
      if (!policy.rules.some((r) => r.id === body.ruleId)) throw httpError(400, 'unknown ruleId');
      const input = {
        componentKey: body.componentKey,
        ruleId: body.ruleId,
        policyId: policy.policyId,
        policyVersion: policy.version,
        bindFingerprint: bindFingerprint(manifestRec.fingerprint),
        pathKey: body.pathKey || null,
        license: body.license || null,
        digest: body.digest || null,
        notBefore: requireInstant(body.notBefore, 'notBefore'),
        notAfter: requireInstant(body.notAfter, 'notAfter'),
        reason: String(body.reason || ''),
        requestedBy: String(body.requestedBy || ''),
        createdAt,
      };
      const errors = validateExceptionInput(input);
      if (errors.length) throw httpError(400, errors.join('; '));
      const exception = createException(input);
      if (await getException(exception.exceptionId)) throw httpError(409, 'identical exception request already exists');
      const event = {
        type: 'exception.requested',
        at: createdAt,
        actor: exception.requestedBy,
        exceptionId: exception.exceptionId,
        fromVersion: 0,
        toVersion: 1,
        fromStatus: null,
        toStatus: 'pending',
        reason: exception.reason,
      };
      // request writes exception + event as one batch
      await txn([{ op: 'put', dir: 'exceptions', name: `${exception.exceptionId}.json`, value: exception }]);
      await appendEvents([withEventId(event)]);
      return json(res, 201, exception);
    }

    // Single decision and batch decisions share one atomic validation+commit.
    if ((method === 'POST' && path === '/api/exceptions/decision') ||
        (method === 'POST' && path === '/api/exceptions/batch')) {
      const body = (await readBody(req)).__json;
      const single = path.endsWith('/decision');
      const decisions = single ? [body] : body.decisions;
      if (!Array.isArray(decisions) || !decisions.length) throw httpError(400, 'decisions[] required');
      const at = requireInstant(body.at || DEMO_NOW, 'at');
      const actor = String(body.actor || '').trim();
      if (!actor) throw httpError(400, 'actor required');
      if (single && !String(body.reason || '').trim()) throw httpError(400, 'reason required');

      // Phase 1: validate everything against current snapshots. No writes.
      const current = await listExceptions();
      const byId = new Map(current.map((e) => [e.exceptionId, e]));
      const planned = [];
      const conflicts = [];
      for (const d of decisions) {
        const exc = byId.get(d.exceptionId);
        if (!exc) {
          conflicts.push({ exceptionId: d.exceptionId, error: 'not-found' });
          continue;
        }
        try {
          const result = applyDecision(exc, {
            decision: d.decision,
            actor,
            reason: String(d.reason || ''),
            at,
            expectedVersion: d.expectedVersion,
          });
          planned.push(result);
        } catch (err) {
          if (err.code === 'VERSION_CONFLICT') {
            conflicts.push({ exceptionId: d.exceptionId, error: 'version-conflict', expected: d.expectedVersion, actual: exc.version, current: err.conflict.current });
          } else {
            conflicts.push({ exceptionId: d.exceptionId, error: err.message });
          }
        }
      }

      // ANY conflict fails the WHOLE batch: no visible partial results.
      if (conflicts.length) {
        return json(res, 409, {
          error: single ? 'decision failed' : 'batch failed: one or more exceptions changed',
          atomic: true,
          applied: 0,
          conflicts,
        });
      }

      // Phase 2: commit all snapshots + events in one batch.
      const writes = planned.map(({ exception }) => ({
        op: 'put', dir: 'exceptions', name: `${exception.exceptionId}.json`, value: exception,
      }));
      await txn(writes);
      await appendEvents(planned.map(({ event }) => withEventId({ ...event, actor })));

      return json(res, 200, {
        applied: planned.length,
        results: planned.map(({ exception, event }) => ({ exceptionId: exception.exceptionId, version: exception.version, status: exception.status, event })),
      });
    }

    // ---- compare manifests ----
    if (method === 'POST' && path === '/api/compare/manifests') {
      const body = (await readBody(req)).__json;
      const a = await requireManifest(body.baseManifestId);
      const b = await requireManifest(body.candidateManifestId);
      const ma = parseSbomJson(a.rawText);
      const mb = parseSbomJson(b.rawText);
      const diff = compareManifests(ma, mb, {});
      return json(res, 200, {
        base: { manifestId: a.manifestId, fingerprint: a.fingerprint, image: a.image },
        candidate: { manifestId: b.manifestId, fingerprint: b.fingerprint, image: b.image },
        ...diff,
      });
    }
    if (method === 'POST' && path === '/api/compare/scans') {
      const body = (await readBody(req)).__json;
      const a = await getScan(body.baseScanId);
      const b = await getScan(body.candidateScanId);
      if (!a || !b) throw httpError(404, 'scan not found');
      return json(res, 200, compareScans(a.scan, b.scan));
    }

    // ---- what-if plans ----
    if (method === 'GET' && path === '/api/plans') {
      return json(res, 200, { plans: await listPlans() });
    }
    if (method === 'GET' && path.startsWith('/api/plans/')) {
      const id = decodeURIComponent(path.split('/').pop());
      const rec = await getPlan(id);
      if (!rec) throw httpError(404, 'plan not found');
      return json(res, 200, rec);
    }
    if (method === 'POST' && path === '/api/plans') {
      const body = (await readBody(req)).__json;
      const baseScanRec = await getScan(body.baseScanId);
      if (!baseScanRec) throw httpError(404, 'base scan not found');
      const manifestRec = await requireManifest(body.manifestId || baseScanRec.manifestId);
      const policy = await loadPolicyRef(baseScanRec.refs.policyId, baseScanRec.refs.policyVersion);
      const parsed = parseSbomJson(manifestRec.rawText);
      const evaluatedAt = requireInstant(body.evaluatedAt || baseScanRec.scan.evaluatedAt, 'evaluatedAt');
      const actions = body.actions || [];
      validateActions(actions);
      const result = applyScenarioCustom(baseScanRec.scan, parsed, policy, actions, { evaluatedAt, exceptions: await listExceptions() });
      const record = {
        planId: result.planId,
        baseScanId: baseScanRec.scan.scanId,
        manifestId: manifestRec.manifestId,
        actions,
        evaluatedAt,
        createdAt: requireInstant(body.createdAt || DEMO_NOW, 'createdAt'),
        effects: result.effects,
        candidateFingerprint: manifestFingerprint(result.candidate, JSON.stringify(result.candidate)),
        candidateComponentCount: result.candidateComponentCount,
        comparison: result.comparison,
        candidateScan: {
          decision: result.candidateScan.decision,
          activeFindings: result.candidateScan.activeFindings,
          findings: result.candidateScan.findings.map((f) => ({ findingKey: f.findingKey, ruleId: f.ruleId, coordinate: f.coordinate, depth: f.depth, reason: f.reason, paths: f.paths, pathCount: f.pathCount })),
        },
      };
      await savePlan(record);
      return json(res, 201, record);
    }

    // ---- supporting paths for a component within a scan ----
    if (method === 'POST' && path === '/api/explain/paths') {
      const body = (await readBody(req)).__json;
      const scanRec = await getScan(body.scanId);
      if (!scanRec) throw httpError(404, 'scan not found');
      const manifestRec = await requireManifest(scanRec.manifestId);
      const parsed = parseSbomJson(manifestRec.rawText);
      const { pathsTo, pathReport } = await import('../shared/paths.js');
      const componentKey = body.componentKey;
      const findings = scanRec.scan.findings.filter((f) => f.component === componentKey);
      return json(res, 200, {
        ...pathReport(parsed, componentKey),
        findings: findings.map((f) => ({
          ruleId: f.ruleId,
          findingKey: f.findingKey,
          reason: f.reason,
          active: scanRec.scan.activeFindings.includes(f.findingKey),
          paths: f.paths,
          pathCount: f.pathCount,
        })),
      });
    }

    // ---- events ----
    if (method === 'GET' && path === '/api/events') {
      return json(res, 200, { events: await getEvents() });
    }

    // ---- audit export ----
    if (method === 'POST' && path === '/api/audit/export') {
      const body = (await readBody(req)).__json;
      const createdAt = requireInstant(body.createdAt || DEMO_NOW, 'createdAt');
      const manifests = await listManifests();
      const policies = await listPolicies();
      const exceptions = await listExceptions();
      const events = await getEvents();
      const evidence = await getEvidence();
      const scans = await listScans();
      const bundle = {
        manifests: manifests.map((m) => ({ manifestId: m.manifestId, fileName: m.fileName, rawText: m.rawText, fingerprint: m.fingerprint })),
        policies: policies.map((p) => ({ policyId: p.policyId, version: p.version, document: p.document })),
        evidence,
        exceptions,
        events,
        scans: scans.map((s) => ({ scan: s.scan, manifestId: s.manifestId })),
        createdAt,
      };
      const pkg = buildAuditPackage(bundle);
      const exportId = 'aud_' + sha256Hex(createdAt + pkg.digest).slice(0, 16);
      const meta = {
        exportId,
        createdAt,
        digest: pkg.digest,
        fileCount: pkg.fileCount,
        scanCount: scans.length,
        manifestCount: manifests.length,
        policyCount: policies.length,
        exceptionCount: exceptions.length,
        eventCount: events.length,
        bytes: pkg.zip.length,
      };
      await saveExport(meta, pkg.zip);
      return json(res, 201, meta);
    }
    if (method === 'GET' && path === '/api/audit/exports') {
      return json(res, 200, { exports: await listExports() });
    }
    if (method === 'GET' && /^\/api\/audit\/exports\/[^/]+\/download$/.test(path)) {
      const id = path.split('/')[4];
      const zip = await getExportZip(id).catch(() => null);
      if (!zip) throw httpError(404, 'export not found');
      res.writeHead(200, {
        'content-type': 'application/zip',
        'content-disposition': `attachment; filename="${id}.zip"`,
        'content-length': zip.length,
      });
      return res.end(zip);
    }
    if (method === 'POST' && path === '/api/audit/verify') {
      const body = await readBody(req);
      const raw = body.__raw;
      if (!raw || !raw.length) throw httpError(400, 'zip body required');
      const manifests = await listManifests();
      const policies = await listPolicies();
      const evidence = await getEvidence();
      const exceptions = await listExceptions();
      const result = verifyAuditPackage(raw, {
        manifests: manifests.map((m) => ({ manifestId: m.manifestId, rawText: m.rawText })),
        policies: policies.map((p) => ({ policyId: p.policyId, version: p.version, document: p.document })),
        evidence,
        exceptions,
      });
      return json(res, result.ok ? 200 : 422, result);
    }

    return json(res, 404, { error: `not found: ${method} ${path}` });
  } catch (err) {
    const status = err.status || 500;
    if (status >= 500) console.error(err);
    return json(res, status, { error: err.message, ...(err.extra || {}) });
  }
}

// ---- helpers ----
function json(res, status, value) {
  const body = JSON.stringify(value, null, 2);
  res.writeHead(status, { 'content-type': 'application/json; charset=utf-8', 'content-length': Buffer.byteLength(body) });
  res.end(body);
}

// Accept only explicit-instant strings: date-time with either Z or a numeric
// UTC offset. A bare date or "YYYY-MM-DD HH:mm:ss" (local implied) is rejected
// so the timezone is always an explicit, recorded fact.
const INSTANT_RE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}(:\d{2})?(\.\d+)?(Z|[+-]\d{2}:\d{2})$/;

function requireInstant(value, field) {
  if (typeof value !== 'string' || !INSTANT_RE.test(value) || Number.isNaN(Date.parse(value))) {
    throw httpError(400, field + ' must be an ISO-8601 instant with explicit timezone/offset (Z or +/-HH:MM)');
  }
  return value;
}

async function requireManifest(id) {
  const rec = await getManifest(id);
  if (!rec) throw httpError(404, `manifest not found: ${id}`);
  return rec;
}

function manifestSummary(m) {
  return {
    manifestId: m.manifestId,
    fileName: m.fileName,
    format: m.format,
    uploadedAt: m.uploadedAt,
    image: m.image,
    fingerprint: m.fingerprint,
    bindFingerprint: m.fingerprint ? bindFingerprint(m.fingerprint) : null,
  };
}

function scanSummary(s) {
  return {
    scanId: s.scan.scanId,
    manifestId: s.manifestId,
    decision: s.scan.decision,
    evaluatedAt: s.scan.evaluatedAt,
    policy: s.scan.policy,
    activeFindings: s.scan.activeFindings.length,
    totalFindings: s.scan.findings.length,
    appliedExceptions: s.scan.appliedExceptions.map((a) => a.exceptionId),
  };
}

function withEventId(event) {
  return { eventId: 'evt_' + hashCanonical({ ...event, nonce: event.at + event.exceptionId + event.toVersion }).slice(0, 16), ...event };
}

function validateActions(actions) {
  for (const a of actions) {
    if (!['delete-node', 'upgrade-node'].includes(a.action)) throw httpError(400, `unknown action: ${a.action}`);
    if (!a.componentKey) throw httpError(400, 'componentKey required');
    if (a.action === 'upgrade-node' && !a.to?.version) throw httpError(400, 'upgrade-node requires to.version');
  }
}

// Evaluate candidate scenario using the same primitives, WITHOUT carrying
// exceptions forward (a candidate must stand on its own; stale exceptions can
// never silently mask new risks).
function applyScenarioCustom(baseScan, manifest, policy, actions, { evaluatedAt, exceptions }) {
  return evaluateScenario(baseScan, manifest, policy, actions, { evaluatedAt, carryExceptions: [] });
}
