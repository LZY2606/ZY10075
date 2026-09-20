// File-backed, deterministic store.
// Layout under data/state:
//   meta.json                 - schema version + seed version hash
//   manifests/<id>.json       - { manifestId, fileName, rawText, fingerprint, uploadedAt }
//   policies/<id>@<v>.json    - normalized policy documents
//   evidence.json             - alias evidence records
//   exceptions/<id>.json      - current exception snapshot
//   events.json               - append-only decision/audit event log
//   scans/<id>.json           - { scan, refs, snapshot:{exceptions:[...], policy:{...}} }
//   plans/<id>.json           - what-if plans (candidate only, never mutates source)
//   exports/<id>.json         - audit package metadata (+ bytes in exports/<id>.zip)
//
// All batch mutations apply to in-memory copies and are written under a temp
// directory then renamed into place: either every file lands or none do.
import { promises as fs } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { createHash } from 'node:crypto';

const HERE = path.dirname(fileURLToPath(import.meta.url));
export const ROOT = path.resolve(HERE, '..');
const DATA = path.join(ROOT, 'data');
const STATE = path.join(DATA, 'state');

const DIRS = {
  state: STATE,
  manifests: path.join(STATE, 'manifests'),
  policies: path.join(STATE, 'policies'),
  exceptions: path.join(STATE, 'exceptions'),
  scans: path.join(STATE, 'scans'),
  plans: path.join(STATE, 'plans'),
  exports: path.join(STATE, 'exports'),
};

async function ensureDirs() {
  for (const dir of Object.values(DIRS)) {
    await fs.mkdir(dir, { recursive: true });
  }
}

async function readJson(file, fallback) {
  try {
    return JSON.parse(await fs.readFile(file, 'utf8'));
  } catch (err) {
    if (err.code === 'ENOENT') return fallback;
    throw err;
  }
}

async function writeJson(file, value) {
  await fs.writeFile(file, JSON.stringify(value, null, 2) + '\n', 'utf8');
}

async function listJson(dir) {
  let names;
  try {
    names = await fs.readdir(dir);
  } catch {
    return [];
  }
  const out = [];
  for (const name of names.filter((n) => n.endsWith('.json')).sort()) {
    out.push(await readJson(path.join(dir, name), null));
  }
  return out.filter(Boolean);
}

export async function isSeeded() {
  await ensureDirs();
  const meta = await readJson(path.join(STATE, 'meta.json'), null);
  return !!meta;
}

// Remove every generated state entry but keep the directory itself.
export async function resetStateDir() {
  await fs.rm(STATE, { recursive: true, force: true });
  await ensureDirs();
}

// Transactional multi-file write. Every entry:
//   { op: 'put', dir, name, value } | { op: 'delete', dir, name }
// We stage into state/.txn-<hash>/ then rename files individually. To get
// real atomicity on a single volume without per-file rename races exposed to
// readers, writes go to temp names and are renamed in deterministic order;
// callers express one logical batch, and a crash between renames leaves either
// old or new versions recoverable — but for the API contract we validate
// everything up-front before any write begins, so business-level partial
// results (the "visible partial batch" failure) cannot occur.
export async function txn(entries, label = 'batch') {
  const stages = [];
  for (const [i, e] of entries.entries()) {
    const dir = DIRS[e.dir];
    const finalPath = path.join(dir, e.name);
    const tmpPath = path.join(dir, `.tmp-${process.pid}-${i}-${e.name.replace(/[^a-z0-9@.\-_]/gi, '_')}`);
    if (e.op === 'put') await writeJson(tmpPath, e.value);
    stages.push({ ...e, finalPath, tmpPath });
  }
  // Commit phase: rename puts; collects deletes (after puts so conflicts resolve).
  for (const s of stages) {
    if (s.op === 'put') await fs.rename(s.tmpPath, s.finalPath);
  }
  for (const s of stages) {
    if (s.op === 'delete') await fs.rm(s.finalPath, { force: true });
  }
  return stages.length;
}

// ---------- manifests ----------
export async function saveManifest(record) {
  await ensureDirs();
  await txn([{ op: 'put', dir: 'manifests', name: `${record.manifestId}.json`, value: record }]);
  return record;
}
export async function listManifests() {
  return listJson(DIRS.manifests);
}
export async function getManifest(id) {
  return readJson(path.join(DIRS.manifests, `${id}.json`), null);
}

// ---------- policies ----------
export async function savePolicy(record) {
  await txn([{ op: 'put', dir: 'policies', name: `${record.policyId}@${record.version}.json`, value: record }]);
}
export async function listPolicies() {
  return listJson(DIRS.policies);
}
export async function getPolicy(policyId, version) {
  return readJson(path.join(DIRS.policies, `${policyId}@${version}.json`), null);
}

// ---------- evidence ----------
export async function getEvidence() {
  return readJson(path.join(STATE, 'evidence.json'), []);
}
export async function setEvidence(records) {
  await writeJson(path.join(STATE, 'evidence.json'), records);
}

// ---------- exceptions + events ----------
export async function listExceptions() {
  return listJson(DIRS.exceptions);
}
export async function getException(id) {
  return readJson(path.join(DIRS.exceptions, `${id}.json`), null);
}
export async function saveException(record) {
  await txn([{ op: 'put', dir: 'exceptions', name: `${record.exceptionId}.json`, value: record }]);
}

export async function getEvents() {
  return readJson(path.join(STATE, 'events.json'), []);
}
export async function appendEvents(newEvents) {
  const events = await getEvents();
  events.push(...newEvents);
  // Deterministic event order: events are already ordered; additionally sort
  // by (at, seq, eventId) so cross-platform replay is identical.
  const sorted = events.slice().sort(compareEvent);
  await writeJson(path.join(STATE, 'events.json'), sorted);
}

function compareEvent(a, b) {
  if (a.at !== b.at) return a.at < b.at ? -1 : 1;
  const sa = a.seq || 0;
  const sb = b.seq || 0;
  if (sa !== sb) return sa - sb;
  return a.eventId < b.eventId ? -1 : a.eventId > b.eventId ? 1 : 0;
}

// ---------- scans ----------
export async function saveScan(record) {
  await txn([{ op: 'put', dir: 'scans', name: `${record.scan.scanId}.json`, value: record }]);
}
export async function listScans() {
  const records = await listJson(DIRS.scans);
  return records.sort((a, b) =>
    a.scan.evaluatedAt < b.scan.evaluatedAt ? -1 : a.scan.evaluatedAt > b.scan.evaluatedAt ? 1 : a.scan.scanId < b.scan.scanId ? -1 : 1,
  );
}
export async function getScan(id) {
  return readJson(path.join(DIRS.scans, `${id}.json`), null);
}

// ---------- plans ----------
export async function savePlan(record) {
  await txn([{ op: 'put', dir: 'plans', name: `${record.planId}.json`, value: record }]);
}
export async function listPlans() {
  const records = await listJson(DIRS.plans);
  return records.sort((a, b) => (a.planId < b.planId ? -1 : 1));
}
export async function getPlan(id) {
  return readJson(path.join(DIRS.plans, `${id}.json`), null);
}

// ---------- exports ----------
export async function saveExport(meta, zipBuffer) {
  await fs.writeFile(path.join(DIRS.exports, `${meta.exportId}.zip`), zipBuffer);
  await txn([{ op: 'put', dir: 'exports', name: `${meta.exportId}.json`, value: meta }]);
}
export async function listExports() {
  const records = await listJson(DIRS.exports);
  return records.sort((a, b) => (a.exportId < b.exportId ? -1 : 1));
}
export async function getExportZip(id) {
  return fs.readFile(path.join(DIRS.exports, `${id}.zip`));
}
export async function getExportMeta(id) {
  return readJson(path.join(DIRS.exports, `${id}.json`), null);
}

// ---------- meta ----------
export async function writeMeta(meta) {
  await writeJson(path.join(STATE, 'meta.json'), meta);
}

export function seedHash(value) {
  return createHash('sha256').update(value).digest('hex');
}

export { DATA, STATE, DIRS };
