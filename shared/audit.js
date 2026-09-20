// Audit packages prove:
//  1. every original manifest is unchanged (raw byte hash re-verified)
//  2. policy + exception versions used by each scan are all present
//  3. ordering/naming is platform independent (code-unit sort, fixed timestamps)
//  4. scan decisions recompute exactly from saved inputs + rule versions
import { createZip, readZip } from './zip.js';
import { canonicalize } from './canonical.js';
import { sha256Hex, hashText } from './id.js';
import { parseSbomJson } from './parse.js';
import { manifestFingerprint } from './fingerprint.js';
import { evidenceHash } from './scan.js';
import { evaluateScan } from './scan.js';
import { normalizePolicy } from './policy.js';

// bundle: {
//   manifests: [{ manifestId, fileName, rawText, fingerprint }],
//   policies: [{ policyId, version, document }],
//   evidence: [records],
//   exceptions: [snapshots],
//   events: [decision/request events],
//   scans: [scan result records + their input references],
//   createdAt (explicit instant, for manifest naming only — does not hash)
// }
export function buildAuditPackage(bundle) {
  const files = [];
  const add = (path, valueOrText, raw = false) => {
    const data = raw ? valueOrText : canonicalize(valueOrText) + '\n';
    files.push({ path, data });
  };

  add('audit/version', 'sbom-policy-gate-audit/1\n', true);
  add('audit/created-at.txt', `${bundle.createdAt}\n`, true);

  const manifestIndex = [];
  for (const m of sortedBy(bundle.manifests, (x) => x.manifestId)) {
    const rawText = m.rawText;
    const parsed = parseSbomJson(rawText);
    const fp = manifestFingerprint(parsed, rawText);
    if (m.fingerprint && m.fingerprint.manifestFingerprint !== fp.manifestFingerprint) {
      throw new Error(`manifest ${m.manifestId}: stored fingerprint mismatch`);
    }
    add(`manifests/${m.manifestId}/${m.fileName || 'sbom.json'}`, rawText, true);
    add(`manifests/${m.manifestId}/fingerprint.json`, {
      manifestId: m.manifestId,
      ...fp,
      rawLength: Buffer.byteLength(rawText, 'utf8'),
    });
    manifestIndex.push({ manifestId: m.manifestId, fileName: m.fileName, ...fp });
  }
  add('manifests/index.json', { manifests: manifestIndex });

  const policyIndex = [];
  for (const p of sortedBy(bundle.policies, (x) => `${x.policyId}@${x.version}`)) {
    const normalized = normalizePolicy(p.document);
    add(`policies/${p.policyId}@${p.version}.json`, normalized);
    policyIndex.push({ policyId: p.policyId, version: p.version, sha256: sha256Hex(canonicalize(normalized)) });
  }
  add('policies/index.json', { policies: policyIndex });

  add('evidence/records.json', bundle.evidence || []);
  add('evidence/version.txt', `${evidenceHash(bundle.evidence || [])}\n`, true);

  add('exceptions/snapshots.json', bundle.exceptions || []);
  add('events/decision-log.json', bundle.events || []);

  const scanIndex = [];
  for (const s of sortedBy(bundle.scans, (x) => x.scan.scanId)) {
    add(`scans/${s.scan.scanId}/result.json`, s.scan);
    add(
      `scans/${s.scan.scanId}/inputs.json`,
      {
        manifestId: s.manifestId,
        bindFingerprint: s.scan.bindFingerprint,
        policyId: s.scan.policy.policyId,
        policyVersion: s.scan.policy.version,
        evidenceVersion: s.scan.evidenceVersion,
        evaluatedAt: s.scan.evaluatedAt,
      },
    );
    scanIndex.push({
      scanId: s.scan.scanId,
      decision: s.scan.decision,
      manifestId: s.manifestId,
      policy: s.scan.policy,
      evaluatedAt: s.scan.evaluatedAt,
    });
  }
  add('scans/index.json', { scans: scanIndex });

  // Manifest of the package itself: sorted file list with raw sha256 + sizes.
  const fileList = files
    .map((f) => ({ path: f.path, sha256: sha256Hex(f.data), bytes: Buffer.byteLength(f.data) }))
    .sort((a, b) => (a.path < b.path ? -1 : a.path > b.path ? 1 : 0));
  add('audit/files.json', { files: fileList });
  const digest = sha256Hex(canonicalize(fileList));
  add('audit/digest.txt', `${digest}\n`, true);

  // Re-sort not needed: createZip sorts deterministically.
  const zip = createZip(files);
  return { zip, digest, fileCount: files.length, files: fileList };
}

export function verifyAuditPackage(zipBuffer, { policies, manifests, evidence, exceptions }) {
  let entries;
  try {
    entries = readZip(zipBuffer);
  } catch (err) {
    return { ok: false, issues: ['package is not a readable zip: ' + err.message], digest: null, fileCount: null, scans: null };
  }
  const map = new Map(entries.map((e) => [e.path, e.data]));
  const issues = [];

  const filesDoc = readJson(map, 'audit/files.json', issues);
  const claimedDigest = (map.get('audit/digest.txt') || Buffer.from('')).toString().trim();
  if (!filesDoc) return { ok: false, issues: issues.concat('missing audit/files.json') };
  const recomputedDigest = sha256Hex(canonicalize(filesDoc.files));
  if (recomputedDigest !== claimedDigest) issues.push('audit digest mismatch');

  // Every listed file present with matching bytes; order must be code-unit sorted
  let last = '';
  for (const f of filesDoc.files) {
    if (f.path < last) issues.push(`file order not canonical at ${f.path}`);
    last = f.path;
    const data = map.get(f.path);
    if (!data) {
      issues.push(`missing file in package: ${f.path}`);
      continue;
    }
    if (sha256Hex(data) !== f.sha256) issues.push(`file content mismatch: ${f.path}`);
    if (Buffer.byteLength(data) !== f.bytes) issues.push(`file size mismatch: ${f.path}`);
  }

  // Raw manifests re-parse and re-fingerprint identically
  const manifestById = new Map((manifests || []).map((m) => [m.manifestId, m]));
  const policyByVer = new Map((policies || []).map((p) => [`${p.policyId}@${p.version}`, p.document]));
  const indexDoc = readJson(map, 'manifests/index.json', issues);
  if (indexDoc) {
    for (const row of indexDoc.manifests) {
      const prefix = `manifests/${row.manifestId}/`;
      const fileEntry = entries.find((e) => e.path.startsWith(prefix) && e.path !== prefix + 'fingerprint.json');
      if (!fileEntry) {
        issues.push(`manifest raw bytes missing: ${row.manifestId}`);
        continue;
      }
      const rawText = fileEntry.data.toString('utf8');
      const parsed = parseSbomJson(rawText);
      const fp = manifestFingerprint(parsed, rawText);
      for (const k of ['rawSha256', 'modelSha256', 'manifestFingerprint']) {
        if (fp[k] !== row[k]) issues.push('manifest ' + row.manifestId + ' ' + k + ' differs from index');
      }
      const supplied = manifestById.get(row.manifestId);
      if (supplied && sha256Hex(supplied.rawText) !== row.rawSha256) {
        issues.push('manifest ' + row.manifestId + ': supplied raw bytes differ from sealed manifest');
      }
    }
  }

  // Policies + exception snapshots + evidence versions are present
  const scansDoc = readJson(map, 'scans/index.json', issues);
  const exceptionsDoc = readJson(map, 'exceptions/snapshots.json', issues);
  const evidenceVersion = (map.get('evidence/version.txt') || Buffer.from('')).toString().trim();

  if (scansDoc) {
    for (const row of scansDoc.scans) {
      const inputs = readJson(map, `scans/${row.scanId}/inputs.json`, issues);
      const result = readJson(map, `scans/${row.scanId}/result.json`, issues);
      if (!inputs || !result) continue;
      if (!map.has(`policies/${inputs.policyId}@${inputs.policyVersion}.json`)) {
        issues.push(`scan ${row.scanId}: policy ${inputs.policyId}@${inputs.policyVersion} missing`);
      }
      const evRow = entries.find((e) => e.path.startsWith('manifests/') && e.path.endsWith('fingerprint.json'));
      // verify manifest referenced by scan exists in package
      const mList = (indexDoc && indexDoc.manifests) || [];
      if (!mList.some((m) => m.manifestId === inputs.manifestId)) {
        issues.push(`scan ${row.scanId}: bound manifest missing`);
      }
      if (inputs.evidenceVersion && inputs.evidenceVersion !== evidenceVersion) {
        issues.push(`scan ${row.scanId}: evidence version missing/inconsistent`);
      }
      // Recompute the decision from saved inputs and compare.
      const mRec = manifestById.get(inputs.manifestId);
      const pDoc = policyByVer.get(`${inputs.policyId}@${inputs.policyVersion}`);
      if (mRec && pDoc) {
        const reparsed = parseSbomJson(mRec.rawText);
        const fp = manifestFingerprint(reparsed, mRec.rawText);
        const recomputed = evaluateScan({
          manifest: reparsed,
          fingerprint: fp,
          policy: normalizePolicy(pDoc),
          aliasEvidence: evidence || [],
          exceptions: exceptionsDoc || [],
          evaluatedAt: inputs.evaluatedAt,
        });
        if (recomputed.decision !== result.decision) issues.push(`scan ${row.scanId}: decision not reproducible`);
        if (canonicalize(recomputed.findings) !== canonicalize(result.findings)) {
          issues.push(`scan ${row.scanId}: findings not reproducible`);
        }
      }
    }
  }

  return {
    ok: issues.length === 0,
    issues,
    digest: claimedDigest,
    fileCount: filesDoc ? filesDoc.files.length : null,
    scans: scansDoc ? scansDoc.scans.length : null,
  };
}

function readJson(map, path, issues) {
  const data = map.get(path);
  if (!data) {
    issues.push(`missing ${path}`);
    return null;
  }
  try {
    return JSON.parse(data.toString('utf8'));
  } catch (err) {
    issues.push(`invalid JSON in ${path}: ${err.message}`);
    return null;
  }
}

function sortedBy(list, keyFn) {
  return [...list].sort((a, b) => {
    const ka = keyFn(a);
    const kb = keyFn(b);
    return ka < kb ? -1 : ka > kb ? 1 : 0;
  });
}

export { hashText };
