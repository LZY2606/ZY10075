// Deterministic seed. Every instant is fixed; re-running seed produces the
// same state byte-for-byte. Seed represents a realistic timeline:
//   - image 1.4.0 scanned twice: once under policy v1 (deny), once at a later
//     instant with an approved, bound exception for the recalled hash finding
//   - one revoked exception (revocation is a NEW event; history is preserved)
//   - pending exceptions ready for single + batch approval demos
//   - image 1.5.0 registered (SPDX) but left for the user to evaluate
import { promises as fs } from 'node:fs';
import path from 'node:path';
import { parseSbomJson } from '../shared/parse.js';
import { manifestFingerprint, bindFingerprint } from '../shared/fingerprint.js';
import { normalizePolicy, evaluate, pathKeyOf } from '../shared/policy.js';
import { evaluateScan, evidenceHash } from '../shared/scan.js';
import { createException, applyDecision } from '../shared/exceptions.js';
import { hashCanonical } from '../shared/id.js';
import {
  isSeeded,
  writeMeta,
  resetStateDir,
  saveManifest,
  savePolicy,
  setEvidence,
  saveException,
  appendEvents,
  saveScan,
  listPolicies,
  seedHash,
  DATA,
} from './store.js';

const T = {
  built14: '2026-09-01T09:00:00+09:00',
  scan14: '2026-09-02T10:00:00+09:00',
  requestHash: '2026-09-02T11:00:00+09:00',
  approveHash: '2026-09-02T13:30:00+09:00',
  scan14Exc: '2026-09-02T14:00:00+09:00',
  requestTemp: '2026-09-03T09:00:00+09:00',
  approveTemp: '2026-09-03T10:00:00+09:00',
  revokeTemp: '2026-09-08T10:00:00+09:00',
  built15: '2026-09-10T09:00:00+09:00',
};

async function readSeed(rel) {
  return fs.readFile(path.join(DATA, rel), 'utf8');
}

export async function seed(force = false) {
  if ((await isSeeded()) && !force) return { skipped: true };
  if (force) await resetStateDir();

  // ---- policies ----
  const policyRaw1 = await readSeed('policies/policy-v1.json');
  const policyRaw2 = await readSeed('policies/policy-v2.json');
  const policyDoc1 = normalizePolicy(JSON.parse(policyRaw1));
  const policyDoc2 = normalizePolicy(JSON.parse(policyRaw2));
  await savePolicy({
    policyId: policyDoc1.policyId,
    version: policyDoc1.version,
    document: JSON.parse(policyRaw1),
    normalized: policyDoc1,
    addedAt: T.built14,
  });
  await savePolicy({
    policyId: policyDoc2.policyId,
    version: policyDoc2.version,
    document: JSON.parse(policyRaw2),
    normalized: policyDoc2,
    addedAt: T.built15,
  });

  // ---- evidence ----
  const evidence = JSON.parse(await readSeed('evidence/aliases.json'));
  await setEvidence(evidence);

  // ---- manifests ----
  const raw14 = await readSeed('sbom/payments-1.4.0.cdx.json');
  const raw15 = await readSeed('sbom/payments-1.5.0.spdx.json');
  const m14 = parseSbomJson(raw14);
  const m15 = parseSbomJson(raw15);
  const fp14 = manifestFingerprint(m14, raw14);
  const fp15 = manifestFingerprint(m15, raw15);
  const id14 = 'sbom_1-4-0';
  const id15 = 'sbom_1-5-0';
  await saveManifest({
    manifestId: id14,
    fileName: 'payments-1.4.0.cdx.json',
    rawText: raw14,
    format: m14.format,
    fingerprint: fp14,
    image: m14.image,
    uploadedAt: T.built14,
  });
  await saveManifest({
    manifestId: id15,
    fileName: 'payments-1.5.0.spdx.json',
    rawText: raw15,
    format: m15.format,
    fingerprint: fp15,
    image: m15.image,
    uploadedAt: T.built15,
  });

  // ---- exceptions ----
  const events = [];
  const addEvent = (e) => {
    const ev = {
      eventId: 'evt_' + hashCanonical({ ...e, n: events.length }).slice(0, 16),
      seq: events.length + 1,
      ...e,
    };
    events.push(ev);
  };

  const hashFinding = evaluate(m14, policyDoc1).findings.find(
    (f) => f.ruleId === 'R-HASH-DENY' && f.component.startsWith('pypi|'),
  );
  const hashPathKey = pathKeyOf(hashFinding.paths[0]);

  const excHash = createException({
    componentKey: hashFinding.component,
    ruleId: 'R-HASH-DENY',
    policyId: policyDoc1.policyId,
    policyVersion: policyDoc1.version,
    bindFingerprint: bindFingerprint(fp14),
    pathKey: hashPathKey,
    digest: hashFinding.digest,
    notBefore: '2026-09-02T00:00:00+09:00',
    notAfter: '2026-10-15T23:59:59+09:00',
    reason: 'Compensating control: artifact quarantined at egress and vendor patch scheduled (fixture).',
    requestedBy: 'alice',
    createdAt: T.requestHash,
  });
  addEvent({ type: 'exception.requested', at: T.requestHash, actor: 'alice', exceptionId: excHash.exceptionId, fromVersion: 0, toVersion: 1, fromStatus: null, toStatus: 'pending', reason: excHash.reason });
  const hashDecision = applyDecision(excHash, {
    decision: 'approve',
    actor: 'security-bob',
    reason: 'Accepted: egress quarantine verified, remediation tracked as SEC-1042.',
    at: T.approveHash,
    expectedVersion: 1,
  });
  addEvent(hashDecision.event);
  await saveException(hashDecision.exception);

  // A temporary exception that was approved and later REVOKED (new event,
  // history retained).
  const gplFinding = evaluate(m14, policyDoc1).findings.find((f) => f.ruleId === 'R-LIC-GPL');
  const excTemp = createException({
    componentKey: gplFinding.component,
    ruleId: 'R-LIC-GPL',
    policyId: policyDoc1.policyId,
    policyVersion: policyDoc1.version,
    bindFingerprint: bindFingerprint(fp14),
    pathKey: pathKeyOf(gplFinding.paths[0]),
    license: gplFinding.license,
    notBefore: '2026-09-03T00:00:00+09:00',
    notAfter: '2026-09-20T12:00:00+09:00',
    reason: 'Legacy release train; migration to a permissive replacement planned.',
    requestedBy: 'carol',
    createdAt: T.requestTemp,
  });
  addEvent({ type: 'exception.requested', at: T.requestTemp, actor: 'carol', exceptionId: excTemp.exceptionId, fromVersion: 0, toVersion: 1, fromStatus: null, toStatus: 'pending', reason: excTemp.reason });
  const tempApproved = applyDecision(excTemp, {
    decision: 'approve',
    actor: 'security-bob',
    reason: 'Time-boxed approval pending replacement.',
    at: T.approveTemp,
    expectedVersion: 1,
  });
  addEvent(tempApproved.event);
  const tempRevoked = applyDecision(tempApproved.exception, {
    decision: 'revoke',
    actor: 'security-bob',
    reason: 'Replacement shipped early; exception no longer needed.',
    at: T.revokeTemp,
    expectedVersion: 2,
  });
  addEvent(tempRevoked.event);
  await saveException(tempRevoked.exception);

  // Two pending exceptions for approval demos.
  const provFinding = evaluate(m14, policyDoc1).findings.find((f) => f.ruleId === 'R-PROV-SUPPLIER');
  const excPending1 = createException({
    componentKey: provFinding.component,
    ruleId: 'R-PROV-SUPPLIER',
    policyId: policyDoc1.policyId,
    policyVersion: policyDoc1.version,
    bindFingerprint: bindFingerprint(fp14),
    pathKey: pathKeyOf(provFinding.paths[0]),
    notBefore: '2026-09-05T00:00:00+09:00',
    notAfter: '2026-09-30T23:59:59+09:00',
    reason: 'Vendor migrating package to the official registry next sprint.',
    requestedBy: 'dave',
    createdAt: '2026-09-04T15:00:00+09:00',
  });
  addEvent({ type: 'exception.requested', at: '2026-09-04T15:00:00+09:00', actor: 'dave', exceptionId: excPending1.exceptionId, fromVersion: 0, toVersion: 1, fromStatus: null, toStatus: 'pending', reason: excPending1.reason });
  await saveException(excPending1);

  const depthFinding = evaluate(m14, policyDoc1).findings.find((f) => f.ruleId === 'R-DEPTH');
  const excPending2 = createException({
    componentKey: depthFinding.component,
    ruleId: 'R-DEPTH',
    policyId: policyDoc1.policyId,
    policyVersion: policyDoc1.version,
    bindFingerprint: bindFingerprint(fp14),
    pathKey: pathKeyOf(depthFinding.paths[0]),
    notBefore: '2026-09-05T00:00:00+09:00',
    notAfter: '2026-09-30T23:59:59+09:00',
    reason: 'Build-tool only chain; evaluated and accepted with tree-shaking proof.',
    requestedBy: 'erin',
    createdAt: '2026-09-04T16:00:00+09:00',
  });
  addEvent({ type: 'exception.requested', at: '2026-09-04T16:00:00+09:00', actor: 'erin', exceptionId: excPending2.exceptionId, fromVersion: 0, toVersion: 1, fromStatus: null, toStatus: 'pending', reason: excPending2.reason });
  await saveException(excPending2);

  // ---- scans ----
  // Historical scan at release: no exception yet.
  const exceptionsNow = [excHash, excTemp, excPending1, excPending2];
  const scan1 = evaluateScan({
    manifest: m14,
    fingerprint: fp14,
    policy: policyDoc1,
    aliasEvidence: evidence,
    exceptions: [],
    evaluatedAt: T.scan14,
  });
  await saveScan({
    scan: scan1,
    manifestId: id14,
    refs: { policyId: policyDoc1.policyId, policyVersion: policyDoc1.version, evidenceVersion: evidenceHash(evidence) },
    savedAt: T.scan14,
  });

  // Later scan the same day: approved hash exception is applied; GPL exception
  // did not exist yet at that instant either.
  const scan2 = evaluateScan({
    manifest: m14,
    fingerprint: fp14,
    policy: policyDoc1,
    aliasEvidence: evidence,
    exceptions: [hashDecision.exception],
    evaluatedAt: T.scan14Exc,
  });
  await saveScan({
    scan: scan2,
    manifestId: id14,
    refs: { policyId: policyDoc1.policyId, policyVersion: policyDoc1.version, evidenceVersion: evidenceHash(evidence) },
    savedAt: T.scan14Exc,
  });

  await appendEvents(events);

  await writeMeta({
    schema: 1,
    seededAt: '2026-09-10T12:00:00+09:00',
    seedVersion: 'fixture-1',
    defaultBindFingerprint: bindFingerprint(fp14),
  });

  return { skipped: false, manifests: [id14, id15], exceptions: exceptionsNow.length };
}

if (import.meta.url === `file://${process.argv[1]}`) {
  seed(true).then((r) => {
    console.log(JSON.stringify(r));
  }).catch((err) => {
    console.error(err);
    process.exit(1);
  });
}
