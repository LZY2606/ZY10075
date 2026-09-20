// Stateless service operations over a Store instance. All time-sensitive
// operations require an explicit `at` instant.

import { parseManifest } from '../core/sbom.js';
import { buildGraph, applyOverlay } from '../core/graph.js';
import { evaluate, diffDecisions } from '../core/policy.js';
import { purlCoordinate } from '../core/purl.js';
import { computeFingerprints } from '../core/fingerprint.js';
import { buildAuditPack, verifyAuditPack } from '../core/audit.js';
import { publicException } from '../core/store.js';

export function resolveImage(store, imageId) {
  const image = store.getImage(imageId);
  if (!image) throw httpError(404, 'Unknown image: ' + imageId);
  return image;
}

export function resolvePolicy(store, version) {
  const policy = store.getPolicy(version ?? store.latestPolicyVersion());
  if (!policy) throw httpError(404, 'Unknown policy version: ' + version);
  return policy;
}

function httpError(status, message, extra = {}) {
  const error = new Error(message);
  error.status = status;
  Object.assign(error, extra);
  return error;
}

export async function evaluateImage(store, params) {
  const image = resolveImage(store, params.imageId);
  const policy = resolvePolicy(store, params.policyVersion);
  const at = params.at ?? '2026-09-21T03:00:00Z';
  const exceptions = store.listExceptions();
  const result = await evaluate({
    model: image.model,
    policy,
    exceptions,
    at,
    fingerprint: image.imageFingerprint
  });
  return {
    image: publicImage(image),
    policy: { policyId: policy.policyId, version: policy.version },
    result
  };
}

export async function comparePlan(store, params) {
  const image = resolveImage(store, params.imageId);
  const policy = resolvePolicy(store, params.policyVersion);
  const at = params.at ?? '2026-09-21T03:00:00Z';
  const actions = params.actions ?? [];

  const baselineGraph = buildGraph(image.model.components, image.model.edges, image.model.rootIds);
  const candidateModel = overlayToModel(image.model, actions, store.catalogByCoordinate);
  const candidateGraph = buildGraph(candidateModel.components, candidateModel.edges, candidateModel.rootIds);

  const exceptions = store.listExceptions();
  // Candidates do NOT carry the original manifest fingerprint claim, and
  // existing waivers are fingerprint-bound, so they never apply inside the
  // plan (upgrades/path changes must be re-approved).
  const baseline = await evaluate({
    model: image.model,
    graph: baselineGraph,
    policy,
    exceptions,
    at,
    fingerprint: image.imageFingerprint
  });
  const candidate = await evaluate({
    model: candidateModel,
    graph: candidateGraph,
    policy,
    exceptions: [],
    at,
    fingerprint: image.imageFingerprint + '#candidate',
    overlay: { actions }
  });
  return {
    image: publicImage(image),
    policy: { policyId: policy.policyId, version: policy.version },
    baseline,
    candidate,
    diff: diffDecisions(baseline, candidate)
  };
}

function overlayToModel(model, actions, catalogByCoordinate) {
  const graph = buildGraph(model.components, model.edges, model.rootIds);
  const upgraded = applyOverlay(
    graph,
    actions.map((action) => ({
      ...action,
      coordinate: purlCoordinate(action.id),
      name: graph.nodeById.get(action.id)?.name,
      ecosystem: graph.nodeById.get(action.id)?.ecosystem
    })),
    catalogByCoordinate
  );
  return {
    formatVersion: model.formatVersion,
    components: [...upgraded.nodeById.values()],
    edges: upgraded.edges,
    rootIds: upgraded.roots,
    aliases: model.aliases
  };
}

export async function recordScan(store, params) {
  const image = resolveImage(store, params.imageId);
  const policy = resolvePolicy(store, params.policyVersion);
  const at = params.at ?? '2026-09-21T03:00:00Z';
  const exceptions = store.listExceptions();
  const result = await evaluate({
    model: image.model,
    policy,
    exceptions,
    at,
    fingerprint: image.imageFingerprint
  });
  const scanId =
    params.scanId ??
    'SCN-' + at.slice(0, 10).replace(/-/g, '') + '-' + String(store.scans.size + 1).padStart(2, '0');
  const scan = {
    scanId,
    imageId: image.id,
    imageFingerprint: image.imageFingerprint,
    manifestSha256: image.manifestSha256,
    policyId: policy.policyId,
    policyVersion: policy.version,
    evaluatedAt: at,
    conclusion: result.conclusion,
    result,
    appliedExceptions: result.findings.filter((finding) => finding.waivedBy).map((finding) => finding.waivedBy)
  };
  store.append('scan.recorded', { scan }, { at, operator: params.operator ?? 'scanner-bot' });
  return scan;
}

export function listScans(store) {
  return [...store.scans.values()]
    .map((scan) => ({
      scanId: scan.scanId,
      imageId: scan.imageId,
      policyVersion: scan.policyVersion,
      evaluatedAt: scan.evaluatedAt,
      conclusion: scan.conclusion,
      appliedExceptions: scan.appliedExceptions ?? []
    }))
    .sort((a, b) => (a.scanId < b.scanId ? 1 : -1));
}

export function getScan(store, scanId) {
  const scan = store.scans.get(scanId);
  if (!scan) throw httpError(404, 'Unknown scan: ' + scanId);
  return scan;
}

export async function exportAuditPack(store, params) {
  const image = resolveImage(store, params.imageId);
  const policyVersion = params.policyVersion ?? image.model?.policyVersion;
  const policy = resolvePolicy(store, policyVersion);
  const scan = params.scanId ? getScan(store, params.scanId) : null;
  const events = store.allEvents();
  const exceptions = store.listExceptions().map(publicException);
  return buildAuditPack({
    imageId: image.id,
    rawManifest: image.rawManifest,
    model: image.model,
    policy,
    exceptions,
    events,
    scan,
    createdAt: params.createdAt ?? params.at ?? '2026-09-21T03:00:00Z',
    catalog: Object.fromEntries(store.catalogByCoordinate)
  });
}

export async function verifyPack(pack) {
  return verifyAuditPack(pack);
}

export async function ingestManifest(store, params) {
  let doc;
  try {
    doc = JSON.parse(params.rawText);
  } catch (error) {
    throw httpError(400, 'Manifest is not valid JSON: ' + error.message);
  }
  const model = parseManifest(doc);
  const fingerprints = await computeFingerprints(params.rawText, model);
  const record = {
    id: params.id,
    label: params.label ?? params.id,
    tag: params.tag ?? 'adhoc',
    format: doc.bomFormat === 'CycloneDX' ? 'CycloneDX' : 'SPDX',
    rawManifest: params.rawText,
    model,
    ...fingerprints,
    submittedAt: params.at ?? '2026-09-21T03:00:00Z'
  };
  store.images.set(record.id, record);
  return publicImage(record);
}

export function publicImage(image) {
  return {
    id: image.id,
    label: image.label,
    tag: image.tag,
    format: image.format,
    manifestSha256: image.manifestSha256,
    imageFingerprint: image.imageFingerprint,
    submittedAt: image.submittedAt,
    componentCount: image.model.components.length,
    edgeCount: image.model.edges.length,
    rootIds: image.model.rootIds,
    aliases: image.model.aliases
  };
}
