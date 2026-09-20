// Audit packs. A pack contains every input needed to reproduce the displayed
// decision: exact original manifest bytes, the policy document revision, the
// full exception/event history and the evaluation inputs. Nothing in the pack
// depends on wall-clock time: createdAt is supplied by the caller.

import { canonicalJson, sha256Text } from './canonical.js';
import { imageFingerprint, manifestSha256 } from './fingerprint.js';
import { eventChainDigest } from './store.js';

export async function buildAuditPack(input) {
  const { imageId, rawManifest, model, policy, exceptions, events, scan, createdAt, catalog = {} } = input;
  const manifestSha = await manifestSha256(rawManifest);
  const imageSha = await imageFingerprint(model);
  const chainDigest = await eventChainDigest(events);

  const policyRecord = {
    policyId: policy.policyId,
    version: policy.version,
    document: policy
  };
  const exceptionRecords = exceptions.map((record) => ({
    exceptionId: record.id,
    state: record.state,
    revision: record.revision,
    document: record
  }));

  const files = {};
  files['manifest.json'] = { sha256: manifestSha, bytes: rawManifest };
  files['policy.json'] = { sha256: await sha256Text(canonicalJson(policyRecord)), value: policyRecord };
  files['exceptions.json'] = {
    sha256: await sha256Text(canonicalJson(exceptionRecords)),
    value: exceptionRecords
  };
  files['events.json'] = {
    sha256: chainDigest,
    value: events.map((event) => ({
      eventId: event.eventId,
      sequence: event.sequence,
      type: event.type,
      at: event.at,
      operator: event.operator,
      payload: event.payload
    }))
  };

  const summary = {
    packFormat: 1,
    imageId,
    createdAt,
    manifestSha256: manifestSha,
    imageFingerprint: imageSha,
    policy: { policyId: policy.policyId, version: policy.version },
    exceptionCount: exceptionRecords.length,
    eventCount: events.length,
    eventChainDigest: chainDigest,
    conclusion: scan?.conclusion ?? null,
    files: Object.keys(files).sort()
  };
  files['audit-summary.json'] = { sha256: await sha256Text(canonicalJson(summary)), value: summary };

  const pack = { summary, files, catalog };
  pack.packDigest = await sha256Text(canonicalJson(pack));
  return pack;
}

export async function verifyAuditPack(pack) {
  const errors = [];
  if (!pack || typeof pack !== 'object') return { ok: false, errors: ['Pack is not an object'] };
  const { files, summary } = pack;
  if (!files || !summary) return { ok: false, errors: ['Pack missing files or summary'] };

  const recomputeFile = async (name, value) => sha256Text(canonicalJson(value));
  for (const name of Object.keys(files).sort()) {
    const entry = files[name];
    if (!entry || entry.sha256 === undefined) {
      errors.push('File entry malformed: ' + name);
      continue;
    }
    const payload = entry.bytes !== undefined ? entry.bytes : entry.value;
    const digest =
      entry.bytes !== undefined
        ? await sha256Text(entry.bytes)
        : await recomputeFile(name, entry.value);
    if (digest !== entry.sha256) errors.push('Tampered file: ' + name);
  }

  // Recompute image fingerprint from the stored manifest bytes and compare to
  // the manifest recorded for the scan — this proves the original manifest is
  // unchanged relative to what was evaluated.
  try {
    const { parseManifest } = await import('./sbom.js');
    const raw = files['manifest.json'].bytes;
    const model = parseManifest(JSON.parse(raw));
    const fingerprint = await imageFingerprint(model);
    if (fingerprint !== summary.imageFingerprint) {
      errors.push('Image fingerprint mismatch: manifest content does not match recorded scan input');
    }
    if ((await manifestSha256(raw)) !== summary.manifestSha256) {
      errors.push('Manifest sha256 mismatch');
    }
  } catch (error) {
    errors.push('Cannot re-parse embedded manifest: ' + error.message);
  }

  const policyEntry = files['policy.json']?.value;
  if (!policyEntry?.version || !policyEntry?.policyId) errors.push('Policy version missing');
  const exceptionEntries = files['exceptions.json']?.value ?? [];
  for (const record of exceptionEntries) {
    if (!record.exceptionId || !record.revision || !record.document?.policyVersion) {
      errors.push('Exception revision/version incomplete: ' + record.exceptionId);
    }
  }

  const chainDigest = await eventChainDigest(files['events.json']?.value ?? []);
  if (chainDigest !== summary.eventChainDigest) errors.push('Event chain digest mismatch');

  const summaryDigest = await recomputeFile('audit-summary.json', summary);
  if (files['audit-summary.json'].sha256 !== summaryDigest) errors.push('Summary digest mismatch');

  return { ok: errors.length === 0, errors };
}
