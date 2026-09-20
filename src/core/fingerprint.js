// Image / manifest fingerprints.
//   manifestSha256: digest of the exact bytes that were submitted (proves the
//     original manifest was not altered when an audit pack is verified).
//   imageFingerprint: digest of the NORMALIZED model (canonical JSON of
//     components, edges, roots and aliases). Any semantic change to the graph —
//     new component version, removed edge, changed path — changes this value,
//     so an exception bound to the old fingerprint can no longer match.

import { canonicalJson, sha256Text } from './canonical.js';

export async function sha256Bytes(bytes) {
  const { createHash } = await import('node:crypto');
  return createHash('sha256').update(bytes).digest('hex');
}

export async function manifestSha256(rawText) {
  return sha256Text(rawText);
}

export async function imageFingerprint(model) {
  const normalized = {
    aliases: model.aliases.map((alias) => ({
      from: alias.from,
      to: alias.to,
      evidence: alias.evidence,
      sharedHashes: alias.sharedHashes.map((hash) => ({ alg: hash.alg, value: hash.value }))
    })),
    components: model.components.map((component) => ({
      id: component.id,
      coordinate: component.coordinate,
      name: component.name,
      ecosystem: component.ecosystem,
      version: component.version,
      hashes: component.hashes.map((hash) => ({ alg: hash.alg, value: hash.value })),
      licenses: component.licenses,
      sources: component.sources.map((source) => ({ kind: source.kind, url: source.url }))
    })),
    edges: model.edges.map((edge) => ({ from: edge.from, to: edge.to })),
    rootIds: model.rootIds
  };
  return sha256Text(canonicalJson(normalized));
}

export async function computeFingerprints(rawText, model) {
  const [manifest, image] = await Promise.all([manifestSha256(rawText), imageFingerprint(model)]);
  return { manifestSha256: manifest, imageFingerprint: image };
}
