// Bill-of-materials ingestion: CycloneDX (1.4/1.5 JSON) and SPDX (2.3 JSON).
// Both are normalized into one model:
//   component { id, coordinate, name, ecosystem, version, hashes[],
//               licenses[] (SPDX expressions), sources[] {kind,url},
//               bomRef, scope }
//   edge      { from, to }                    (canonical purl ids)
//   alias     { from, to, evidence, hashes }  (equivalence candidates)
//   rootIds[]
//
// Identity rules (see README "Component identity and aliases"):
//   * canonical purl is the node id; pkg:npm/left-pad != pkg:pypi/left-pad.
//   * aliases are NEVER inferred from a shared name. They require (a) explicit
//     alias evidence in the document AND (b) at least one equal cryptographic
//     hash between the two nodes. Verified pairs become equivalence links.

import { canonicalPurl, purlCoordinate } from './purl.js';
import { normalizeExpression } from './license.js';
import { stableCompare } from './canonical.js';

function buildPurlFromParts(ecosystem, namespace, name, version, qualifiers) {
  let purl = 'pkg:' + ecosystem + '/';
  if (namespace) purl += namespace.toLowerCase() + '/';
  purl += name.toLowerCase();
  if (version) purl += '@' + version;
  if (qualifiers && Object.keys(qualifiers).length) {
    const q = Object.keys(qualifiers).sort().map((key) => key + '=' + qualifiers[key]).join('&');
    purl += '?' + q;
  }
  return purl;
}

function cdxLicense(component) {
  const out = [];
  for (const license of component.licenses ?? []) {
    if (license.expression) out.push(normalizeExpression(license.expression));
    else if (license.license?.id) out.push(normalizeExpression(license.license.id));
    else if (license.license?.name) out.push(license.license.name);
  }
  return [...new Set(out)];
}

function cdxHashes(component) {
  return (component.hashes ?? [])
    .filter((hash) => hash.alg && hash.content)
    .map((hash) => ({ alg: String(hash.alg).toLowerCase().replace('-', ''), value: hash.content.toLowerCase() }));
}

function cdxSources(component) {
  return (component.externalReferences ?? [])
    .filter((ref) => ref.url)
    .map((ref) => ({ kind: ref.type ?? 'unknown', url: ref.url }));
}

function aliasEvidenceFromProperties(properties) {
  const map = new Map((properties ?? []).map((entry) => [entry.name, entry.value]));
  const raw = map.get('sbomguard:aliasOf') ?? map.get('internal:aliasOf');
  if (!raw) return null;
  return { targetRef: raw, kind: map.get('sbomguard:aliasEvidence') ?? 'explicit' };
}

export function parseCycloneDx(doc) {
  if (!doc || doc.bomFormat !== 'CycloneDX') {
    throw new Error('Not a CycloneDX document (missing bomFormat)');
  }
  const byRef = new Map();
  const components = [];
  const rawComponents = [...(doc.components ?? []), ...(doc.metadata?.component ? [doc.metadata.component] : [])];
  for (const raw of rawComponents) {
    if (!raw) continue;
    const purl = canonicalPurl(raw.purl ?? buildPurlFromParts(raw.type ?? 'generic', raw.group, raw.name, raw.version)) ;
    if (!purl) continue;
    const component = {
      id: purl,
      coordinate: purlCoordinate(purl),
      name: raw.name,
      ecosystem: raw.type ?? 'generic',
      version: (raw.version ?? null),
      hashes: cdxHashes(raw),
      licenses: cdxLicense(raw),
      sources: cdxSources(raw),
      bomRef: raw['bom-ref'] ?? raw.bomRef ?? purl,
      scope: raw.scope ?? null
    };
    if (!byRef.has(component.bomRef)) byRef.set(component.bomRef, component);
    components.push(component);
  }

  // Merge duplicate components with the same canonical id (keep unique data).
  const merged = mergeComponents(components);

  const edges = [];
  for (const dep of doc.dependencies ?? []) {
    const fromComponent = byRef.get(dep.ref);
    if (!fromComponent) continue;
    for (const ref of dep.dependencies ?? []) {
      const toComponent = byRef.get(ref);
      if (toComponent && toComponent.id !== fromComponent.id) edges.push({ from: fromComponent.id, to: toComponent.id });
    }
  }

  const rootComponents = merged.filter(
    (component) => component.bomRef === doc.metadata?.component?.['bom-ref'] || component.id === canonicalPurl(doc.metadata?.component?.purl ?? '')
  );
  const rootIds = rootComponents.length
    ? [...new Set(rootComponents.map((component) => component.id))]
    : merged.filter((component) => component.scope === 'required' && component.ecosystem === 'image').map((component) => component.id);

  const aliases = collectCdxAliases(rawComponents, byRef);
  return finalizeModel(merged, edges, rootIds, aliases);
}

function collectCdxAliases(rawComponents, byRef) {
  const pairs = [];
  for (const raw of rawComponents) {
    const evidence = aliasEvidenceFromProperties(raw.properties);
    if (!evidence) continue;
    const source = byRef.get(raw['bom-ref'] ?? raw.bomRef);
    const target = byRef.get(evidence.targetRef);
    if (!source || !target || source.id === target.id) continue;
    pairs.push({ from: source.id, to: target.id, evidence: evidence.kind });
  }
  return verifyAliases(pairs, byRef);
}

function spdxLicense(raw, idField = 'licenseConcluded') {
  const value = raw?.[idField];
  if (!value || value === 'NOASSERTION' || value === 'NONE') return [];
  if (typeof value === 'string') return [normalizeExpression(value)];
  if (value.license?.id) return [normalizeExpression(value.license.id)];
  if (value.expression) return [normalizeExpression(value.expression)];
  return [];
}

export function parseSpdx(doc) {
  if (!doc || (!doc.spdxVersion || !String(doc.spdxVersion).startsWith('SPDX-'))) {
    throw new Error('Not an SPDX document (missing spdxVersion)');
  }
  const byId = new Map();
  const components = [];
  for (const pkg of doc.packages ?? []) {
    const purlRef = (pkg.externalRefs ?? []).find((ref) => String(ref.referenceType).toLowerCase() === 'purl');
    let purl = purlRef ? canonicalPurl(purlRef.referenceLocator) : null;
    if (!purl) {
      purl = canonicalPurl(buildPurlFromParts('generic', null, pkg.name, pkg.versionInfo));
    }
    if (!purl) continue;
    const refs = [];
    const component = {
      id: purl,
      coordinate: purlCoordinate(purl),
      name: pkg.name,
      ecosystem: (purlRef ? purl.split('/')[0].replace('pkg:', '') : 'generic'),
      version: pkg.versionInfo ?? null,
      hashes: (pkg.checksums ?? []).map((checksum) => ({
        alg: String(checksum.algorithm).replace(/^SHA\d+:/i, (m) => m.slice(0, -1).toLowerCase()).toLowerCase(),
        value: String(checksum.checksumValue).toLowerCase()
      })),
      licenses: spdxLicense(pkg),
      sources: (pkg.externalRefs ?? [])
        .filter((ref) => ref.referenceLocator)
        .map((ref) => ({ kind: ref.referenceType, url: ref.referenceLocator })),
      bomRef: pkg.SPDXID,
      scope: null,
      annotations: pkg.annotations ?? []
    };
    byId.set(pkg.SPDXID, component);
    components.push(component);
  }
  const merged = mergeComponents(components);

  const described = new Set();
  const edges = [];
  for (const relationship of doc.relationships ?? []) {
    if (relationship.relationshipType === 'DESCRIBES') described.add(relationship.relatedSpdxElement);
    if (relationship.relationshipType === 'DEPENDS_ON' || relationship.relationshipType === 'CONTAINS') {
      const from = byId.get(relationship.spdxElementId);
      const to = byId.get(relationship.relatedSpdxElement);
      if (from && to && from.id !== to.id) edges.push({ from: from.id, to: to.id });
    }
  }
  const rootIds = [...described].map((id) => byId.get(id)?.id).filter(Boolean);
  const aliases = collectSpdxAliases(merged, byId);
  return finalizeModel(merged, edges, rootIds.length ? [...new Set(rootIds)].sort(stableCompare) : [], aliases);
}

function collectSpdxAliases(components, byId) {
  const pairs = [];
  for (const component of components) {
    const annotation = (component.annotations ?? []).find(
      (entry) => entry.annotationType === 'OTHER' && /aliasOf/i.test(entry.comment ?? '')
    );
    if (!annotation) continue;
    const match = String(annotation.comment).match(/(SPDXRef-[A-Za-z0-9:.-]+)/);
    const source = byId.get(component.bomRef);
    const target = match ? byId.get(match[1]) : null;
    if (source && target && source.id !== target.id) {
      pairs.push({ from: source.id, to: target.id, evidence: 'annotation' });
    }
  }
  return verifyAliases(pairs, byId);
}

// Shared hash evidence is mandatory: both sides must expose the same alg/value.
function verifyAliases(pairs, byRef) {
  const findComponent = (id) =>
    [...byRef.values()].find((component) => component.id === id || component.bomRef === id) ?? null;
  const verified = [];
  const seen = new Set();
  for (const pair of pairs) {
    const left = findComponent(pair.from);
    const right = findComponent(pair.to);
    if (!left || !right) continue;
    const shared = left.hashes.filter((hash) => right.hashes.some((other) => other.alg === hash.alg && other.value === hash.value));
    if (!shared.length) continue;
    const key = [pair.from, pair.to].sort(stableCompare).join('|');
    if (seen.has(key)) continue;
    seen.add(key);
    verified.push({
      from: pair.from,
      to: pair.to,
      evidence: pair.evidence,
      sharedHashes: shared.map((hash) => ({ alg: hash.alg, value: hash.value }))
    });
  }
  return verified.sort((a, b) => stableCompare(a.from + a.to, b.from + b.to));
}

function mergeComponents(components) {
  const map = new Map();
  for (const component of components) {
    const existing = map.get(component.id);
    if (!existing) {
      map.set(component.id, { ...component });
      continue;
    }
    existing.licenses = [...new Set([...existing.licenses, ...component.licenses])].sort(stableCompare);
    existing.sources = mergeBy(existing.sources, component.sources, (entry) => entry.url);
    existing.hashes = mergeBy(existing.hashes, component.hashes, (entry) => entry.alg + ':' + entry.value);
    existing.bomRef = existing.bomRef ?? component.bomRef;
  }
  return [...map.values()].sort((a, b) => stableCompare(a.id, b.id));
}

function mergeBy(a, b, keyFn) {
  const seen = new Set(a.map(keyFn));
  const out = [...a];
  for (const item of b) if (!seen.has(keyFn(item))) out.push(item);
  return out.sort((x, y) => stableCompare(keyFn(x), keyFn(y)));
}

function finalizeModel(components, edges, rootIds, aliases) {
  const uniqueEdges = [...new Map(edges.map((edge) => [edge.from + '\u0000' + edge.to, edge])).values()].sort(
    (a, b) => stableCompare(a.from + a.to, b.from + b.to)
  );
  return {
    formatVersion: 1,
    components: components.map(({ annotations, ...rest }) => rest),
    edges: uniqueEdges,
    rootIds: [...new Set(rootIds)].sort(stableCompare),
    aliases
  };
}

export function parseManifest(doc) {
  if (doc?.bomFormat === 'CycloneDX') return parseCycloneDx(doc);
  if (doc?.spdxVersion) return parseSpdx(doc);
  throw new Error('Unrecognized manifest: neither CycloneDX nor SPDX');
}
