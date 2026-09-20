// Parsers for CycloneDX JSON (1.4/1.5) and SPDX JSON (2.2/2.3).
// Only the fields the policy model needs are extracted; originals stay saved
// byte-for-byte for audit verification.
import { buildManifest, componentKey } from './model.js';

export function parseSbomJson(rawText) {
  let doc;
  try {
    doc = JSON.parse(rawText);
  } catch (err) {
    throw new Error('SBOM is not valid JSON: ' + err.message);
  }
  if (doc && (doc.bomFormat === 'CycloneDX' || doc.spdxVersion || doc.SPDXID)) {
    return doc.spdxVersion || doc.SPDXID ? parseSpdx(doc) : parseCdx(doc);
  }
  throw new Error('unrecognized SBOM format (expected CycloneDX or SPDX JSON)');
}

export function parseCdx(doc) {
  if (doc.bomFormat !== 'CycloneDX') throw new Error('not a CycloneDX document');
  const components = [];
  const byBomRef = new Map();

  for (const c of doc.components || []) {
    const eco0 = inferEcosystemCdx(c);
    const grp0 = c.group || '';
    const comp = {
      key: [eco0, grp0, c.name, c.version || ''].join('|'),
      ecosystem: eco0,
      group: grp0,
      name: c.name,
      version: c.version || '',
      purl: c.purl || null,
      hashes: Object.fromEntries((c.hashes || []).map((h) => [String(h.alg).toUpperCase(), h.content])),
      licenses: (c.licenses || []).map(cdxLicense).filter(Boolean),
      supplier: supplierName(c.supplier || c.publisher),
      downloadLocation: externalLocator(c, ['vcs', 'distribution']) || null,
      externalRefs: (c.externalRefs || []).map((r) => ({ type: r.referenceType, locator: r.locator })),
      bomRef: c['bom-ref'] ?? null,
    };
    components.push(comp);
    if (comp.bomRef != null) byBomRef.set(String(comp.bomRef), comp);
  }

  // metadata.component is the image/application itself.
  const metaComp = doc.metadata && doc.metadata.component;
  if (metaComp) {
    const ecoR = inferEcosystemCdx(metaComp) || 'container';
    const grpR = metaComp.group || '';
    const comp = {
      key: [ecoR, grpR, metaComp.name, metaComp.version || ''].join('|'),
      ecosystem: ecoR,
      group: grpR,
      name: metaComp.name,
      version: metaComp.version || '',
      purl: metaComp.purl || null,
      hashes: Object.fromEntries((metaComp.hashes || []).map((h) => [String(h.alg).toUpperCase(), h.content])),
      licenses: (metaComp.licenses || []).map(cdxLicense).filter(Boolean),
      supplier: supplierName(metaComp.supplier || metaComp.publisher),
      downloadLocation: externalLocator(metaComp, ['vcs', 'distribution']) || null,
      externalRefs: (metaComp.externalRefs || []).map((r) => ({ type: r.referenceType, locator: r.locator })),
      bomRef: metaComp['bom-ref'] ?? null,
      root: true,
    };
    components.push(comp);
    if (comp.bomRef != null) byBomRef.set(String(comp.bomRef), comp);
  }

  const rawEdges = [];
  const unresolved = [];
  for (const dep of doc.dependencies || []) {
    const ref = String(dep.ref);
    const from = refComp(byBomRef, ref);
    if (!from) {
      unresolved.push({ ref, declaredBy: null });
      continue;
    }
    for (const depRef of dep.dependencies || []) {
      const to = refComp(byBomRef, String(depRef));
      if (!to) {
        unresolved.push({ ref: String(depRef), declaredBy: ref });
        continue;
      }
      if (to.key !== from.key) {
        rawEdges.push({ from: from.key, to: to.key, kind: 'dependsOn', rawRefs: { from: ref, to: String(depRef) } });
      }
    }
  }
  void unresolved;

  // No dependency graph: metadata.component depends on every listed component.
  if (!rawEdges.length && metaComp) {
    const root = components.find((c) => c.root);
    for (const c of components) if (!c.root) rawEdges.push({ from: root.key, to: c.key, kind: 'dependsOn' });
  }
  // Document-level edges: root components with no parent.
  const hasParent = new Set(rawEdges.map((e) => e.to));
  for (const c of components) {
    if (c.root && !hasParent.has(c.key)) rawEdges.push({ from: null, to: c.key, kind: 'dependsOn' });
  }

  const edges = dedupeEdges(rawEdges);
  const clean = components.map(stripInternal);
  return buildManifest(
    {
      format: 'cyclonedx',
      formatVersion: doc.specVersion || null,
      specName: 'CycloneDX',
      specVersion: doc.specVersion || null,
      documentName: doc.metadata && doc.metadata.component ? doc.metadata.component.name : null,
      documentId: doc.serialNumber || null,
      image: imageCdx(doc),
    },
    clean,
    edges,
  );
}

function refComp(map, ref) {
  // bom-ref may equal purl; fall back to purl match.
  if (map.has(ref)) return map.get(ref);
  for (const c of map.values()) if (c.purl === ref) return c;
  return null;
}

function cdxLicense(l) {
  if (!l) return null;
  if (l.license) {
    const lo = l.license;
    const refs = [];
    if (lo.id) refs.push(lo.id);
    return { expression: lo.id || lo.name || null, refs };
  }
  if (l.expression) return { expression: l.expression, refs: [] };
  return null;
}

function inferEcosystemCdx(c) {
  if (c.type === 'container' || c.type === 'application') {
    // containers may still carry a purl ecosystem; trust purl when present
    const fromPurl = purlType(c.purl);
    if (fromPurl) return fromPurl;
    return 'container';
  }
  if (c.type === 'file') return 'file';
  return purlType(c.purl) || (c.type ? String(c.type) : 'unknown');
}

function purlType(purl) {
  if (!purl) return null;
  const m = /^pkg:([^/]+)\//.exec(purl);
  return m ? decodeURIComponent(m[1]) : null;
}

function supplierName(s) {
  if (!s) return null;
  return typeof s === 'string' ? s : s.name || null;
}

function externalLocator(c, types) {
  const ref = (c.externalRefs || []).find((r) => types.includes(r.referenceType));
  return ref ? ref.locator : null;
}

function imageCdx(doc) {
  const props = {};
  for (const p of (doc.metadata && doc.metadata.properties) || []) props[p.name] = p.value;
  const mc = doc.metadata && doc.metadata.component;
  const digest =
    props['aquasecurity:trivy:ImageDigest'] ||
    props['image:digest'] ||
    hashAlg((mc && mc.hashes) || [], 'SHA-256') ||
    null;
  const repo = props['aquasecurity:trivy:ImageRepository'] || props['image:repository'] || (mc && mc.name) || null;
  const tag = props['aquasecurity:trivy:ImageTag'] || props['image:tag'] || (mc && mc.version) || null;
  return { repository: repo, digest: digest ? normalizeDigest(digest) : null, tag };
}

function hashAlg(hashes, alg) {
  const h = hashes.find((x) => String(x.alg).toUpperCase() === alg);
  return h ? h.content : null;
}

export function parseSpdx(doc) {
  if (!doc.spdxVersion && !doc.SPDXID) throw new Error('not an SPDX document');
  const packages = doc.packages || [];
  const byId = new Map();
  const components = [];

  for (const p of packages) {
    const purl = spdxExternalRef(p, ['purl']);
    const maven = spdxExternalRef(p, ['maven-central']);
    const described = isDescribedPackage(doc, p.SPDXID);
    const ecosystem = described
      ? 'container'
      : purlType(purl) || (maven ? 'maven' : spdxPkgType(p, purl));
    const { group, name } = spdxNameParts(p, ecosystem);
    const hashes = {};
    for (const cs of p.checksums || []) hashes[String(cs.algorithm).replace(/^SHA-/i, 'SHA-')] = cs.checksumValue;
    const comp = {
      key: [ecosystem, group, name, p.versionInfo || ''].join('|'),
      ecosystem,
      group,
      name,
      version: p.versionInfo || '',
      purl,
      hashes,
      licenses: spdxLicenses(p),
      supplier: spdxParty(p.supplier),
      downloadLocation: p.downloadLocation && p.downloadLocation !== 'NOASSERTION' ? p.downloadLocation : null,
      externalRefs: (p.externalRefs || []).map((r) => ({ type: r.referenceType, locator: r.referenceLocator })),
      spdxId: p.SPDXID,
    };
    components.push(comp);
    byId.set(p.SPDXID, comp);
  }

  const rawEdges = [];
  const roots = new Set(components.map((c) => c.spdxId));
  for (const rel of doc.relationships || []) {
    const kind = rel.relationshipType;
    const sourceId = rel.spdxElementId;
    const targetId = rel.relatedSpdxElement;
    if (isDependsOn(kind) && byId.has(sourceId) && byId.has(targetId)) {
      const from = byId.get(sourceId);
      const to = byId.get(targetId);
      if (from.key !== to.key) rawEdges.push({ from: from.key, to: to.key, kind: 'dependsOn', rawRefs: { from: sourceId, to: targetId } });
      roots.delete(targetId);
    }
    if (isDescribes(kind) && sourceId === doc.SPDXID && byId.has(targetId)) {
      // document -> described package: root edge handled below
      roots.add(targetId);
    }
  }
  // DESCRIBES relationships mark document roots explicitly.
  const described = (doc.relationships || [])
    .filter((r) => isDescribes(r.relationshipType) && r.spdxElementId === doc.SPDXID && byId.has(r.relatedSpdxElement))
    .map((r) => byId.get(r.relatedSpdxElement).key);
  for (const key of described) rawEdges.push({ from: null, to: key, kind: 'dependsOn' });
  if (!described.length) {
    for (const id of roots) {
      const c = byId.get(id);
      if (c && !(rawEdges.some((e) => e.to === c.key))) rawEdges.push({ from: null, to: c.key, kind: 'dependsOn' });
    }
  }

  return buildManifest(
    {
      format: 'spdx',
      formatVersion: doc.spdxVersion || null,
      specName: 'SPDX',
      specVersion: (doc.spdxVersion || '').replace('SPDX-', '') || null,
      documentName: doc.name || null,
      documentId: doc.documentNamespace || doc.SPDXID || null,
      image: imageSpdx(doc),
    },
    components.map(stripInternal),
    dedupeEdges(rawEdges),
  );
}

const DEPENDS_REL = new Set([
  'DEPENDS_ON',
  'DYNAMIC_LINK',
  'STATIC_LINK',
  'RUNTIME_DEPENDENCY_OF',
  'DEV_DEPENDENCY_OF',
  'CONTAINS',
]);
function isDependsOn(kind) {
  return DEPENDS_REL.has(kind);
}
function isDescribedPackage(doc, spdxId) {
  return (doc.relationships || []).some(
    (r) =>
      (r.relationshipType === 'DESCRIBES' || r.relationshipType === 'DESCRIBE') &&
      r.spdxElementId === doc.SPDXID &&
      r.relatedSpdxElement === spdxId,
  );
}
function isDescribes(kind) {
  return kind === 'DESCRIBES' || kind === 'DESCRIBE';
}

function spdxExternalRef(p, types) {
  const ref = (p.externalRefs || []).find((r) => types.includes(r.referenceCategory) || types.includes(r.referenceType));
  return ref ? ref.referenceLocator : null;
}

function spdxPkgType(p, purl) {
  const loc = spdxExternalRef(p, ['package-manager']);
  if (loc) {
    const t = purlType(loc);
    if (t) return t;
  }
  // heuristics based on download location
  const dl = p.downloadLocation || '';
  if (/pypi\.org/.test(dl)) return 'pypi';
  if (/npmjs/.test(dl)) return 'npm';
  if (/repo1\.maven|mvn/.test(dl)) return 'maven';
  return 'unknown';
}

function spdxNameParts(p, ecosystem) {
  const name = p.name;
  if (ecosystem === 'maven' && p.name && p.name.includes(':')) {
    const idx = p.name.indexOf(':');
    return { group: p.name.slice(0, idx), name: p.name.slice(idx + 1) };
  }
  if (ecosystem === 'pypi') return { group: '', name: name.toLowerCase().replace(/_/g, '-') };
  if (ecosystem === 'npm' && name && name.startsWith('@') && name.includes('/')) {
    const idx = name.indexOf('/');
    return { group: name.slice(0, idx), name: name.slice(idx + 1) };
  }
  return { group: '', name };
}

function spdxLicenses(p) {
  const out = [];
  const declared = p.licenseDeclared;
  if (declared && declared !== 'NOASSERTION' && declared !== 'NONE') {
    out.push({ expression: declared, refs: [] });
  }
  const concluded = p.licenseConcluded;
  if (concluded && concluded !== 'NOASSERTION' && concluded !== 'NONE' && concluded !== declared) {
    out.push({ expression: concluded, refs: [] });
  }
  return out;
}

function spdxParty(value) {
  if (!value || value === 'NOASSERTION') return null;
  const m = /^[^:]*:\s*(.*?)(\s*\(.*\))?$/.exec(value);
  return m ? m[1] : value;
}

function imageSpdx(doc) {
  const ns = doc.documentNamespace || '';
  const digest = /sha256:([a-f0-9]{64})/i.exec(ns);
  return {
    repository: doc.name || null,
    digest: digest ? 'sha256:' + digest[1].toLowerCase() : null,
    tag: null,
  };
}

function normalizeDigest(d) {
  return /^sha256:/.test(d) ? d : 'sha256:' + d;
}

function dedupeEdges(edges) {
  const seen = new Set();
  const out = [];
  for (const e of edges) {
    const sig = `${e.from == null ? '' : e.from}\u0000${e.to}\u0000${e.kind}`;
    if (!seen.has(sig)) {
      seen.add(sig);
      out.push(e);
    }
  }
  return out;
}

function stripInternal(c) {
  const { bomRef, spdxId, root, ...rest } = c;
  return rest;
}
