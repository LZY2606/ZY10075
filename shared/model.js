// Canonical model shared by parsers, policy engine, planning and UI.
//
// Component identity:
//   key = ecosystem + '|' + group/namespace + '|' + name + '|' + version
//   "" is used for absent group. Same name in different ecosystems yields
//   different keys and is NEVER merged here. Equivalence is established
//   separately by aliases.js only when evidence is sufficient.
export function componentKey({ ecosystem, group, name, version }) {
  return [ecosystem || '', group || '', name || '', version || ''].join('|');
}

export function keyParts(key) {
  const [ecosystem, group, name, version] = key.split('|');
  return { ecosystem, group, name, version };
}

// Human readable coordinate, e.g. "npm:left-pad@1.2.3" or "pypi:requests@2.31".
export function coordinate(key) {
  const p = keyParts(key);
  const g = p.group ? p.group + '/' : '';
  return `${p.ecosystem || 'unknown'}:${g}${p.name}@${p.version}`;
}

// Normalized manifest:
// {
//   format: 'cyclonedx'|'spdx', formatVersion, specName, specVersion,
//   documentName, documentId,
//   image: { repository, digest, tag },
//   components: [{ key, ecosystem, group, name, version, purl,
//                  hashes: { alg: hex }, licenses: [ {expression, refs:[spdxId...]} ],
//                  supplier, downloadLocation, externalRefs: [{type, locator}] }],
//   edges: [{ from: key|null, to: key, kind, rawRefs?: {from,to} }]
// }
export function normalizeComponent(raw) {
  const c = {
    key: componentKey(raw),
    ecosystem: raw.ecosystem || '',
    group: raw.group || '',
    name: raw.name,
    version: raw.version || '',
    purl: raw.purl || null,
    hashes: sortHashes(raw.hashes || {}),
    licenses: (raw.licenses || []).map(normalizeLicense),
    supplier: raw.supplier || null,
    downloadLocation: raw.downloadLocation || null,
    externalRefs: (raw.externalRefs || []).map((r) => ({
      type: r.type,
      locator: r.locator,
    })),
  };
  return c;
}

function sortHashes(hashes) {
  const out = {};
  for (const alg of Object.keys(hashes).sort()) out[alg] = hashes[alg].toLowerCase();
  return out;
}

function normalizeLicense(l) {
  if (typeof l === 'string') return { expression: l.trim(), refs: [] };
  return {
    expression: l.expression || null,
    refs: [...(l.refs || [])].map((r) => String(r)).sort(),
  };
}

// Build normalized manifest object and validate uniqueness of keys.
export function buildManifest(meta, rawComponents, rawEdges) {
  const components = rawComponents.map(normalizeComponent);
  const byKey = new Map();
  for (const c of components) {
    if (byKey.has(c.key)) {
      throw new Error(`duplicate component identity in manifest: ${coordinate(c.key)}`);
    }
    byKey.set(c.key, c);
  }
  const edges = rawEdges.map((e) => ({
    from: e.from == null ? null : e.from,
    to: e.to,
    kind: e.kind || 'dependsOn',
    ...(e.rawRefs ? { rawRefs: e.rawRefs } : {}),
  }));
  for (const e of edges) {
    if (e.from != null && !byKey.has(e.from)) {
      throw new Error(`edge references unknown source component: ${e.from}`);
    }
    if (!byKey.has(e.to)) {
      throw new Error(`edge references unknown target component: ${e.to}`);
    }
  }
  return {
    format: meta.format,
    formatVersion: meta.formatVersion || null,
    specName: meta.specName || null,
    specVersion: meta.specVersion || null,
    documentName: meta.documentName || null,
    documentId: meta.documentId || null,
    image: meta.image || {},
    components: sortComponents(components),
    edges: sortEdges(edges),
  };
}

export function sortComponents(components) {
  return [...components].sort((a, b) => (a.key < b.key ? -1 : a.key > b.key ? 1 : 0));
}

export function sortEdges(edges) {
  return [...edges].sort((a, b) => {
    const ka = `${a.from == null ? '' : a.from}\u0000${a.to}\u0000${a.kind}`;
    const kb = `${b.from == null ? '' : b.from}\u0000${b.to}\u0000${b.kind}`;
    return ka < kb ? -1 : ka > kb ? 1 : 0;
  });
}

// Dependency adjacency (kind = dependsOn only).
// Returns Map<key|null, sorted target keys[]>; null key = document roots.
export function adjacency(manifest) {
  const map = new Map();
  for (const c of manifest.components) map.set(c.key, []);
  map.set(null, []);
  for (const e of manifest.edges) {
    if (e.kind !== 'dependsOn') continue;
    const list = map.has(e.from) ? map.get(e.from) : [];
    list.push(e.to);
    map.set(e.from, list);
  }
  for (const [k, list] of map) {
    list.sort();
    // de-duplicate identical edges
    map.set(k, [...new Set(list)]);
  }
  return map;
}

export function componentMap(manifest) {
  const m = new Map();
  for (const c of manifest.components) m.set(c.key, c);
  return m;
}

// Root components: targets of edges from document (from == null),
// or all components with no incoming dependsOn edge when no root edges exist.
export function rootKeys(manifest) {
  const adj = adjacency(manifest);
  const explicit = adj.get(null) || [];
  if (explicit.length) return explicit;
  const incoming = new Set();
  for (const c of manifest.components) {
    for (const t of adj.get(c.key) || []) incoming.add(t);
  }
  return manifest.components
    .map((c) => c.key)
    .filter((k) => !incoming.has(k))
    .sort();
}
