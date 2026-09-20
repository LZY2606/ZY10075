// Package URL normalization. The canonical purl string is the component
// identity key: same name in a different ecosystem always keeps a different key
// (pkg:npm/left-pad vs pkg:pypi/left-pad), so such components are never merged.

function decodePct(segment) {
  return decodeURIComponent(segment);
}

function encodePct(segment) {
  // purl percent-encoding: encode anything outside the unreserved set.
  return segment.replace(/[^A-Za-z0-9._~-]/g, (ch) =>
    Array.from(new TextEncoder().encode(ch))
      .map((b) => '%' + b.toString(16).toUpperCase().padStart(2, '0'))
      .join('')
  );
}

export function parsePurl(purl) {
  if (typeof purl !== 'string') return null;
  const trimmed = purl.trim();
  if (!trimmed.startsWith('pkg:')) return null;
  let rest = trimmed.slice(4);
  const fragmentAt = rest.indexOf('#');
  const fragment = fragmentAt >= 0 ? rest.slice(fragmentAt + 1) : null;
  rest = fragmentAt >= 0 ? rest.slice(0, fragmentAt) : rest;
  let qualifiers = null;
  const queryAt = rest.indexOf('?');
  if (queryAt >= 0) {
    const q = rest.slice(queryAt + 1);
    rest = rest.slice(0, queryAt);
    qualifiers = {};
    for (const pair of q.split('&')) {
      if (!pair) continue;
      const eq = pair.indexOf('=');
      const key = eq >= 0 ? pair.slice(0, eq) : pair;
      const val = eq >= 0 ? pair.slice(eq + 1) : '';
      qualifiers[decodePct(key)] = decodePct(val);
    }
  }
  let subpath = null;
  const slashSlash = rest.indexOf('//') === 0;
  if (slashSlash) rest = rest.slice(2);
  const slashIdx = rest.indexOf('/');
  const head = slashIdx >= 0 ? rest.slice(0, slashIdx) : rest;
  let tail = slashIdx >= 0 ? rest.slice(slashIdx + 1) : '';
  const colonIdx = head.indexOf(':');
  const type = (colonIdx >= 0 ? head.slice(0, colonIdx) : head).toLowerCase();
  let namespace = null;
  if (colonIdx >= 0) namespace = head.slice(colonIdx + 1);
  const lastSlash = tail.lastIndexOf('/');
  if (lastSlash >= 0) {
    const nsPart = namespace ? namespace + '/' + tail.slice(0, lastSlash) : tail.slice(0, lastSlash);
    namespace = nsPart.split('/').filter(Boolean).map(decodePct).join('/');
    tail = tail.slice(lastSlash + 1);
  }
  const atIdx = tail.lastIndexOf('@');
  let name = atIdx >= 0 ? tail.slice(0, atIdx) : tail;
  let version = atIdx >= 0 ? tail.slice(atIdx + 1) : null;
  if (version !== null) {
    // purl puts subpath after version: name@version?query#subpath handled above
    // by fragment; SPDX sometimes uses '@' inside encoded names but we keep
    // decoding simple here.
  }
  name = decodePct(name);
  if (version) version = decodePct(version);
  if (fragment) subpath = decodePct(fragment);
  if (!type || !name) return null;
  return { type, namespace, name, version, qualifiers, subpath };
}

export function canonicalPurl(purl) {
  const parsed = parsePurl(purl);
  if (!parsed) return null;
  let out = 'pkg:' + parsed.type + '/';
  if (parsed.namespace) {
    // Per purl spec, namespace is case-sensitive; only the name is lowercased.
    out += parsed.namespace.split('/').map(encodePct).join('/') + '/';
  }
  out += encodePct(parsed.name.toLowerCase());
  if (parsed.version) out += '@' + encodePct(parsed.version);
  if (parsed.qualifiers && Object.keys(parsed.qualifiers).length) {
    const keys = Object.keys(parsed.qualifiers).sort();
    out += '?' + keys.map((k) => encodePct(k) + '=' + encodePct(String(parsed.qualifiers[k]))).join('&');
  }
  if (parsed.subpath) out += '#' + parsed.subpath.split('/').map(encodePct).join('/');
  return out;
}

// Coordinate without version, used by rule matching (deny rules may pin a
// version) and by "same component, new version" detection.
export function purlCoordinate(purl) {
  const parsed = parsePurl(purl);
  if (!parsed) return null;
  let out = 'pkg:' + parsed.type + '/';
  if (parsed.namespace) out += parsed.namespace.split('/').map(encodePct).join('/') + '/';
  out += encodePct(parsed.name.toLowerCase());
  return out;
}

export function purlWithoutVersion(purl) {
  const canonical = canonicalPurl(purl);
  if (!canonical) return null;
  const at = canonical.indexOf('@');
  return at >= 0 ? canonical.slice(0, at) : canonical;
}
