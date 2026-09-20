// Component equivalence is established ONLY from explicit evidence.
// Same name in different ecosystems never merges by default.
//
// Evidence record:
// { id, kind, aKey|aPurl, bKey|bPurl, source, confidence: 'high'|'medium',
//   sha256?, note }
// supported kinds:
//   purl-alias     — two purls asserted to identify the same component
//                    (e.g. pkg:npm/fs-extra == pkg:npm/%40scope/x); needs
//                    high confidence OR 2 medium records
//   hash-equality  — identical SHA-256 artifact hash (strongest evidence);
//                    always sufficient WITHIN an ecosystem.
//   vcs-locator    — identical canonical VCS URL + release tag
//   advisory       — named upstream advisory mapping (needs 2 mediums or 1 high)
import { canonicalize } from './canonical.js';
import { componentKey } from './model.js';
import { hashText } from './id.js';

export function evidenceId(ev) {
  return (
    'ev_' +
    hashText(
      canonicalize({
        kind: ev.kind,
        a: ev.aPurl || ev.aKey || null,
        b: ev.bPurl || ev.bKey || null,
        sha256: ev.sha256 || null,
        source: ev.source || null,
      }),
    ).slice(0, 16)
  );
}

function sufficient(groupKinds) {
  const high = groupKinds.filter((k) => k.confidence === 'high').length;
  const medium = groupKinds.length - high;
  if (high >= 1) return true;
  if (medium >= 2) return true;
  // a single hash-equality is intrinsically strong
  if (groupKinds.some((k) => k.kind === 'hash-equality' && k.sha256)) return true;
  return false;
}

// Build equivalence groups over the components of one or more manifests.
// `manifests` is used to resolve purls -> component keys and to find hash facts.
// Returns { groups: [[key,...]], evidenceUsed: [evidenceId], rejected: [ev...] }
export function buildEquivalence(manifests, evidence) {
  const allKeys = new Set();
  const byPurl = new Map();
  const byHash = new Map();
  for (const m of manifests) {
    for (const c of m.components) {
      allKeys.add(c.key);
      if (c.purl) byPurl.set(canonicalPurl(c.purl), c.key);
      if (c.hashes && c.hashes.SHA256) {
        const h = c.hashes.SHA256.toLowerCase();
        const list = byHash.get(h) || [];
        list.push(c.key);
        byHash.set(h, list);
      }
    }
  }

  const parent = new Map();
  const find = (x) => {
    if (!parent.has(x)) parent.set(x, x);
    const p = parent.get(x);
    if (p === x) return x;
    const r = find(p);
    parent.set(x, r);
    return r;
  };
  const union = (a, b) => {
    parent.set(find(a), find(b));
  };

  // Collect candidate pairs per union with the supporting evidence, so
  // sufficiency is evaluated per equivalence claim.
  const pending = new Map(); // sig -> { a, b, evs: [] }
  const rejected = [];
  const consider = (a, b, ev) => {
    const [x, y] = a < b ? [a, b] : [b, a];
    if (x === y) return;
    const sig = `${x}\u0000${y}`;
    if (!pending.has(sig)) pending.set(sig, { a: x, b: y, evs: [] });
    pending.get(sig).evs.push(ev);
  };

  const keyOfPurl = (purl) => byPurl.get(canonicalPurl(purl));

  for (const ev of evidence || []) {
    const a = ev.aKey || (ev.aPurl ? keyOfPurl(ev.aPurl) : null);
    const b = ev.bKey || (ev.bPurl ? keyOfPurl(ev.bPurl) : null);
    if (!allKeys.has(a) || !allKeys.has(b)) {
      rejected.push({ ...ev, reason: 'endpoint not present in analyzed manifests' });
      continue;
    }
    if (ecosystemOf(a) !== ecosystemOf(b) && !crossEcosystemAllowed(ev)) {
      rejected.push({ ...ev, reason: 'different ecosystems and no hash-equality evidence' });
      continue;
    }
    consider(a, b, ev);
  }

  // Implicit hash-equality within the same ecosystem is accepted as high
  // evidence (same artifact bytes); cross-ecosystem hash matches still require
  // an explicit record so accidental collisions/confusion stay visible.
  for (const [hash, keys] of byHash) {
    for (let i = 0; i < keys.length; i++) {
      for (let j = i + 1; j < keys.length; j++) {
        const a = keys[i];
        const b = keys[j];
        if (ecosystemOf(a) === ecosystemOf(b)) {
          consider(a, b, {
            id: 'implicit-hash-' + hash.slice(0, 12),
            kind: 'hash-equality',
            aKey: a,
            bKey: b,
            sha256: hash,
            source: 'artifact-hash',
            confidence: 'high',
          });
        }
      }
    }
  }

  const evidenceUsed = [];
  for (const { a, b, evs } of pending.values()) {
    if (sufficient(evs)) {
      union(a, b);
      for (const e of evs) evidenceUsed.push(e.id);
    } else {
      for (const e of evs) rejected.push({ ...e, reason: 'insufficient alias evidence' });
    }
  }

  const groupsMap = new Map();
  for (const k of allKeys) {
    const r = find(k);
    if (!groupsMap.has(r)) groupsMap.set(r, []);
    groupsMap.get(r).push(k);
  }
  const groups = [...groupsMap.values()]
    .filter((g) => g.length > 1)
    .map((g) => g.sort())
    .sort((x, y) => (x[0] < y[0] ? -1 : x[0] > y[0] ? 1 : 0));

  return {
    groups,
    evidenceUsed: [...new Set(evidenceUsed)].sort(),
    rejected: sortRejected(rejected),
  };
}

function crossEcosystemAllowed(ev) {
  return ev.kind === 'hash-equality' && !!ev.sha256;
}

function ecosystemOf(key) {
  return key.split('|')[0];
}

// Canonicalize a purl for comparison: decode percent encoding, lowercase
// type/namespace/name, strip trailing slash. Qualifiers are ignored for
// identity (build flags do not change upstream identity).
export function canonicalPurl(purl) {
  const m = /^pkg:([^/]+)\/(.+?)(?:\?.*)?$/.exec(purl);
  if (!m) return purl;
  const type = decodeURIComponent(m[1]).toLowerCase();
  const path = decodeURIComponent(m[2]).toLowerCase().replace(/\/+$/, '');
  return `pkg:${type}/${path}`;
}

// Canonical key of a component for lookup, re-exported convenience.
export { componentKey };

function sortRejected(list) {
  return [...list].sort((a, b) => {
    const ka = `${a.kind}|${a.aKey || a.aPurl || ''}|${a.bKey || b.bPurl || ''}`;
    const kb = `${b.kind}|${b.aKey || b.aPurl || ''}|${b.bKey || b.bPurl || ''}`;
    return ka < kb ? -1 : ka > kb ? 1 : 0;
  });
}
