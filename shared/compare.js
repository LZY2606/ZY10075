// Compare two manifests / two evaluated scans.
// Components match by canonical key. Alias groups may additionally treat keys
// as equivalent when evidence is sufficient (passed in from scans).
import { sorted } from './canonical.js';

export function compareManifests(base, candidate, { equivalenceGroups = [] } = {}) {
  const aliasOf = buildAliasIndex(equivalenceGroups);
  const bMap = new Map(base.components.map((c) => [c.key, c]));
  const cMap = new Map(candidate.components.map((c) => [c.key, c]));

  const added = [];
  const removed = [];
  const changed = [];
  const unchanged = [];

  const matched = new Set();
  for (const c of candidate.components) {
    if (bMap.has(c.key)) {
      matched.add(c.key);
      const old = bMap.get(c.key);
      const changes = diffComponent(old, c);
      if (changes.length) changed.push({ key: c.key, coordinate: c.key, changes });
      else unchanged.push(c.key);
    } else {
      const aliasKey = aliasOf.get(c.key);
      const oldViaAlias = aliasKey && bMap.has(aliasKey) ? bMap.get(aliasKey) : null;
      if (oldViaAlias) {
        matched.add(aliasKey);
        changed.push({
          key: c.key,
          renamedFrom: aliasKey,
          coordinate: c.key,
          changes: diffComponent(oldViaAlias, c),
        });
      } else {
        added.push(c.key);
      }
    }
  }
  for (const c of base.components) {
    if (!matched.has(c.key) && !cMap.has(c.key)) removed.push(c.key);
  }

  // Edge differences
  const baseEdges = new Set(base.edges.map(edgeSig));
  const candEdges = new Set(candidate.edges.map(edgeSig));
  const edgesAdded = [];
  const edgesRemoved = [];
  for (const e of candidate.edges) {
    const s = edgeSig(e);
    if (!baseEdges.has(s)) edgesAdded.push(e);
  }
  for (const e of base.edges) {
    const s = edgeSig(e);
    if (!candEdges.has(s)) edgesRemoved.push(e);
  }

  return {
    base: { fingerprint: base.__fingerprint || null, componentCount: base.components.length },
    candidate: { fingerprint: candidate.__fingerprint || null, componentCount: candidate.components.length },
    added: sortKeys(added),
    removed: sortKeys(removed),
    changed: sorted(changed, (x) => x.key),
    unchanged: sortKeys(unchanged),
    edgesAdded: edgesAdded.sort((a, b) => edgeSig(a) < edgeSig(b) ? -1 : 1),
    edgesRemoved: edgesRemoved.sort((a, b) => edgeSig(a) < edgeSig(b) ? -1 : 1),
  };
}

// Compare two scan decisions by findingKey; exceptions do not blur this view:
// raw findings are compared, and coverage is reported alongside.
export function compareScans(baseScan, candidateScan) {
  const b = new Map(baseScan.findings.map((f) => [f.findingKey, f]));
  const c = new Map(candidateScan.findings.map((f) => [f.findingKey, f]));
  const bActive = new Set(baseScan.activeFindings);
  const cActive = new Set(candidateScan.activeFindings);

  const risksRemoved = [];
  const risksAdded = [];
  const stillPresent = [];

  for (const [key, f] of c) {
    if (!b.has(key)) {
      risksAdded.push({ findingKey: key, component: f.component, ruleId: f.ruleId, reason: f.reason, active: cActive.has(key) });
    } else {
      stillPresent.push({
        findingKey: key,
        component: f.component,
        ruleId: f.ruleId,
        activeBefore: bActive.has(key),
        activeAfter: cActive.has(key),
        reason: f.reason,
      });
    }
  }
  for (const [key, f] of b) {
    if (!c.has(key)) {
      risksRemoved.push({ findingKey: key, component: f.component, ruleId: f.ruleId, reason: f.reason, wasActive: bActive.has(key) });
    }
  }

  const sortFn = (x) => x.findingKey;
  return {
    decisionBefore: baseScan.decision,
    decisionAfter: candidateScan.decision,
    risksRemoved: sorted(risksRemoved, sortFn),
    risksAdded: sorted(risksAdded, sortFn),
    stillPresent: sorted(stillPresent, sortFn),
    exceptionsBefore: baseScan.appliedExceptions,
    exceptionsAfter: candidateScan.appliedExceptions,
  };
}

function diffComponent(oldC, newC) {
  const changes = [];
  if (JSON.stringify(oldC.hashes) !== JSON.stringify(newC.hashes)) {
    changes.push({ field: 'hashes', before: oldC.hashes, after: newC.hashes });
  }
  if (JSON.stringify(oldC.licenses) !== JSON.stringify(newC.licenses)) {
    changes.push({ field: 'licenses', before: oldC.licenses, after: newC.licenses });
  }
  if (oldC.supplier !== newC.supplier) changes.push({ field: 'supplier', before: oldC.supplier, after: newC.supplier });
  if (oldC.downloadLocation !== newC.downloadLocation) {
    changes.push({ field: 'downloadLocation', before: oldC.downloadLocation, after: newC.downloadLocation });
  }
  return changes;
}

function edgeSig(e) {
  return `${e.from == null ? '' : e.from}>${e.kind}>${e.to}`;
}

function sortKeys(list) {
  return [...list].sort();
}

function buildAliasIndex(groups) {
  // group representative is the smallest key; map every member to representative
  const idx = new Map();
  for (const g of groups) {
    const rep = g[0];
    for (const k of g) idx.set(k, rep);
  }
  return idx;
}
