// What-if scenarios operate on an in-memory COPY of the manifest.
// The original saved manifest is never mutated.
import { buildManifest } from './model.js';
import { reachableFrom, directDependencies } from './paths.js';
import { evaluate } from './policy.js';
import { hashCanonical } from './id.js';
import { compareScans } from './compare.js';

export function planId(plan) {
  return 'plan_' + hashCanonical(plan).slice(0, 16);
}

// actions: [{ action: 'delete-node', componentKey },
//           { action: 'upgrade-node', componentKey, to: { version, hashes?,
//               licenses?, supplier?, downloadLocation? } }]
// delete-node removes the node AND the subtree that becomes unreachable
// (only components exclusively reachable through the deleted node are removed).
export function applyScenario(manifest, actions) {
  let components = manifest.components.map((c) => ({ ...c, hashes: { ...c.hashes }, licenses: c.licenses.map((l) => ({ ...l })), externalRefs: c.externalRefs.map((r) => ({ ...r })) }));
  let edges = manifest.edges.map((e) => ({ ...e }));

  const effects = [];

  // Upgrades first (change identity), then deletes.
  for (const act of actions.filter((a) => a.action === 'upgrade-node')) {
    const idx = components.findIndex((c) => c.key === act.componentKey);
    if (idx < 0) throw new Error('unknown component: ' + act.componentKey);
    const old = components[idx];
    const updated = {
      ...old,
      version: act.to.version,
      hashes: act.to.hashes ? normHashes(act.to.hashes) : old.hashes,
      licenses: act.to.licenses || old.licenses,
      supplier: act.to.supplier !== undefined ? act.to.supplier : old.supplier,
      downloadLocation:
        act.to.downloadLocation !== undefined ? act.to.downloadLocation : old.downloadLocation,
    };
    const key = componentKeyOf(updated);
    if (key !== old.key) {
      updated.key = key;
      edges = edges.map((e) => ({
        ...e,
        from: e.from === old.key ? key : e.from,
        to: e.to === old.key ? key : e.to,
      }));
    }
    components[idx] = updated;
    effects.push({ type: 'upgraded', from: old.key, to: key });
  }

  const componentKeys = new Set(components.map((c) => c.key));

  for (const act of actions.filter((a) => a.action === 'delete-node')) {
    if (!componentKeys.has(act.componentKey)) {
      throw new Error('unknown component: ' + act.componentKey);
    }
    // Reachable-from-node in current graph vs graph without the node.
    const removedKeys = exclusivelyReachable(
      components.map((c) => ({ ...c })),
      edges,
      act.componentKey,
    );
    removedKeys.add(act.componentKey);
    components = components.filter((c) => !removedKeys.has(c.key));
    edges = edges.filter((e) => !removedKeys.has(e.to) && !removedKeys.has(e.from));
    effects.push({ type: 'deleted', keys: [...removedKeys].sort() });
  }

  const candidate = buildManifest(
    {
      format: manifest.format,
      formatVersion: manifest.formatVersion,
      specName: manifest.specName,
      specVersion: manifest.specVersion,
      documentName: manifest.documentName,
      documentId: manifest.documentId,
      image: manifest.image,
    },
    components.map((c) => ({
      ecosystem: c.ecosystem,
      group: c.group,
      name: c.name,
      version: c.version,
      purl: c.purl,
      hashes: c.hashes,
      licenses: c.licenses,
      supplier: c.supplier,
      downloadLocation: c.downloadLocation,
      externalRefs: c.externalRefs,
    })),
    edges,
  );

  return { candidate, effects };
}

function componentKeyOf(c) {
  return [c.ecosystem, c.group, c.name, c.version].join('|');
}

// Components reachable ONLY through node (i.e. disappear when node is deleted).
// Recomputed on a graph with node removed.
function exclusivelyReachable(components, edges, nodeKey) {
  const keepAdj = new Map();
  const rootTargets = [];
  for (const c of components) keepAdj.set(c.key, []);
  for (const e of edges) {
    if (e.kind !== 'dependsOn') continue;
    if (e.from === nodeKey || e.to === nodeKey) continue;
    if (e.from == null) {
      rootTargets.push(e.to);
      continue;
    }
    if (!keepAdj.has(e.from)) continue;
    keepAdj.get(e.from).push(e.to);
  }
  const reachable = new Set(rootTargets);
  const queue = [...rootTargets];
  while (queue.length) {
    const k = queue.shift();
    for (const n of keepAdj.get(k) || []) {
      if (!reachable.has(n)) {
        reachable.add(n);
        queue.push(n);
      }
    }
  }
  const all = new Set(components.map((c) => c.key));
  const exclusive = new Set();
  for (const k of all) if (!reachable.has(k)) exclusive.add(k);
  return exclusive;
}

function normHashes(hashes) {
  const out = {};
  for (const alg of Object.keys(hashes).sort()) out[alg.toUpperCase()] = hashes[alg].toLowerCase();
  return out;
}

// Full what-if: evaluate candidate under same policy/evidence, then compare to
// a baseline scan. Note: exceptions bound to specific fingerprints/paths are
// NOT carried into what-if evaluation by default (caller may pass carry=true
// for path-stable components; exceptions can never silently cover new risks).
export function evaluateScenario(baseScan, baseManifest, policy, actions, { aliasEvidence = [], evaluatedAt, carryExceptions = [] }) {
  const { candidate, effects } = applyScenario(baseManifest, actions);
  const result = evaluate(candidate, policy, {});
  const candidateScan = {
    scanId: 'plan-scan',
    decision: result.denied ? 'deny' : 'allow',
    evaluatedAt,
    findings: result.findings,
    activeFindings: result.findings
      .filter((f) => !carryExceptions.some((e) => e.ruleId === f.ruleId && e.componentKey === f.component))
      .map((f) => f.findingKey),
    appliedExceptions: [],
  };
  const comparison = compareScans(baseScan, candidateScan);
  return {
    planId: planId({ base: baseScan.scanId, actions, evaluatedAt }),
    actions,
    evaluatedAt,
    effects,
    candidateComponentCount: candidate.components.length,
    candidate,
    candidateScan,
    comparison,
  };
}

export { reachableFrom, directDependencies };
