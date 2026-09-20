// Dependency graph over canonical component identities (canonical purls).
// Roots are manifest/root components; depth of a direct dependency is 1.
// A component reached through several routes keeps ONE node but reports ALL
// supporting paths, which the UI renders separately.

import { stableCompare } from './canonical.js';

export function buildGraph(components, edges, rootIds) {
  const nodeById = new Map();
  for (const component of components) nodeById.set(component.id, component);
  const outgoing = new Map();
  const incoming = new Map();
  const nodes = new Set(components.map((component) => component.id));
  for (const id of nodes) {
    outgoing.set(id, []);
    incoming.set(id, []);
  }
  const cleanEdges = [];
  for (const edge of edges) {
    if (!nodes.has(edge.from) || !nodes.has(edge.to)) continue;
    if (edge.from === edge.to) continue;
    cleanEdges.push({ from: edge.from, to: edge.to });
    outgoing.get(edge.from).push(edge.to);
    incoming.get(edge.to).push(edge.from);
  }
  for (const list of outgoing.values()) list.sort(stableCompare);
  for (const list of incoming.values()) list.sort(stableCompare);
  const roots = rootIds.filter((id) => nodes.has(id));
  return { nodeById, outgoing, incoming, nodes, edges: dedupeEdges(cleanEdges), roots };
}

function dedupeEdges(edges) {
  const seen = new Set();
  const out = [];
  for (const edge of edges) {
    const key = edge.from + '\u0000' + edge.to;
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(edge);
  }
  return out.sort((a, b) => stableCompare(a.from + a.to, b.from + b.to));
}

// Shortest depth from any root (roots themselves are depth 0, direct deps 1).
export function shortestDepths(graph) {
  const depth = new Map();
  for (const root of graph.roots) depth.set(root, 0);
  const queue = [...graph.roots];
  while (queue.length) {
    const current = queue.shift();
    const nextDepth = depth.get(current) + 1;
    for (const next of graph.outgoing.get(current) ?? []) {
      if (!depth.has(next) || depth.get(next) > nextDepth) {
        depth.set(next, nextDepth);
        queue.push(next);
      }
    }
  }
  return depth;
}

export function isDirect(graph, id, depths) {
  return graph.roots.some((root) => (graph.outgoing.get(root) ?? []).includes(id)) || depths.get(id) === 1;
}

// Enumerate every simple root -> id path, bounded by maxDepth / maxPaths so a
// pathological cyclic manifest cannot exhaust memory. Paths are returned in a
// stable order (lexicographic by joined node id).
export function allPaths(graph, id, options = {}) {
  const maxDepth = options.maxDepth ?? 32;
  const maxPaths = options.maxPaths ?? 500;
  const results = [];
  const dfs = (node, trail, seen) => {
    if (results.length >= maxPaths) return;
    if (trail.length - 1 > maxDepth) return;
    if (node === id) {
      results.push([...trail]);
      return;
    }
    for (const next of graph.outgoing.get(node) ?? []) {
      if (seen.has(next)) continue;
      seen.add(next);
      dfs(next, [...trail, next], seen);
      seen.delete(next);
    }
  };
  for (const root of [...graph.roots].sort(stableCompare)) {
    dfs(root, [root], new Set([root]));
  }
  results.sort((a, b) => stableCompare(a.join('\u0000'), b.join('\u0000')));
  return results;
}

export function reachableClosure(graph, ids) {
  const reachable = new Set();
  const queue = [...ids];
  while (queue.length) {
    const current = queue.shift();
    for (const next of graph.outgoing.get(current) ?? []) {
      if (!reachable.has(next)) {
        reachable.add(next);
        queue.push(next);
      }
    }
  }
  return reachable;
}

// Candidate overlay for what-if scenarios. Pure: never mutates the original.
//   actions: [{ action: 'remove', id } | { action: 'upgrade', id, toVersion, newHashes?, license? }]
// Upgrade rewrites the id to id@newVersion for every component coordinate
// match: edges are re-pointed, which is how "dependency path changed" becomes
// visible to re-evaluation and exception binding.
export function applyOverlay(graph, actions, catalogByCoordinate = new Map()) {
  const idMap = new Map(); // old id -> current id
  const componentOverrides = new Map(); // current id -> replacement component
  const removed = new Set();
  for (const action of actions) {
    if (action.action === 'remove') {
      removed.add(action.id);
    } else if (action.action === 'upgrade') {
      const coordinate = action.coordinate;
      const newId = coordinate + '@' + action.toVersion;
      idMap.set(action.id, newId);
      const catalogEntry = catalogByCoordinate.get(coordinate);
      const candidate = catalogEntry?.versions?.[action.toVersion] ?? null;
      componentOverrides.set(newId, {
        id: newId,
        coordinate,
        name: action.name,
        ecosystem: action.ecosystem,
        version: action.toVersion,
        licenses: action.license ? [action.license] : candidate?.licenses ?? graph.nodeById.get(action.id)?.licenses ?? [],
        hashes: action.newHashes ?? candidate?.hashes ?? [],
        sources: candidate?.sources ?? graph.nodeById.get(action.id)?.sources ?? [],
        upgradedFrom: action.id
      });
    }
  }
  const remap = (id) => idMap.get(id) ?? id;

  const newComponents = [];
  for (const component of graph.nodeById.values()) {
    if (removed.has(component.id)) continue;
    const mapped = remap(component.id);
    if (componentOverrides.has(mapped)) {
      newComponents.push(componentOverrides.get(mapped));
    } else {
      newComponents.push({ ...component, id: mapped });
    }
  }

  const removedClosure = new Set();
  for (const id of removed) removedClosure.add(id);
  // Removing a node removes only that node; edges to it disappear. Orphaned
  // components that become unreachable are still nodes (matches "delete node").

  const newEdges = [];
  for (const edge of graph.edges) {
    if (removed.has(edge.from) || removed.has(edge.to)) continue;
    newEdges.push({ from: remap(edge.from), to: remap(edge.to) });
  }
  const roots = graph.roots.filter((id) => !removed.has(id)).map(remap);
  return buildGraph(newComponents, newEdges, roots);
}

export function describeOverlayChanges(before, after) {
  const beforeIds = new Set(before.nodeById.keys());
  const afterIds = new Set(after.nodeById.keys());
  const removed = [...beforeIds].filter((id) => !afterIds.has(id)).sort(stableCompare);
  const added = [...afterIds].filter((id) => !beforeIds.has(id)).sort(stableCompare);
  const edgeKey = (edge) => edge.from + '\u0000' + edge.to;
  const beforeEdges = new Set(before.edges.map(edgeKey));
  const afterEdges = new Set(after.edges.map(edgeKey));
  return {
    removedComponents: removed,
    addedComponents: added,
    removedEdges: [...beforeEdges].filter((key) => !afterEdges.has(key)).map((key) => key.split('\u0000')),
    addedEdges: [...afterEdges].filter((key) => !beforeEdges.has(key)).map((key) => key.split('\u0000'))
  };
}
