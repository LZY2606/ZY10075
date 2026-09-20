// Deterministic dependency-path enumeration.
// A path is a sequence of component keys starting at a document root.
// Simple paths only (a component cannot repeat), so cycles terminate.
import { adjacency, rootKeys as rootKeysImpl } from './model.js';
export { rootKeysImpl as rootKeys };

export const MAX_PATH_NODES = 40;

// All simple root->target paths. Returns arrays of keys, deterministically ordered.
export function pathsTo(manifest, targetKey, { includeRootPath = true } = {}) {
  const adj = adjacency(manifest);
  const roots = rootKeysImpl(manifest);
  const results = [];

  if (includeRootPath && roots.includes(targetKey)) {
    results.push([targetKey]);
  }

  // Enumerate with a stack; every stack frame is [node, path, visited].
  for (const root of roots) {
    if (root === targetKey) continue; // handled above
    walk(root, [root], new Set([root]));
  }

  function walk(node, path, visited) {
    if (path.length >= MAX_PATH_NODES) return;
    for (const next of adj.get(node) || []) {
      if (visited.has(next)) continue; // break cycles
      const np = path.concat(next);
      if (next === targetKey) {
        results.push(np);
        continue; // target cannot be revisited (simple path)
      }
      const nv = new Set(visited);
      nv.add(next);
      walk(next, np, nv);
    }
  }

  results.sort(comparePath);
  return results;
}

// Number of dependency edges from the closest root:
// depth(root) = 0, direct dependency = 1, ...
// Minimum across all introducing paths (deterministic given full enumeration).
export function minDepth(manifest, targetKey) {
  const paths = pathsTo(manifest, targetKey);
  if (!paths.length) return null;
  return paths.reduce((m, p) => Math.min(m, p.length - 1), Infinity);
}

// Set of every component reachable from a given node (including itself),
// order independent: BFS with sorted children.
export function reachableFrom(manifest, startKey) {
  const adj = adjacency(manifest);
  const seen = new Set();
  const queue = [startKey];
  seen.add(startKey);
  while (queue.length) {
    const node = queue.shift();
    for (const next of adj.get(node) || []) {
      if (!seen.has(next)) {
        seen.add(next);
        queue.push(next);
      }
    }
  }
  return seen;
}

// Direct dependencies (depth 1 from a node).
export function directDependencies(manifest, key) {
  return adjacency(manifest).get(key) || [];
}

// Components that directly depend on key.
export function directDependents(manifest, key) {
  const adj = adjacency(manifest);
  const out = [];
  for (const c of manifest.components) {
    if ((adj.get(c.key) || []).includes(key)) out.push(c.key);
  }
  return out.sort();
}

export function comparePath(a, b) {
  const len = Math.min(a.length, b.length);
  for (let i = 0; i < len; i++) {
    if (a[i] < b[i]) return -1;
    if (a[i] > b[i]) return 1;
  }
  return a.length - b.length;
}

// Summary used by the UI/API when expanding a denial: one entry per distinct
// introducing path, so the same component brought in several ways is shown
// separately for each path.
export function pathReport(manifest, targetKey) {
  const paths = pathsTo(manifest, targetKey);
  return {
    target: targetKey,
    direct: minDepth(manifest, targetKey) <= 1,
    pathCount: paths.length,
    minDepth: paths.length ? paths[0].length - 1 : null,
    maxDepth: paths.length ? paths[paths.length - 1].length - 1 : null,
    paths,
  };
}
