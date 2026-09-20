// Policy evaluation. Pure and deterministic: given the parsed manifest model,
// the graph, one immutable policy document version, the exception set and an
// explicit effective instant, the result is always identical.
//
// Finding identity is derived from (policy version, rule id, component id), so
// changing a component version (id@x -> id@y) or a rule revision always yields
// a fresh finding that an old exception cannot waive.

import { buildGraph, shortestDepths, allPaths, isDirect } from './graph.js';
import { purlCoordinate, canonicalPurl } from './purl.js';
import { toDnf, evaluateAlternatives, comboSatisfied } from './license.js';
import { isActiveAt } from './time.js';
import { sha256Text, stableCompare } from './canonical.js';

export async function findingId(ruleId, componentId, policyVersion) {
  const digest = await sha256Text([ruleId, componentId, policyVersion].join('\u0000'));
  return 'F-' + digest.slice(0, 12);
}

export function equivalenceClasses(aliases) {
  // Verified alias pairs (parser guarantees shared cryptographic hash plus
  // explicit evidence) define union-find equivalence classes. Nothing else
  // ever merges two identities.
  const parent = new Map();
  const find = (x) => {
    if (!parent.has(x)) parent.set(x, x);
    if (parent.get(x) !== x) parent.set(x, find(parent.get(x)));
    return parent.get(x);
  };
  const union = (a, b) => parent.set(find(a), find(b));
  for (const alias of aliases) union(alias.from, alias.to);
  return { find };
}

function componentTokens(component) {
  // Multiple license entries without an explicit expression are alternatives
  // (SPDX/CycloneDX convention), joined with OR.
  const expression = component.licenses.length ? component.licenses.join(' OR ') : 'NOASSERTION';
  return { expression, alternatives: toDnf(expression) };
}

function hostOf(url) {
  try {
    return new URL(url).hostname.toLowerCase();
  } catch {
    return null;
  }
}

function hostMatches(host, patterns) {
  return patterns.some((pattern) => {
    const p = pattern.toLowerCase();
    return host === p || host.endsWith('.' + p);
  });
}

function scopeMatches(scope, direct) {
  if (!scope || scope === 'any') return true;
  if (scope === 'direct') return direct;
  if (scope === 'transitive') return !direct;
  return true;
}

export async function evaluate(input) {
  const { model, policy, exceptions = [], at, fingerprint, overlay = null, graph: providedGraph } = input;
  const graph = providedGraph ?? buildGraph(model.components, model.edges, model.rootIds);
  const depths = shortestDepths(graph);
  const classes = equivalenceClasses(model.aliases);
  const aliasPeers = (componentId) => {
    const root = classes.find(componentId);
    return [...graph.nodes].filter((id) => classes.find(id) === root);
  };

  const findings = [];
  for (const componentId of [...graph.nodes].sort(stableCompare)) {
    const component = graph.nodeById.get(componentId);
    if (!component) continue;
    if (graph.roots.includes(componentId)) continue;
    const depth = depths.get(componentId);
    if (depth === undefined) continue;
    const direct = isDirect(graph, componentId, depths);
    const coordinate = purlCoordinate(componentId);
    const { expression, alternatives } = componentTokens(component);

    for (const rule of policy.rules) {
      if (!scopeMatches(rule.scope, direct)) continue;
      const evidence = {};
      let triggered = false;

      if (rule.type === 'component.deny') {
        const coordinateMatch = (rule.coordinates ?? []).some((entry) => {
          const entryCoordinate = purlCoordinate(canonicalPurl(entry) ?? entry) ?? entry;
          return aliasPeers(componentId).some((peer) => purlCoordinate(peer) === entryCoordinate);
        });
        const versionOk = rule.versionExact ? component.version === rule.versionExact : true;
        triggered = coordinateMatch && versionOk;
        if (triggered) evidence.coordinate = coordinate;
      } else if (rule.type === 'license.block') {
        const blocked = new Set(rule.licenses);
        const hits = alternatives
          .flat()
          .filter((token) => blocked.has(token))
          .sort(stableCompare);
        triggered = hits.length > 0;
        if (triggered) Object.assign(evidence, { declared: expression, blockedTokens: hits });
      } else if (rule.type === 'license.allow') {
        const result = evaluateAlternatives(expression, 'allowlist', new Set(rule.licenses));
        triggered = !result.satisfied;
        if (triggered) Object.assign(evidence, { declared: expression, alternatives });
      } else if (rule.type === 'source.block') {
        const hits = component.sources
          .map((source) => source.url)
          .filter((url) => hostMatches(hostOf(url), rule.blockedHosts ?? []))
          .sort(stableCompare);
        triggered = hits.length > 0;
        if (triggered) evidence.blockedSources = hits;
      } else if (rule.type === 'source.require') {
        const hasAllowed = component.sources.some((source) => hostMatches(hostOf(source.url), rule.allowedHosts ?? []));
        triggered = !hasAllowed;
        if (triggered) evidence.sources = component.sources.map((source) => source.url).sort(stableCompare);
      } else if (rule.type === 'depth.max') {
        const coordinateFiltered = rule.coordinate ? coordinate === purlCoordinate(rule.coordinate) : true;
        triggered = coordinateFiltered && depth > rule.maxDepth;
        if (triggered) evidence.depth = depth;
      } else if (rule.type === 'license.combo') {
        if (rule.coordinate && coordinate !== purlCoordinate(rule.coordinate)) continue;
        const closureIds = closureOf(graph, componentId);
        const observed = [...closureIds].flatMap((id) => graph.nodeById.get(id)?.licenses ?? []);
        const tokens = new Set();
        for (const license of observed) for (const alt of toDnf(license)) for (const token of alt) tokens.add(token);
        triggered = !comboSatisfied([...tokens], rule.require);
        if (triggered) {
          evidence.required = rule.require;
          evidence.observedTokens = [...tokens].sort(stableCompare);
        }
      }

      if (!triggered) continue;
      const paths = allPaths(graph, componentId);
      findings.push({
        findingId: await findingId(rule.id, componentId, policy.version),
        ruleId: rule.id,
        ruleType: rule.type,
        policyId: policy.policyId,
        policyVersion: policy.version,
        componentId,
        componentName: component.name,
        depth,
        scope: direct ? 'direct' : 'transitive',
        paths,
        message: rule.message ?? rule.id,
        evidence
      });
    }
  }

  findings.sort((a, b) =>
    stableCompare(a.ruleId + a.componentId, b.ruleId + b.componentId)
  );

  const activeExceptions = exceptions.filter((exception) => exception.state === 'approved');
  const decisionAt = at;
  const withWaivers = findings.map((finding) => {
    const matching = activeExceptions.filter((exception) =>
      exceptionMatches(exception, finding, fingerprint, model.aliases, graph, at)
    );
    return matching.length ? { ...finding, waivedBy: matching[0].id, waiver: serializeWaiver(matching[0]) } : finding;
  });
  const open = withWaivers.filter((finding) => !finding.waivedBy);

  return {
    policyId: policy.policyId,
    policyVersion: policy.version,
    fingerprint,
    evaluatedAt: decisionAt,
    conclusion: open.length ? 'REJECT' : 'ALLOW',
    findings: withWaivers,
    openFindingIds: open.map((finding) => finding.findingId),
    waivedCount: withWaivers.length - open.length,
    overlay: overlay ? { actions: overlay.actions } : null
  };
}

function closureOf(graph, componentId) {
  const ids = new Set([componentId]);
  const queue = [componentId];
  while (queue.length) {
    const current = queue.shift();
    for (const next of graph.outgoing.get(current) ?? []) {
      if (!ids.has(next)) {
        ids.add(next);
        queue.push(next);
      }
    }
  }
  ids.delete(componentId);
  return ids;
}

function serializeWaiver(exception) {
  return {
    id: exception.id,
    componentId: exception.componentId,
    ruleId: exception.ruleId,
    policyVersion: exception.policyVersion,
    imageFingerprint: exception.imageFingerprint,
    validFrom: exception.validFrom,
    validUntil: exception.validUntil,
    reason: exception.reason,
    operator: exception.operator
  };
}

export function exceptionMatches(exception, finding, fingerprint, aliases, graph, at) {
  if (exception.policyVersion !== finding.policyVersion) return false;
  if (exception.ruleId !== finding.ruleId) return false;
  if (exception.imageFingerprint !== fingerprint) return false;
  if (!isActiveAt(exception, at)) return false;
  const { find } = equivalenceClasses(aliases);
  const identityOk = find(exception.componentId) === find(finding.componentId);
  if (!identityOk) return false;
  if (exception.boundPaths && exception.boundPaths.length) {
    const bound = exception.boundPaths.map((path) => path.join('\u0000'));
    const actual = new Set(finding.paths.map((path) => path.join('\u0000')));
    if (!bound.some((path) => actual.has(path))) return false;
  }
  return true;
}

// Compare baseline evaluation with a candidate (overlay) evaluation.
export function diffDecisions(baseline, candidate) {
  const byId = (findings) => new Map(findings.map((finding) => [finding.findingId, finding]));
  const baseOpen = new Map(baseline.openFindingIds.map((id) => [id, true]));
  const candidateOpen = new Map(candidate.openFindingIds.map((id) => [id, true]));
  const baseAll = byId(baseline.findings);
  const candAll = byId(candidate.findings);

  const disappeared = [...baseOpen.keys()]
    .filter((id) => !candidateOpen.has(id))
    .map((id) => baseAll.get(id))
    .filter(Boolean);
  const introduced = [...candidateOpen.keys()]
    .filter((id) => !baseOpen.has(id))
    .map((id) => candAll.get(id))
    .filter(Boolean);
  const remaining = [...candidateOpen.keys()].filter((id) => baseOpen.has(id)).map((id) => candAll.get(id)).filter(Boolean);

  return {
    baselineConclusion: baseline.conclusion,
    candidateConclusion: candidate.conclusion,
    disappeared: disappeared.map(slimFinding),
    introduced: introduced.map(slimFinding),
    remaining: remaining.map(slimFinding)
  };
}

function slimFinding(finding) {
  return {
    findingId: finding.findingId,
    ruleId: finding.ruleId,
    componentId: finding.componentId,
    scope: finding.scope,
    depth: finding.depth,
    waivedBy: finding.waivedBy ?? null
  };
}
