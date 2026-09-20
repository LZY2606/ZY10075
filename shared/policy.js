// Policy documents and deterministic evaluation.
//
// Policy:
// { policyId, version, rules: [
//   { id, mode: 'deny'|'allow', type, ...params }
// ]}
//
// Rule types:
//  license
//    { licenses: [SPDX-id...], match: 'any-selected'|'all-must-allow',
//      scope: 'all'|'direct'|'transitive' }
//  hash
//    { algorithm, digests: [hex...] }
//  provenance
//    { requireSupplier: bool, allowedRegistries: [host suffix...],
//      blockedSuppliers: [substring...] }
//  depth
//    { maxDepth: int }
import { componentLicenseInfo, exprSelects, exprAllAllowed } from './license.js';
import { pathsTo, minDepth } from './paths.js';

export function normalizePolicy(p) {
  if (!p || !p.policyId) throw new Error('policy requires policyId');
  if (!p.version) throw new Error('policy requires version');
  return {
    policyId: p.policyId,
    version: p.version,
    rules: (p.rules || []).map(normalizeRule),
  };
}

function normalizeRule(r) {
  const base = {
    id: r.id,
    mode: r.mode === 'allow' ? 'allow' : 'deny',
    type: r.type,
    description: r.description || '',
  };
  switch (r.type) {
    case 'license':
      return {
        ...base,
        licenses: (r.licenses || []).map((x) => x.toUpperCase()).sort(),
        match: r.match === 'all-must-allow' ? 'all-must-allow' : 'any-selected',
        scope: r.scope === 'direct' || r.scope === 'transitive' ? r.scope : 'all',
      };
    case 'hash':
      return {
        ...base,
        algorithm: String(r.algorithm || 'SHA-256').toUpperCase(),
        digests: (r.digests || []).map((x) => x.toLowerCase()).sort(),
      };
    case 'provenance':
      return {
        ...base,
        requireSupplier: !!r.requireSupplier,
        allowedRegistries: (r.allowedRegistries || []).map((x) => x.toLowerCase()).sort(),
        blockedSuppliers: (r.blockedSuppliers || []).map((x) => x.toLowerCase()).sort(),
      };
    case 'depth':
      return { ...base, maxDepth: Number(r.maxDepth) };
    default:
      throw new Error(`unknown policy rule type: ${r.type}`);
  }
}

// Evaluate manifest under policy. Bind fingerprint and evaluatedAt are recorded
// but do not change the results (results depend only on manifest+policy+groups).
export function evaluate(manifest, policy, { equivalenceGroups = [] } = {}) {
  const pol = typeof policy.rules[0] === 'object' && policy.rules[0].mode ? policy : normalizePolicy(policy);
  const findings = [];
  const rulesById = new Map(pol.rules.map((r) => [r.id, r]));

  for (const component of manifest.components) {
    const depth = minDepth(manifest, component.key);
    for (const rule of pol.rules) {
      const hit = checkRule(rule, component, manifest, depth);
      if (hit) {
        findings.push(makeFinding(rule, component, manifest, hit));
      }
    }
  }

  findings.sort(compareFinding);
  return {
    policyId: pol.policyId,
    policyVersion: pol.version,
    ruleIds: pol.rules.map((r) => r.id),
    findings,
    denied: findings.some((f) => f.severity === 'deny'),
    equivalenceGroups,
  };
}

function checkRule(rule, component, manifest, depth) {
  switch (rule.type) {
    case 'license':
      return checkLicense(rule, component, depth);
    case 'hash':
      return checkHash(rule, component);
    case 'provenance':
      // The container image itself is the subject, not a sourced artifact.
      if (component.ecosystem === 'container') return null;
      return checkProvenance(rule, component);
    case 'depth':
      return checkDepth(rule, component, manifest, depth);
    default:
      return null;
  }
}

function inScope(scope, depth) {
  if (scope === 'direct') return depth !== null && depth <= 1;
  if (scope === 'transitive') return depth !== null && depth > 1;
  return depth !== null;
}

function checkLicense(rule, component, depth) {
  if (!inScope(rule.scope, depth)) return null;
  const info = componentLicenseInfo(component);
  if (!info.expression) return null;
  if (rule.match === 'any-selected' && rule.mode === 'deny') {
    const hit = exprSelects(info.expression, rule.licenses);
    if (hit === true) {
      return {
        reason: `license selects a denied license (${rule.licenses.join(', ')})`,
        license: info.expression,
        scope: depth <= 1 ? 'direct' : 'transitive',
        depth,
      };
    }
    if (hit === null) {
      return { reason: 'unparseable license expression', license: info.rawExpression, scope: depth <= 1 ? 'direct' : 'transitive', depth, unparseable: true };
    }
    return null;
  }
  if (rule.match === 'all-must-allow' && rule.mode === 'allow') {
    const allowed = exprAllAllowed(info.expression, rule.licenses);
    if (allowed === false) {
      return {
        reason: `license not fully within allow-list (${rule.licenses.join(', ')})`,
        license: info.expression,
        scope: depth <= 1 ? 'direct' : 'transitive',
        depth,
      };
    }
    if (allowed === null) {
      return { reason: 'unparseable license expression', license: info.rawExpression, scope: depth <= 1 ? 'direct' : 'transitive', depth, unparseable: true };
    }
  }
  return null;
}

function checkHash(rule, component) {
  const actual = component.hashes && component.hashes[rule.algorithm];
  if (actual && rule.digests.includes(actual)) {
    return { reason: `component hash matches ${rule.algorithm} denylist`, digest: actual };
  }
  return null;
}

function checkProvenance(rule, component) {
  if (rule.requireSupplier && !component.supplier) {
    return { reason: 'component has no declared supplier' };
  }
  if (component.supplier) {
    const s = component.supplier.toLowerCase();
    for (const blocked of rule.blockedSuppliers) {
      if (blocked && s.includes(blocked)) {
        return { reason: `supplier "${component.supplier}" is blocked`, supplier: component.supplier };
      }
    }
  }
  if (rule.allowedRegistries.length) {
    const loc = component.downloadLocation;
    if (!loc) return { reason: 'component has no download location' };
    const host = hostOf(loc);
    if (!host || !rule.allowedRegistries.some((suffix) => hostMatches(host, suffix))) {
      return { reason: `download registry "${host || loc}" not in allowed list`, registry: host || loc };
    }
  }
  return null;
}

function hostOf(url) {
  try {
    return new URL(url).host.toLowerCase();
  } catch {
    return null;
  }
}

function hostMatches(host, suffix) {
  return host === suffix || host.endsWith('.' + suffix);
}

function checkDepth(rule, component, manifest, depth) {
  if (depth === null) return null;
  if (depth > rule.maxDepth) {
    return { reason: `dependency depth ${depth} exceeds maximum ${rule.maxDepth}`, depth, maxDepth: rule.maxDepth };
  }
  return null;
}

function makeFinding(rule, component, manifest, hit) {
  // Attach every supporting path so the UI can expand a denial into the full
  // set of introducing paths (multiple paths => multiple path entries).
  const paths = ['license', 'depth', 'provenance'].includes(rule.type)
    ? pathsTo(manifest, component.key)
    : pathsTo(manifest, component.key);
  return {
    findingKey: findingKey(rule, component, hit),
    ruleId: rule.id,
    ruleType: rule.type,
    severity: rule.mode === 'allow' ? 'deny' : 'deny', // allow-list violation also denies
    mode: rule.mode,
    component: component.key,
    coordinate: shortCoord(component),
    ecosystem: component.ecosystem,
    paths,
    pathCount: paths.length,
    depth: hit.depth ?? (paths.length ? paths[0].length - 1 : null),
    ...hit,
  };
}

function findingKey(rule, component, hit) {
  const parts = [rule.id, component.key];
  if (hit.digest) parts.push(hit.digest);
  if (hit.license) parts.push(hit.license);
  if (hit.reason) parts.push(hit.reason);
  return parts.join('|');
}

function shortCoord(c) {
  const g = c.group ? c.group + '/' : '';
  return `${c.ecosystem}:${g}${c.name}@${c.version}`;
}

function compareFinding(a, b) {
  if (a.findingKey < b.findingKey) return -1;
  if (a.findingKey > b.findingKey) return 1;
  return 0;
}

// Determine whether an exception covers a finding. Checks identity binding,
// rule version, image fingerprint, and validity window (instant semantics
// fixed: [notBefore, notAfter], boundaries inclusive).
export function exceptionCovers(finding, exception, ctx) {
  if (exception.status !== 'approved') return false;
  if (exception.ruleId !== finding.ruleId) return false;
  if (exception.policyId !== ctx.policyId || exception.policyVersion !== ctx.policyVersion) return false;
  if (exception.componentKey !== finding.component) return false;
  if (ctx.bindFingerprint !== exception.bindFingerprint) return false;
  const at = Date.parse(ctx.evaluatedAt);
  if (!(at >= Date.parse(exception.notBefore) && at <= Date.parse(exception.notAfter))) return false;
  // License/hash exceptions may narrow the specific value they excuse.
  if (finding.license && exception.license && finding.license !== exception.license) return false;
  if (finding.digest && exception.digest && finding.digest !== exception.digest) return false;
  // The dependency path must still exist under the exception's recorded path
  // prefix: a changed path invalidates the exception.
  if (exception.pathKey && !pathMatches(finding.paths, exception.pathKey)) return false;
  return true;
}

// pathKey is the exact introducing path (array joined). Coverage requires at
// least one current finding path to equal it (same introducing route).
function pathMatches(paths, pathKey) {
  return paths.some((p) => p.join('>') === pathKey);
}

export function pathKeyOf(path) {
  return path.join('>');
}
