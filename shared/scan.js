// A scan binds: manifest fingerprint + policy version + alias evidence version
// + evaluated-at instant. Every output is recomputable from those inputs.
import { canonicalize } from './canonical.js';
import { hashCanonical } from './id.js';
import { buildEquivalence } from './aliases.js';
import { bindFingerprint } from './fingerprint.js';
import { evaluate, exceptionCovers, pathKeyOf } from './policy.js';

export function evaluateScan({
  manifest,
  fingerprint,
  policy,
  aliasEvidence = [],
  exceptions = [],
  evaluatedAt,
}) {
  if (!evaluatedAt || Number.isNaN(Date.parse(evaluatedAt))) {
    throw new Error('evaluatedAt must be an explicit ISO-8601 instant with timezone');
  }
  const evidenceVersion = evidenceHash(aliasEvidence);
  const equivalence = buildEquivalence([manifest], aliasEvidence);
  const result = evaluate(manifest, policy, { equivalenceGroups: equivalence.groups });

  const ctx = {
    policyId: policy.policyId,
    policyVersion: policy.version,
    bindFingerprint: bindFingerprint(fingerprint),
    evaluatedAt,
  };

  const applied = [];
  const unmatchedExceptions = [];
  for (const exc of exceptions) {
    const covers = result.findings.find((f) => exceptionCovers(f, exc, ctx));
    if (covers) {
      applied.push({
        exceptionId: exc.exceptionId,
        version: exc.version,
        findingKey: covers.findingKey,
        ruleId: exc.ruleId,
        componentKey: exc.componentKey,
        pathKey: exc.pathKey || null,
      });
    } else if (exc.status === 'approved' && exc.bindFingerprint === ctx.bindFingerprint) {
      unmatchedExceptions.push({
        exceptionId: exc.exceptionId,
        version: exc.version,
        reason: explainMismatch(exc, result, ctx),
      });
    }
  }

  const coveredKeys = new Set(applied.map((a) => a.findingKey));
  const activeFindings = result.findings.filter((f) => !coveredKeys.has(f.findingKey));

  const decision = activeFindings.length ? 'deny' : 'allow';

  return {
    scanId: scanId({
      fingerprint: fingerprint.manifestFingerprint,
      policyId: policy.policyId,
      policyVersion: policy.version,
      evidenceVersion,
      evaluatedAt,
    }),
    decision,
    evaluatedAt,
    bindFingerprint: ctx.bindFingerprint,
    policy: { policyId: policy.policyId, version: policy.version },
    evidenceVersion,
    findings: result.findings,
    activeFindings: activeFindings.map((f) => f.findingKey),
    appliedExceptions: sortApplied(applied),
    unmatchedExceptions: unmatchedExceptions.sort((a, b) => (a.exceptionId < b.exceptionId ? -1 : 1)),
    equivalenceGroups: equivalence.groups,
    rejectedEvidence: equivalence.rejected,
  };
}

export function evidenceHash(aliasEvidence) {
  return hashCanonical((aliasEvidence || []).map(stripTransient));
}

function stripTransient(ev) {
  const { id, ...rest } = ev;
  return rest;
}

export function scanId(parts) {
  return 'scan_' + hashCanonical(parts).slice(0, 20);
}

function sortApplied(list) {
  return [...list].sort((a, b) => {
    const ka = `${a.exceptionId}|${a.findingKey}`;
    const kb = `${b.exceptionId}|${b.findingKey}`;
    return ka < kb ? -1 : ka > kb ? 1 : 0;
  });
}

function explainMismatch(exc, result, ctx) {
  if (exc.policyId !== ctx.policyId || exc.policyVersion !== ctx.policyVersion) {
    return 'policy id/version differs from the evaluated policy';
  }
  const sameRuleComponent = result.findings.find(
    (f) => f.ruleId === exc.ruleId && f.component === exc.componentKey,
  );
  if (!sameRuleComponent) return 'bound component no longer triggers the bound rule (path/content changed)';
  const at = Date.parse(ctx.evaluatedAt);
  if (at < Date.parse(exc.notBefore)) return 'exception not yet valid';
  if (at > Date.parse(exc.notAfter)) return 'exception expired';
  if (exc.pathKey && !sameRuleComponent.paths.some((p) => pathKeyOf(p) === exc.pathKey)) {
    return 'dependency path changed; bound introducing path no longer exists';
  }
  return 'exception does not match current finding';
}
