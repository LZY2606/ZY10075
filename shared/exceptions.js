// Exception lifecycle and validation.
// An exception binds FIVE things and cannot silently survive change:
//   1. component coordinate (componentKey)
//   2. rule + rule version (ruleId, policyId, policyVersion)
//   3. image fingerprint (bindFingerprint)
//   4. validity window with explicit timezone (notBefore/notAfter)
//   5. introducing path (pathKey) — a changed path invalidates it
import { canonicalize } from './canonical.js';
import { hashText } from './id.js';
import { pathKeyOf } from './policy.js';

export const STATUSES = ['pending', 'approved', 'rejected', 'revoked'];

export function exceptionId(input) {
  return (
    'exc_' +
    hashText(
      canonicalize({
        componentKey: input.componentKey,
        ruleId: input.ruleId,
        policyId: input.policyId,
        policyVersion: input.policyVersion,
        bindFingerprint: input.bindFingerprint,
        pathKey: input.pathKey || null,
        license: input.license || null,
        digest: input.digest || null,
        requestedBy: input.requestedBy || null,
        reason: input.reason || '',
      }),
    ).slice(0, 16)
  );
}

export function validateExceptionInput(input, { manifestsByFingerprint = new Map() } = {}) {
  const errors = [];
  must(input.componentKey, 'componentKey required', errors);
  must(input.ruleId, 'ruleId required', errors);
  must(input.policyId, 'policyId required', errors);
  must(input.policyVersion, 'policyVersion required', errors);
  must(input.bindFingerprint, 'bindFingerprint required (image digest or manifest fingerprint)', errors);
  must(input.reason && input.reason.trim(), 'reason required', errors);
  must(input.requestedBy, 'requestedBy required', errors);
  const nb = Date.parse(input.notBefore);
  const na = Date.parse(input.notAfter);
  if (Number.isNaN(nb)) errors.push('notBefore must be ISO-8601 with explicit timezone');
  if (Number.isNaN(na)) errors.push('notAfter must be ISO-8601 with explicit timezone');
  if (!Number.isNaN(nb) && !Number.isNaN(na) && nb > na) errors.push('notBefore must be <= notAfter');
  if (input.pathKey !== undefined && input.pathKey !== null && typeof input.pathKey !== 'string') {
    errors.push('pathKey must be a string');
  }
  return errors;
}

function must(cond, msg, errors) {
  if (!cond) errors.push(msg);
}

export function createException(input) {
  const errors = validateExceptionInput(input);
  if (errors.length) throw new Error('invalid exception: ' + errors.join('; '));
  return {
    exceptionId: exceptionId(input),
    version: 1,
    status: 'pending',
    componentKey: input.componentKey,
    ruleId: input.ruleId,
    policyId: input.policyId,
    policyVersion: input.policyVersion,
    bindFingerprint: input.bindFingerprint,
    pathKey: input.pathKey || null,
    license: input.license || null,
    digest: input.digest || null,
    notBefore: input.notBefore,
    notAfter: input.notAfter,
    reason: input.reason,
    requestedBy: input.requestedBy,
    createdAt: input.createdAt, // explicit, required
  };
}

// Decision application with optimistic concurrency: the caller must present
// the version they saw. Version increments on each state change.
export function applyDecision(exception, { decision, actor, reason, at, expectedVersion }) {
  if (!Number.isInteger(expectedVersion) || exception.version !== expectedVersion) {
    const err = new Error('version conflict');
    err.code = 'VERSION_CONFLICT';
    err.conflict = {
      exceptionId: exception.exceptionId,
      expected: expectedVersion,
      actual: exception.version,
      current: publicView(exception),
    };
    throw err;
  }
  if (!['approve', 'reject', 'revoke'].includes(decision)) throw new Error('unknown decision');
  if (decision === 'revoke' && exception.status !== 'approved') {
    throw new Error('only approved exceptions can be revoked');
  }
  if ((decision === 'approve' || decision === 'reject') && exception.status !== 'pending') {
    throw new Error('only pending exceptions can be approved or rejected');
  }
  if (!actor) throw new Error('actor required');
  if (!reason || !reason.trim()) throw new Error('decision reason required');
  if (Number.isNaN(Date.parse(at))) throw new Error('decision instant must be ISO-8601');

  const nextStatus = decision === 'approve' ? 'approved' : decision === 'reject' ? 'rejected' : 'revoked';
  const next = {
    ...exception,
    version: exception.version + 1,
    status: nextStatus,
  };
  const event = {
    type: decision === 'approve' ? 'exception.approved' : decision === 'reject' ? 'exception.rejected' : 'exception.revoked',
    at,
    actor,
    reason,
    exceptionId: exception.exceptionId,
    fromVersion: exception.version,
    toVersion: exception.version + 1,
    fromStatus: exception.status,
    toStatus: nextStatus,
  };
  return { exception: next, event };
}

export function publicView(e) {
  return { ...e };
}

export { pathKeyOf };
