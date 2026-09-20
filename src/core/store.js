// Event-sourced store. Every human decision appends an immutable event; state
// is a deterministic projection. Revocation appends an event, it never deletes
// history. Event ids are assigned by the caller (seed) or monotonically from a
// revision counter (runtime), and batch operations validate every item before
// appending anything — a failed batch leaves zero visible partial results.

import { instantMillis } from './time.js';
import { canonicalJson, sha256Text } from './canonical.js';

export class Store {
  constructor(options = {}) {
    this.policyByVersion = new Map(options.policies ?? []);
    this.images = new Map(); // id -> image record
    this.scans = new Map(); // scanId -> scan
    this.events = [];
    this.exceptionRevisions = new Map(); // exceptionId -> latest revision
    this.exceptions = new Map(); // exceptionId -> projected state
    this.catalogByCoordinate = new Map();
    this.sequence = 0;
  }

  loadSeed(seed) {
    for (const [version, policy] of seed.policies ?? []) this.policyByVersion.set(version, policy);
    for (const image of seed.images ?? []) this.images.set(image.id, image);
    for (const [coordinate, catalog] of seed.catalogs ?? []) this.catalogByCoordinate.set(coordinate, catalog);
    for (const event of seed.events ?? []) {
      this.sequence = Math.max(this.sequence, event.sequence);
      this.apply(event);
      this.events.push(event);
    }
  }

  getPolicy(version) {
    return this.policyByVersion.get(version) ?? null;
  }
  latestPolicyVersion() {
    return [...this.policyByVersion.keys()].sort((a, b) => (a < b ? 1 : a > b ? -1 : 0))[0] ?? null;
  }
  getImage(id) {
    return this.images.get(id) ?? null;
  }
  listImages() {
    return [...this.images.values()].sort((a, b) => (a.id < b.id ? -1 : 1));
  }
  getException(id) {
    return this.exceptions.get(id) ?? null;
  }
  listExceptions() {
    return [...this.exceptions.values()];
  }
  exceptionHistory(id) {
    return this.events.filter((event) => event.payload?.exceptionId === id).map(slimEvent);
  }
  allEvents() {
    return this.events.map(slimEvent);
  }

  nextEventId() {
    this.sequence += 1;
    return 'E' + String(this.sequence).padStart(4, '0');
  }

  append(type, payload, meta = {}) {
    const event = {
      eventId: meta.eventId ?? this.nextEventId(),
      sequence: meta.sequence ?? this.sequence,
      type,
      payload,
      at: meta.at ?? payload?.at ?? '1970-01-01T00:00:00Z',
      operator: meta.operator ?? payload?.operator ?? 'system'
    };
    this.apply(event);
    this.events.push(event);
    return event;
  }

  apply(event) {
    const payload = event.payload ?? {};
    switch (event.type) {
      case 'exception.requested': {
        const record = {
          id: payload.exceptionId,
          state: 'requested',
          revision: event.eventId,
          componentId: payload.componentId,
          ruleId: payload.ruleId,
          policyVersion: payload.policyVersion,
          imageFingerprint: payload.imageFingerprint,
          boundPaths: payload.boundPaths ?? null,
          validFrom: payload.validFrom,
          validUntil: payload.validUntil,
          reason: payload.reason,
          operator: event.operator,
          createdAt: event.at
        };
        this.exceptions.set(record.id, record);
        this.exceptionRevisions.set(record.id, event.eventId);
        break;
      }
      case 'exception.approved': {
        const record = requireException(this, payload.exceptionId);
        const before = record.revision;
        Object.assign(record, {
          state: 'approved',
          revision: event.eventId,
          validFrom: payload.validFrom ?? record.validFrom,
          validUntil: payload.validUntil ?? record.validUntil,
          reason: payload.reason ?? record.reason,
          operator: event.operator,
          approvedAt: event.at
        });
        record.lastTransition = { from: before, to: event.eventId, at: event.at };
        this.exceptionRevisions.set(record.id, event.eventId);
        break;
      }
      case 'exception.revoked': {
        const record = requireException(this, payload.exceptionId);
        const before = record.revision;
        Object.assign(record, {
          state: 'revoked',
          revision: event.eventId,
          reason: payload.reason,
          operator: event.operator,
          revokedAt: event.at
        });
        record.lastTransition = { from: before, to: event.eventId, at: event.at };
        this.exceptionRevisions.set(record.id, event.eventId);
        break;
      }
      case 'scan.recorded': {
        this.scans.set(payload.scan.scanId, payload.scan);
        break;
      }
      default:
        break;
    }
  }
}

function requireException(store, id) {
  const record = store.exceptions.get(id);
  if (!record) throw new Error('Unknown exception: ' + id);
  return record;
}

function slimEvent(event) {
  return {
    eventId: event.eventId,
    sequence: event.sequence,
    type: event.type,
    at: event.at,
    operator: event.operator,
    payload: event.payload
  };
}

export function newExceptionId(store) {
  let n = store.exceptions.size + 1;
  let id;
  do {
    id = 'EX-' + String(n).padStart(3, '0');
    n += 1;
  } while (store.exceptions.has(id));
  return id;
}

// ---- Single-item commands -------------------------------------------------

export function requestException(store, input) {
  const id = input.exceptionId ?? newExceptionId(store);
  if (store.exceptions.has(id)) throw new Error('Exception already exists: ' + id);
  validateExceptionFields(input);
  store.append(
    'exception.requested',
    {
      exceptionId: id,
      componentId: input.componentId,
      ruleId: input.ruleId,
      policyVersion: input.policyVersion,
      imageFingerprint: input.imageFingerprint,
      boundPaths: input.boundPaths ?? null,
      validFrom: input.validFrom,
      validUntil: input.validUntil,
      reason: input.reason,
      at: input.at
    },
    { at: input.at, operator: input.operator }
  );
  return store.getException(id);
}

export function approveException(store, input) {
  const record = store.getException(input.exceptionId);
  if (!record) throw notFound(input.exceptionId);
  if (input.expectedRevision && record.revision !== input.expectedRevision) {
    throw conflictError(record, input.expectedRevision);
  }
  store.append(
    'exception.approved',
    {
      exceptionId: input.exceptionId,
      validFrom: input.validFrom ?? record.validFrom,
      validUntil: input.validUntil ?? record.validUntil,
      reason: input.reason ?? record.reason,
      at: input.at
    },
    { at: input.at, operator: input.operator }
  );
  return store.getException(input.exceptionId);
}

export function revokeException(store, input) {
  const record = store.getException(input.exceptionId);
  if (!record) throw notFound(input.exceptionId);
  if (input.expectedRevision && record.revision !== input.expectedRevision) {
    throw conflictError(record, input.expectedRevision);
  }
  store.append(
    'exception.revoked',
    { exceptionId: input.exceptionId, reason: input.reason, at: input.at },
    { at: input.at, operator: input.operator }
  );
  return store.getException(input.exceptionId);
}

// ---- Batch: validate everything first, then commit ------------------------

export function runBatch(store, commands, meta) {
  const results = [];
  // Phase 1: validate against a scratch projection so concurrent/duplicate
  // operations inside the same batch are detected without touching the store.
  const scratch = scratchState(store);
  for (let index = 0; index < commands.length; index += 1) {
    const command = commands[index];
    try {
      validateBatchCommand(scratch, command, index);
      results.push({ index, exceptionId: command.exceptionId, ok: true });
    } catch (error) {
      const failures = buildFailures(commands, scratch, index, error);
      const errorOut = new Error('BATCH_FAILED');
      errorOut.code = 'BATCH_FAILED';
      errorOut.failures = failures;
      throw errorOut;
    }
  }
  // Phase 2: commit for real. Re-check expectedRevision against the live store
  // immediately before append; any mismatch aborts the entire batch.
  for (const command of commands) {
    const live = store.getException(command.exceptionId);
    if (command.op !== 'request' && command.expectedRevision && live.revision !== command.expectedRevision) {
      const errorOut = new Error('BATCH_FAILED');
      errorOut.code = 'BATCH_FAILED';
      errorOut.failures = [
        {
          exceptionId: command.exceptionId,
          expected: command.expectedRevision,
          actual: live.revision,
          current: publicException(live)
        }
      ];
      throw errorOut;
    }
  }
  for (const command of commands) {
    if (command.op === 'approve') approveException(store, { ...command, at: meta.at, operator: meta.operator });
    else if (command.op === 'revoke') revokeException(store, { ...command, at: meta.at, operator: meta.operator });
    else if (command.op === 'request') requestException(store, { ...command, at: meta.at, operator: meta.operator });
  }
  return { ok: true, applied: results, batch: true };
}

function scratchState(store) {
  const revisions = new Map();
  const states = new Map();
  for (const [id, record] of store.exceptions) {
    revisions.set(id, record.revision);
    states.set(id, record.state);
  }
  const requested = new Set();
  return {
    revisionOf: (id) => (requested.has(id) ? 'pending-batch' : revisions.get(id)),
    stateOf: (id) => states.get(id) ?? (requested.has(id) ? 'requested' : null),
    exists: (id) => revisions.has(id) || requested.has(id),
    markRequested: (id) => requested.add(id),
    setRevision: (id, revision, state) => {
      requested.delete(id);
      revisions.set(id, revision);
      states.set(id, state);
    }
  };
}

function validateBatchCommand(scratch, command, index) {
  if (!command || !command.op) throw new Error('Missing op at index ' + index);
  if (command.op === 'request') {
    if (scratch.exists(command.exceptionId) || !command.exceptionId) {
      validateExceptionFields(command);
      if (scratch.exists(command.exceptionId)) throw new Error('Exception already exists: ' + command.exceptionId);
    }
    validateExceptionFields(command);
    scratch.markRequested(command.exceptionId);
    return;
  }
  const revision = scratch.revisionOf(command.exceptionId);
  if (!revision) throw notFound(command.exceptionId);
  if (command.expectedRevision && revision !== command.expectedRevision) {
    throw new Error('STALE_REVISION');
  }
  scratch.setRevision(command.exceptionId, 'batch-' + index, command.op === 'approve' ? 'approved' : 'revoked');
}

function buildFailures(commands, scratch, firstIndex, firstError) {
  const failures = [];
  for (let index = firstIndex; index < commands.length; index += 1) {
    const command = commands[index];
    if (command.op === 'request') {
      failures.push({ index, exceptionId: command.exceptionId, code: 'NOT_REACHED' });
      continue;
    }
    const revision = scratch.revisionOf(command.exceptionId);
    if (command.expectedRevision && revision !== command.expectedRevision) {
      failures.push({
        index,
        exceptionId: command.exceptionId,
        code: 'STALE_REVISION',
        expected: command.expectedRevision,
        actual: revision ?? null
      });
    }
  }
  if (!failures.length) failures.push({ index: firstIndex, code: firstError.code ?? firstError.message });
  return failures;
}

function validateExceptionFields(input) {
  for (const field of ['componentId', 'ruleId', 'policyVersion', 'imageFingerprint', 'validFrom', 'validUntil', 'reason', 'operator', 'at']) {
    if (input[field] === undefined || input[field] === null || input[field] === '') {
      throw new Error('Missing exception field: ' + field);
    }
  }
  if (instantMillis(input.validFrom) >= instantMillis(input.validUntil)) {
    throw new Error('validFrom must be strictly before validUntil');
  }
}

function notFound(id) {
  const error = new Error('Unknown exception: ' + id);
  error.code = 'NOT_FOUND';
  return error;
}

function conflictError(record, expected) {
  const error = new Error('STALE_REVISION');
  error.code = 'STALE_REVISION';
  error.failures = [
    { exceptionId: record.id, expected, actual: record.revision, current: publicException(record) }
  ];
  return error;
}

export function publicException(record) {
  return {
    id: record.id,
    state: record.state,
    revision: record.revision,
    componentId: record.componentId,
    ruleId: record.ruleId,
    policyVersion: record.policyVersion,
    imageFingerprint: record.imageFingerprint,
    boundPaths: record.boundPaths,
    validFrom: record.validFrom,
    validUntil: record.validUntil,
    reason: record.reason,
    operator: record.operator
  };
}

export async function eventChainDigest(events) {
  return sha256Text(canonicalJson(events.map(slimEvent)));
}
