import { describe, it, expect } from 'vitest';
import { freshStore, request } from './helpers.js';

describe('batch approval atomicity', () => {
  it('applies the whole batch when revisions are current', async () => {
    const store = await freshStore();
    const revision = store.getException('EX-003').revision;
    const res = await request(store, '/api/batch', {
      operator: 'ori.legal',
      at: '2026-09-21T03:00:00Z',
      commands: [
        { op: 'approve', exceptionId: 'EX-003', expectedRevision: revision, reason: 'bulk ok' }
      ]
    }, 'POST');
    expect(res.status).toBe(200);
    expect(store.getException('EX-003').state).toBe('approved');
  });

  it('fails the entire batch and returns the diff when one item was changed', async () => {
    const store = await freshStore();
    const revision = store.getException('EX-003').revision;
    // Another operator acts first.
    await request(store, '/api/exceptions/EX-003/approve', { expectedRevision: revision, reason: 'someone else' }, 'POST');
    const eventsBefore = store.allEvents().length;
    const res = await request(store, '/api/batch', {
      operator: 'ori.legal',
      at: '2026-09-21T03:05:00Z',
      commands: [
        { op: 'approve', exceptionId: 'EX-003', expectedRevision: revision, reason: 'stale bulk' }
      ]
    }, 'POST');
    expect(res.status).toBe(400);
    expect(res.data.error).toBe('BATCH_FAILED');
    expect(res.data.failures[0].code).toBe('STALE_REVISION');
    expect(res.data.failures[0].expected).toBe(revision);
    expect(res.data.failures[0].actual).not.toBe(revision);
    // no extra events from the failed batch
    expect(store.allEvents().length).toBe(eventsBefore);
  });

  it('leaves no visible partial result when a later command in the batch is invalid', async () => {
    const store = await freshStore();
    const res = await request(store, '/api/batch', {
      operator: 'ori.legal',
      at: '2026-09-21T03:00:00Z',
      commands: [
        { op: 'request', exceptionId: 'EX-TMP-9', componentId: 'pkg:npm/ms@2.1.2', ruleId: 'R-DEPTH-3', policyVersion: '2026.09', imageFingerprint: store.getImage('img-shop-api-2026-09').imageFingerprint, validFrom: '2026-09-21T00:00:00Z', validUntil: '2026-12-21T00:00:00Z', reason: 'x' },
        { op: 'approve', exceptionId: 'EX-DOES-NOT-EXIST', expectedRevision: 'E0000' }
      ]
    }, 'POST');
    expect(res.status).toBe(400);
    expect(store.getException('EX-TMP-9')).toBeNull();
  });
});

describe('decision history is append-only', () => {
  it('revocation creates a new event and preserves the approval event', async () => {
    const store = await freshStore();
    const revision = store.getException('EX-001').revision;
    const res = await request(store, '/api/exceptions/EX-001/revoke', { expectedRevision: revision, reason: 'hotfix rolled back' }, 'POST');
    expect(res.status).toBe(200);
    const history = store.exceptionHistory('EX-001').map((event) => event.type);
    expect(history).toContain('exception.requested');
    expect(history).toContain('exception.approved');
    expect(history.at(-1)).toBe('exception.revoked');
    expect(store.getException('EX-001').state).toBe('revoked');
  });
});
