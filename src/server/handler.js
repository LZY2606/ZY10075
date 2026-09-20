// Framework-free HTTP handler. It speaks the Web Request/Response API so the
// same function is used by the Vite dev plugin and by automated tests (no
// network listener required).

import { Store } from '../core/store.js';
import {
  requestException,
  approveException,
  revokeException,
  runBatch,
  publicException
} from '../core/store.js';
import {
  evaluateImage,
  comparePlan,
  recordScan,
  listScans,
  getScan,
  exportAuditPack,
  verifyPack,
  ingestManifest,
  publicImage
} from './service.js';
import { buildSeed } from './seed.js';

let cachedStore = null;
let seededAt = null;

export async function createStore() {
  const store = new Store();
  store.loadSeed(await buildSeed());
  return store;
}

export async function getStore({ reseed = false } = {}) {
  if (reseed || !cachedStore) {
    cachedStore = await createStore();
    seededAt = '2026-09-21T03:00:00Z';
  }
  return cachedStore;
}

export async function resetStore() {
  cachedStore = null;
  return getStore();
}

function jsonResponse(value, status = 200, headers = {}) {
  return new Response(JSON.stringify(value, null, 2), {
    status,
    headers: { 'content-type': 'application/json; charset=utf-8', ...headers }
  });
}

function errorResponse(error) {
  const status = error.status ?? 400;
  return jsonResponse(
    {
      error: error.code ?? error.message,
      message: error.message,
      ...(error.failures ? { failures: error.failures } : {})
    },
    status
  );
}

async function readBody(request) {
  if (!request.body) return {};
  try {
    return await request.json();
  } catch (error) {
    const err = new Error('Request body must be JSON');
    err.status = 400;
    throw err;
  }
}

export async function handleRequest(request, { store: injectedStore } = {}) {
  const store = injectedStore ?? (await getStore());
  const url = new URL(request.url);
  const path = url.pathname;
  const method = request.method;
  try {
    if (method === 'GET' && path === '/api/health') {
      return jsonResponse({ ok: true, service: 'sbom-policy-guard', demoClock: seededAt });
    }

    if (method === 'GET' && path === '/api/state') {
      return jsonResponse({
        images: store.listImages().map(publicImage),
        policies: [...store.policyByVersion.values()].map((policy) => ({
          policyId: policy.policyId,
          version: policy.version,
          publishedAt: policy.publishedAt,
          ruleCount: policy.rules.length
        })),
        exceptions: store.listExceptions().map(publicException),
        catalog: Object.fromEntries(store.catalogByCoordinate),
        scans: listScans(store),
        demoClock: seededAt
      });
    }

    if (method === 'GET' && path === '/api/images') {
      return jsonResponse({ images: store.listImages().map(publicImage) });
    }

    if (method === 'GET' && path.startsWith('/api/images/') && path.endsWith('/model')) {
      const id = decodeURIComponent(path.slice('/api/images/'.length, -'/model'.length));
      const image = store.getImage(id);
      if (!image) throw notFound('Unknown image: ' + id);
      return jsonResponse({
        image: publicImage(image),
        model: image.model,
        rawManifest: image.rawManifest
      });
    }

    if (method === 'POST' && path === '/api/images') {
      const body = await readBody(request);
      if (!body.id || !body.rawText) throw badRequest('id and rawText are required');
      const record = await ingestManifest(store, body);
      return jsonResponse({ image: record }, 201);
    }

    if (method === 'GET' && path === '/api/policies') {
      return jsonResponse({ policies: [...store.policyByVersion.values()] });
    }

    if (method === 'POST' && path === '/api/evaluate') {
      const body = await readBody(request);
      return jsonResponse(await evaluateImage(store, withAt(body, url)));
    }

    if (method === 'POST' && path === '/api/plans/compare') {
      const body = await readBody(request);
      return jsonResponse(await comparePlan(store, withAt(body, url)));
    }

    if (method === 'POST' && path === '/api/scans') {
      const body = await readBody(request);
      return jsonResponse({ scan: await recordScan(store, withAt(body, url)) }, 201);
    }

    if (method === 'GET' && path === '/api/scans') {
      return jsonResponse({ scans: listScans(store) });
    }

    if (method === 'GET' && path.startsWith('/api/scans/')) {
      const scanId = decodeURIComponent(path.slice('/api/scans/'.length));
      return jsonResponse({ scan: getScan(store, scanId) });
    }

    if (method === 'GET' && path === '/api/exceptions') {
      return jsonResponse({
        exceptions: store.listExceptions().map(publicException),
        events: store.allEvents()
      });
    }

    if (method === 'POST' && path === '/api/exceptions') {
      const body = await readBody(request);
      const record = requestException(store, { ...body, at: body.at ?? url.searchParams.get('at') ?? seededAt });
      return jsonResponse({ exception: publicException(record), event: lastEvent(store) }, 201);
    }

    if (method === 'POST' && path.startsWith('/api/exceptions/') && path.endsWith('/approve')) {
      const id = decodeURIComponent(path.slice('/api/exceptions/'.length, -'/approve'.length));
      const body = await readBody(request);
      const record = approveException(store, {
        exceptionId: id,
        ...body,
        at: body.at ?? seededAt
      });
      return jsonResponse({ exception: publicException(record), event: lastEvent(store) });
    }

    if (method === 'POST' && path.startsWith('/api/exceptions/') && path.endsWith('/revoke')) {
      const id = decodeURIComponent(path.slice('/api/exceptions/'.length, -'/revoke'.length));
      const body = await readBody(request);
      const record = revokeException(store, {
        exceptionId: id,
        ...body,
        at: body.at ?? seededAt
      });
      return jsonResponse({ exception: publicException(record), event: lastEvent(store) });
    }

    if (method === 'GET' && path.startsWith('/api/exceptions/') && path.endsWith('/history')) {
      const id = decodeURIComponent(path.slice('/api/exceptions/'.length, -'/history'.length));
      if (!store.getException(id)) throw notFound('Unknown exception: ' + id);
      return jsonResponse({ exceptionId: id, history: store.exceptionHistory(id) });
    }

    if (method === 'POST' && path === '/api/batch') {
      const body = await readBody(request);
      if (!Array.isArray(body.commands) || !body.commands.length) throw badRequest('commands[] required');
      const result = await runBatch(store, body.commands, {
        at: body.at ?? seededAt,
        operator: body.operator ?? 'batch-operator'
      });
      return jsonResponse(result, 200);
    }

    if (method === 'GET' && path === '/api/events') {
      return jsonResponse({ events: store.allEvents() });
    }

    if (method === 'POST' && path === '/api/audit/export') {
      const body = await readBody(request);
      const pack = await exportAuditPack(store, withAt(body, url));
      return jsonResponse({ pack });
    }

    if (method === 'POST' && path === '/api/audit/verify') {
      const body = await readBody(request);
      const result = await verifyPack(body.pack ?? body);
      return jsonResponse(result, result.ok ? 200 : 422);
    }

    if (method === 'POST' && path === '/api/admin/reseed') {
      await resetStore();
      return jsonResponse({ ok: true });
    }

    return jsonResponse({ error: 'NOT_FOUND', message: 'No route for ' + method + ' ' + path }, 404);
  } catch (error) {
    return errorResponse(error);
  }
}

function withAt(body, url) {
  return { ...body, at: body.at ?? url.searchParams.get('at') ?? seededAt };
}

function lastEvent(store) {
  return store.allEvents().at(-1) ?? null;
}

function notFound(message) {
  const error = new Error(message);
  error.status = 404;
  return error;
}

function badRequest(message) {
  const error = new Error(message);
  error.status = 400;
  return error;
}
