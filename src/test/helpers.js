import { Store } from '../core/store.js';
import { buildSeed } from '../server/seed.js';
import { handleRequest, resetStore } from '../server/handler.js';

export async function freshStore() {
  const store = new Store();
  store.loadSeed(await buildSeed());
  return store;
}

export async function request(store, path, body, method = 'GET', init = {}) {
  const at = init.at ?? '2026-09-21T03:00:00Z';
  const url = 'http://127.0.0.1' + path + (method === 'GET' ? (path.includes('?') ? '&' : '?') + 'at=' + encodeURIComponent(at) : '');
  const response = await handleRequest(
    new Request(url, {
      method,
      headers: { 'content-type': 'application/json' },
      body: body ? JSON.stringify(body) : undefined
    }),
    { store }
  );
  const data = await response.json();
  return { status: response.status, data };
}

export function findFinding(result, ruleId, componentId) {
  return result.findings.find(
    (finding) => finding.ruleId === ruleId && (componentId ? finding.componentId === componentId : true)
  );
}

export { resetStore };
