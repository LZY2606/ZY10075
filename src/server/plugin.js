// Vite dev plugin: mounts the same Web-API handler used in tests at /api.
import { handleRequest } from './handler.js';

export function apiPlugin() {
  return {
    name: 'sbom-policy-api',
    configureServer(server) {
      server.middlewares.use(async (req, res, next) => {
        if (!req.url?.startsWith('/api')) {
          next();
          return;
        }
        const body = await readRawBody(req);
        const request = new Request('http://127.0.0.1' + req.url, {
          method: req.method,
          headers: req.headers,
          body: body && body.length ? body : undefined
        });
        const response = await handleRequest(request);
        res.statusCode = response.status;
        response.headers.forEach((value, key) => res.setHeader(key, value));
        const buffer = Buffer.from(await response.arrayBuffer());
        res.end(buffer);
      });
    }
  };
}

function readRawBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    req.on('data', (chunk) => chunks.push(chunk));
    req.on('end', () => resolve(Buffer.concat(chunks)));
    req.on('error', reject);
  });
}
