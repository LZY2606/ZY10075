import { defineConfig } from 'vite';
import { handle } from './server/api.js';

// Vite dev middleware bridges /api/* to the framework-free Node HTTP handler.
function apiPlugin() {
  return {
    name: 'sbom-api',
    configureServer(server) {
      server.middlewares.use((req, res, next) => {
        if (!req.url || !req.url.startsWith('/api/')) return next();
        // Node's http handler expects a raw (req,res) pair; connect's Incoming
        // Message/ServerResponse are compatible.
        handle(req, res).catch((err) => {
          if (!res.headersSent) {
            res.statusCode = 500;
            res.setHeader('content-type', 'application/json');
            res.end(JSON.stringify({ error: err.message }));
          }
        });
      });
    },
  };
}

export default defineConfig({
  root: 'web',
  plugins: [apiPlugin()],
  server: {
    host: '127.0.0.1',
    port: 5208,
    strictPort: true,
  },
  test: {
    root: __dirname,
    environment: 'node',
    include: ['tests/**/*.test.js'],
  },
});
