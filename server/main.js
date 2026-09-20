import http from 'node:http';
import { handle } from './api.js';

const PORT = Number(process.env.PORT || 5208);
const HOST = process.env.HOST || '127.0.0.1';

export const server = http.createServer((req, res) => handle(req, res));

if (import.meta.url === `file://${process.argv[1]}`) {
  server.listen(PORT, HOST, () => {
    console.log(`SBOM policy gate API on http://${HOST}:${PORT}`);
  });
}
