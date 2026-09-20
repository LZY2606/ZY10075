import { defineConfig } from 'vite';
import { fileURLToPath } from 'node:url';
import { apiPlugin } from './src/server/plugin.js';

export default defineConfig({
  root: fileURLToPath(new URL('.', import.meta.url)),
  plugins: [apiPlugin()],
  test: {
    environment: 'node',
    include: ['src/test/**/*.test.js'],
    testTimeout: 15000
  }
});
