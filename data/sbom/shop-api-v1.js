// CycloneDX 1.5 fixture. Deterministic byte text is derived with JSON.stringify
// in src/server/seed.js, so re-runs hash identically.
export const shopApiV1 = {
  bomFormat: 'CycloneDX',
  specVersion: '1.5',
  version: 1,
  metadata: {
    timestamp: '2026-09-01T08:00:00Z',
    component: {
      'bom-ref': 'IMG-shop-api-2026.09',
      type: 'container',
      name: 'registry.internal/shop-api',
      version: '2026.09',
      purl: 'pkg:oci/shop-api?repository_url=registry.internal&tag=2026.09',
      hashes: [{ alg: 'SHA-256', content: 'a1b2c3d4a1b2c3d4a1b2c3d4a1b2c3d4a1b2c3d4a1b2c3d4a1b2c3d4a1b2c3d4' }]
    }
  },
  components: [
    {
      'bom-ref': 'npm:express:4.19.2',
      type: 'library',
      name: 'express',
      version: '4.19.2',
      purl: 'pkg:npm/express@4.19.2',
      licenses: [{ license: { id: 'MIT' } }],
      hashes: [{ alg: 'SHA-512', content: '11111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111' }],
      externalReferences: [{ type: 'distribution', url: 'https://registry.npmjs.org/express/-/express-4.19.2.tgz' }]
    },
    {
      'bom-ref': 'npm:lodash:4.17.20',
      type: 'library',
      name: 'lodash',
      version: '4.17.20',
      purl: 'pkg:npm/lodash@4.17.20',
      licenses: [{ license: { id: 'MIT' } }],
      externalReferences: [{ type: 'website', url: 'https://lodash.com' }]
    },
    {
      'bom-ref': 'npm:left-pad:1.3.0',
      type: 'library',
      name: 'left-pad',
      version: '1.3.0',
      purl: 'pkg:npm/left-pad@1.3.0',
      licenses: [{ license: { id: 'GPL-3.0-only' } }],
      hashes: [{ alg: 'SHA-256', content: '2222222222222222222222222222222222222222222222222222222222222222' }],
      externalReferences: [{ type: 'vcs', url: 'https://github.com/example/left-pad' }]
    },
    {
      'bom-ref': 'pypi:left-pad:0.1.4',
      type: 'library',
      name: 'left-pad',
      version: '0.1.4',
      purl: 'pkg:pypi/left-pad@0.1.4',
      licenses: [{ license: { id: 'MIT' } }]
    },
    {
      'bom-ref': 'npm:send:0.18.0',
      type: 'library',
      name: 'send',
      version: '0.18.0',
      purl: 'pkg:npm/send@0.18.0',
      licenses: [{ license: { id: 'MIT' } }]
    },
    {
      'bom-ref': 'npm:body-parser:1.20.2',
      type: 'library',
      name: 'body-parser',
      version: '1.20.2',
      purl: 'pkg:npm/body-parser@1.20.2',
      licenses: [{ license: { id: 'MIT' } }]
    },
    {
      'bom-ref': 'npm:debug:4.3.4',
      type: 'library',
      name: 'debug',
      version: '4.3.4',
      purl: 'pkg:npm/debug@4.3.4',
      licenses: [{ license: { id: 'MIT' } }]
    },
    {
      'bom-ref': 'npm:ms:2.1.2',
      type: 'library',
      name: 'ms',
      version: '2.1.2',
      purl: 'pkg:npm/ms@2.1.2',
      licenses: [{ license: { id: 'MIT' } }]
    },
    {
      'bom-ref': 'npm:rogue-source-vendor:1.0.0',
      type: 'library',
      name: 'rogue-source-vendor',
      version: '1.0.0',
      purl: 'pkg:npm/rogue-source-vendor@1.0.0',
      licenses: [{ license: { id: 'MIT' } }],
      externalReferences: [
        { type: 'distribution', url: 'https://registry.npmjs.org/rogue-source-vendor/-/rogue-1.0.0.tgz' },
        { type: 'distribution', url: 'http://malware-mirror.test/dist/rogue-source-vendor-1.0.0.tgz' }
      ]
    },
    {
      'bom-ref': 'npm:acme-utils:2.0.0',
      type: 'library',
      name: 'acme-utils',
      version: '2.0.0',
      purl: 'pkg:npm/acme-utils@2.0.0',
      licenses: [{ license: { id: 'Apache-2.0' } }],
      hashes: [{ alg: 'SHA-256', content: 'abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234' }],
      properties: [{ name: 'sbomguard:aliasOf', value: 'npm:@acme/utils:2.0.0' }]
    },
    {
      'bom-ref': 'npm:@acme/utils:2.0.0',
      type: 'library',
      group: '@acme',
      name: 'utils',
      version: '2.0.0',
      purl: 'pkg:npm/%40acme/utils@2.0.0',
      licenses: [{ license: { id: 'Apache-2.0' } }],
      hashes: [{ alg: 'SHA-256', content: 'abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234' }]
    }
  ],
  dependencies: [
    { ref: 'IMG-shop-api-2026.09', dependencies: ['npm:express:4.19.2', 'npm:lodash:4.17.20', 'pypi:left-pad:0.1.4', 'npm:rogue-source-vendor:1.0.0', 'npm:acme-utils:2.0.0', 'npm:@acme/utils:2.0.0'] },
    { ref: 'npm:express:4.19.2', dependencies: ['npm:left-pad:1.3.0', 'npm:send:0.18.0', 'npm:body-parser:1.20.2'] },
    { ref: 'npm:send:0.18.0', dependencies: ['npm:debug:4.3.4'] },
    { ref: 'npm:body-parser:1.20.2', dependencies: ['npm:debug:4.3.4'] },
    { ref: 'npm:debug:4.3.4', dependencies: ['npm:ms:2.1.2'] }
  ]
};
