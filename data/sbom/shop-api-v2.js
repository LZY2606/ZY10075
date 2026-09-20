// Patched image: left-pad 1.3.1 (MIT), lodash 4.17.21, rogue mirror removed.
// New image fingerprint -> v1 exceptions cannot apply.
export const shopApiV2 = {
  bomFormat: 'CycloneDX',
  specVersion: '1.5',
  version: 1,
  metadata: {
    timestamp: '2026-09-15T08:00:00Z',
    component: {
      'bom-ref': 'IMG-shop-api-2026.10',
      type: 'container',
      name: 'registry.internal/shop-api',
      version: '2026.10',
      purl: 'pkg:oci/shop-api?repository_url=registry.internal&tag=2026.10',
      hashes: [{ alg: 'SHA-256', content: 'e5f6a7b8e5f6a7b8e5f6a7b8e5f6a7b8e5f6a7b8e5f6a7b8e5f6a7b8e5f6a7b8' }]
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
      externalReferences: [{ type: 'distribution', url: 'https://registry.npmjs.org/express/-/express-4.19.2.tgz' }]
    },
    {
      'bom-ref': 'npm:lodash:4.17.21',
      type: 'library',
      name: 'lodash',
      version: '4.17.21',
      purl: 'pkg:npm/lodash@4.17.21',
      licenses: [{ license: { id: 'MIT' } }],
      externalReferences: [{ type: 'website', url: 'https://lodash.com' }]
    },
    {
      'bom-ref': 'npm:left-pad:1.3.1',
      type: 'library',
      name: 'left-pad',
      version: '1.3.1',
      purl: 'pkg:npm/left-pad@1.3.1',
      licenses: [{ license: { id: 'MIT' } }],
      hashes: [{ alg: 'SHA-256', content: '3333333333333333333333333333333333333333333333333333333333333333' }],
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
      externalReferences: [{ type: 'distribution', url: 'https://registry.npmjs.org/rogue-source-vendor/-/rogue-1.0.0.tgz' }]
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
    { ref: 'IMG-shop-api-2026.10', dependencies: ['npm:express:4.19.2', 'npm:lodash:4.17.21', 'pypi:left-pad:0.1.4', 'npm:rogue-source-vendor:1.0.0', 'npm:acme-utils:2.0.0', 'npm:@acme/utils:2.0.0'] },
    { ref: 'npm:express:4.19.2', dependencies: ['npm:left-pad:1.3.1', 'npm:send:0.18.0', 'npm:body-parser:1.20.2'] },
    { ref: 'npm:send:0.18.0', dependencies: ['npm:debug:4.3.4', 'npm:ms:2.1.2'] },
    { ref: 'npm:body-parser:1.20.2', dependencies: ['npm:debug:4.3.4', 'npm:ms:2.1.2'] },
    { ref: 'npm:debug:4.3.4', dependencies: [] }
  ]
};
