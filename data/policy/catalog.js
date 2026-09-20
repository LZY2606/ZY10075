// Upgrade catalog used by candidate plans. Candidate data is explicitly part of
// the saved inputs (audit pack catalog section) so plans remain reproducible.
export const upgradeCatalog = new Map([
  [
    'pkg:npm/left-pad',
    {
      versions: {
        '1.3.1': {
          licenses: ['MIT'],
          hashes: [{ alg: 'sha256', value: '3333333333333333333333333333333333333333333333333333333333333333' }],
          sources: [{ kind: 'distribution', url: 'https://registry.npmjs.org/left-pad/-/left-pad-1.3.1.tgz' }]
        }
      }
    }
  ],
  [
    'pkg:npm/lodash',
    {
      versions: {
        '4.17.21': {
          licenses: ['MIT'],
          hashes: [{ alg: 'sha256', value: '4444444444444444444444444444444444444444444444444444444444444444' }],
          sources: [{ kind: 'website', url: 'https://lodash.com' }]
        }
      }
    }
  ],
  [
    'pkg:npm/ms',
    {
      versions: {
        '2.1.3': {
          licenses: ['MIT'],
          hashes: [{ alg: 'sha256', value: '5555555555555555555555555555555555555555555555555555555555555555' }],
          sources: [{ kind: 'distribution', url: 'https://registry.npmjs.org/ms/-/ms-2.1.3.tgz' }]
        }
      }
    }
  ]
]);
