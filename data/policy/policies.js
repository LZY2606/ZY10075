// Two immutable policy document revisions. Rules are fixed for a given version;
// changing a rule produces a new document version, which invalidates waivers
// pinned to the previous version.
export const policyV1 = {
  policyId: 'org-dependency-policy',
  version: '2026.09',
  publishedAt: '2026-09-01T00:00:00Z',
  rules: [
    {
      id: 'R-DEN-LEFT-PAD-130',
      type: 'component.deny',
      coordinates: ['pkg:npm/left-pad'],
      versionExact: '1.3.0',
      scope: 'any',
      message: 'npm/left-pad 1.3.0 is denied (known vulnerable build)'
    },
    {
      id: 'R-LIC-GPL',
      type: 'license.block',
      licenses: ['GPL-3.0-only', 'GPL-2.0-only', 'AGPL-3.0-only'],
      scope: 'any',
      message: 'Copyleft licenses are not accepted without an exception'
    },
    {
      id: 'R-SRC-UNTRUSTED-MIRROR',
      type: 'source.block',
      blockedHosts: ['malware-mirror.test'],
      scope: 'any',
      message: 'Artifacts referenced from untrusted mirror hosts are blocked'
    },
    {
      id: 'R-DEPTH-3',
      type: 'depth.max',
      maxDepth: 3,
      scope: 'transitive',
      message: 'Dependency depth must not exceed 3 from the image root'
    },
    {
      id: 'R-COMBO-MIT-CHAIN',
      type: 'license.combo',
      coordinate: 'pkg:npm/express',
      require: 'MIT',
      scope: 'any',
      message: 'The express dependency closure must contain an MIT-licensed component'
    }
  ]
};

export const policyV2 = {
  policyId: 'org-dependency-policy',
  version: '2026.10',
  publishedAt: '2026-10-01T00:00:00Z',
  rules: [
    {
      id: 'R-DEN-LEFT-PAD-130',
      type: 'component.deny',
      coordinates: ['pkg:npm/left-pad'],
      versionExact: '1.3.0',
      scope: 'any',
      message: 'npm/left-pad 1.3.0 is denied (known vulnerable build)'
    },
    {
      id: 'R-LIC-GPL',
      type: 'license.block',
      licenses: ['GPL-3.0-only', 'GPL-2.0-only', 'AGPL-3.0-only', 'LGPL-2.1-only'],
      scope: 'any',
      message: 'Copyleft licenses are not accepted without an exception (LGPL added in 2026.10)'
    },
    {
      id: 'R-SRC-UNTRUSTED-MIRROR',
      type: 'source.block',
      blockedHosts: ['malware-mirror.test', 'shadow-registry.test'],
      scope: 'any',
      message: 'Artifacts referenced from untrusted mirror hosts are blocked'
    },
    {
      id: 'R-DEPTH-3',
      type: 'depth.max',
      maxDepth: 3,
      scope: 'transitive',
      message: 'Dependency depth must not exceed 3 from the image root'
    },
    {
      id: 'R-COMBO-MIT-CHAIN',
      type: 'license.combo',
      coordinate: 'pkg:npm/express',
      require: 'MIT',
      scope: 'any',
      message: 'The express dependency closure must contain an MIT-licensed component'
    }
  ]
};
