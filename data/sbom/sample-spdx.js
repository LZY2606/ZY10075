// SPDX 2.3 JSON fixture exercising the second ingestion path.
export const sampleSpdx = {
  spdxVersion: 'SPDX-2.3',
  dataLicense: 'CC0-1.0',
  SPDXID: 'SPDXRef-DOCUMENT',
  name: 'shop-api-spdx-2026.09',
  documentNamespace: 'https://internal.example/spdxdocs/shop-api-2026-09',
  creationInfo: {
    created: '2026-09-02T00:00:00Z',
    creators: ['Tool: sbom-exporter-3']
  },
  packages: [
    {
      SPDXID: 'SPDXRef-Image',
      name: 'registry.internal/shop-api:2026.09-spdx',
      versionInfo: '2026.09',
      downloadLocation: 'NOASSERTION',
      licenseConcluded: 'NOASSERTION',
      externalRefs: [
        { referenceCategory: 'PACKAGE-MANAGER', referenceType: 'purl', referenceLocator: 'pkg:oci/shop-api?repository_url=registry.internal&tag=2026.09-spdx' }
      ]
    },
    {
      SPDXID: 'SPDXRef-Package-express',
      name: 'express',
      versionInfo: '4.19.2',
      downloadLocation: 'https://registry.npmjs.org/express/-/express-4.19.2.tgz',
      licenseConcluded: 'MIT',
      checksums: [{ algorithm: 'SHA256', checksumValue: '1111111111111111111111111111111111111111111111111111111111111111' }],
      externalRefs: [
        { referenceCategory: 'PACKAGE-MANAGER', referenceType: 'purl', referenceLocator: 'pkg:npm/express@4.19.2' }
      ]
    },
    {
      SPDXID: 'SPDXRef-Package-left-pad',
      name: 'left-pad',
      versionInfo: '1.3.0',
      downloadLocation: 'https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz',
      licenseConcluded: 'GPL-3.0-only',
      externalRefs: [
        { referenceCategory: 'PACKAGE-MANAGER', referenceType: 'purl', referenceLocator: 'pkg:npm/left-pad@1.3.0' }
      ]
    },
    {
      SPDXID: 'SPDXRef-Package-left-pad-py',
      name: 'left-pad',
      versionInfo: '0.1.4',
      downloadLocation: 'https://files.pythonhosted.org/packages/source/l/left-pad/left-pad-0.1.4.tar.gz',
      licenseConcluded: 'MIT',
      externalRefs: [
        { referenceCategory: 'PACKAGE-MANAGER', referenceType: 'purl', referenceLocator: 'pkg:pypi/left-pad@0.1.4' }
      ]
    }
  ],
  relationships: [
    { spdxElementId: 'SPDXRef-DOCUMENT', relationshipType: 'DESCRIBES', relatedSpdxElement: 'SPDXRef-Image' },
    { spdxElementId: 'SPDXRef-Image', relationshipType: 'DEPENDS_ON', relatedSpdxElement: 'SPDXRef-Package-express' },
    { spdxElementId: 'SPDXRef-Image', relationshipType: 'DEPENDS_ON', relatedSpdxElement: 'SPDXRef-Package-left-pad-py' },
    { spdxElementId: 'SPDXRef-Package-express', relationshipType: 'DEPENDS_ON', relatedSpdxElement: 'SPDXRef-Package-left-pad' }
  ]
};
