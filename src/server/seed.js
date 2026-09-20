// Deterministic demo seed. Fingerprints are computed from the manifests at seed
// time (same inputs -> same values on every machine); every human decision is
// an event with reason, operator and fixed timestamp, and two historical scans
// show which exception revision was in force at the time.

import { canonicalJson } from '../core/canonical.js';
import { parseManifest } from '../core/sbom.js';
import { computeFingerprints } from '../core/fingerprint.js';
import { evaluate } from '../core/policy.js';
import { policyV1, policyV2 } from '../../data/policy/policies.js';
import { upgradeCatalog } from '../../data/policy/catalog.js';
import { shopApiV1 } from '../../data/sbom/shop-api-v1.js';
import { shopApiV2 } from '../../data/sbom/shop-api-v2.js';
import { sampleSpdx } from '../../data/sbom/sample-spdx.js';

function event(type, sequence, at, operator, payload) {
  return { eventId: 'E' + String(sequence).padStart(4, '0'), sequence, type, at, operator, payload };
}

export async function buildSeed() {
  const manifests = [
    {
      id: 'img-shop-api-2026-09',
      tag: '2026.09',
      label: 'registry.internal/shop-api:2026.09 (CycloneDX)',
      doc: shopApiV1
    },
    {
      id: 'img-shop-api-2026-10',
      tag: '2026.10',
      label: 'registry.internal/shop-api:2026.10 (CycloneDX, patched)',
      doc: shopApiV2
    },
    {
      id: 'img-shop-api-spdx',
      tag: '2026.09-spdx',
      label: 'registry.internal/shop-api:2026.09-spdx (SPDX 2.3)',
      doc: sampleSpdx
    }
  ];

  const images = [];
  const models = new Map();
  for (const manifest of manifests) {
    const rawText = canonicalJson(manifest.doc);
    const model = parseManifest(manifest.doc);
    const fingerprints = await computeFingerprints(rawText, model);
    const record = {
      id: manifest.id,
      label: manifest.label,
      tag: manifest.tag,
      format: manifest.doc.bomFormat === 'CycloneDX' ? 'CycloneDX' : 'SPDX',
      rawManifest: rawText,
      model,
      ...fingerprints,
      submittedAt: '2026-09-0' + (images.length + 1) + 'T00:00:00Z'
    };
    images.push(record);
    models.set(manifest.id, record);
  }

  const v1 = images[0];
  const v2 = images[1];

  const leftPadPath = (await evaluate({
    model: v1.model,
    policy: policyV1,
    exceptions: [],
    at: '2026-09-02T00:00:00Z',
    fingerprint: v1.imageFingerprint
  })).findings.find((finding) => finding.ruleId === 'R-DEN-LEFT-PAD-130');

  const gplFinding = (await evaluate({
    model: v1.model,
    policy: policyV1,
    exceptions: [],
    at: '2026-09-02T00:00:00Z',
    fingerprint: v1.imageFingerprint
  })).findings.find((finding) => finding.componentId === 'pkg:npm/left-pad@1.3.0' && finding.ruleId === 'R-LIC-GPL');

  // Event chain (order is part of the deterministic timeline).
  const events = [];
  let seq = 0;
  const push = (...args) => {
    seq += 1;
    events.push(event(...[args[0], seq, ...args.slice(1)]));
  };

  // EX-002: requested + approved 2026-09-03, expired 2026-09-20 (boundary demo).
  push('exception.requested', '2026-09-03T09:12:00Z', 'ana.sato', {
    exceptionId: 'EX-002',
    componentId: 'pkg:npm/left-pad@1.3.0',
    ruleId: 'R-LIC-GPL',
    policyVersion: '2026.09',
    imageFingerprint: v1.imageFingerprint,
    boundPaths: gplFinding.paths,
    validFrom: '2026-09-03T00:00:00Z',
    validUntil: '2026-09-20T00:00:00Z',
    reason: 'GPL component isolated in a build-time helper; legal approval LP-41 pending replacement',
    at: '2026-09-03T09:12:00Z'
  });
  push('exception.approved', '2026-09-03T14:05:00Z', 'ori.legal', {
    exceptionId: 'EX-002',
    validFrom: '2026-09-03T00:00:00Z',
    validUntil: '2026-09-20T00:00:00Z',
    reason: 'Time-boxed approval; replacement must land before 2026-09-20 UTC',
    at: '2026-09-03T14:05:00Z'
  });

  const earlyEval = await evaluate({
    model: v1.model,
    policy: policyV1,
    exceptions: [
      {
        id: 'EX-002',
        state: 'approved',
        componentId: 'pkg:npm/left-pad@1.3.0',
        ruleId: 'R-LIC-GPL',
        policyVersion: '2026.09',
        imageFingerprint: v1.imageFingerprint,
        boundPaths: gplFinding.paths,
        validFrom: '2026-09-03T00:00:00Z',
        validUntil: '2026-09-20T00:00:00Z',
        reason: 'Time-boxed approval; replacement must land before 2026-09-20 UTC',
        operator: 'ori.legal'
      }
    ],
    at: '2026-09-10T00:00:00Z',
    fingerprint: v1.imageFingerprint
  });
  push('scan.recorded', '2026-09-10T00:00:00Z', 'scanner-bot', {
    scan: {
      scanId: 'SCN-20260910-01',
      imageId: v1.id,
      imageFingerprint: v1.imageFingerprint,
      manifestSha256: v1.manifestSha256,
      policyId: policyV1.policyId,
      policyVersion: policyV1.version,
      evaluatedAt: '2026-09-10T00:00:00Z',
      conclusion: earlyEval.conclusion,
      result: earlyEval,
      appliedExceptions: ['EX-002']
    }
  });

  // EX-001: requested 2026-09-11, approved 2026-09-12, valid through 2026-12-31 23:59:59+09:00.
  push('exception.requested', '2026-09-11T10:30:00Z', 'kenji.ito', {
    exceptionId: 'EX-001',
    componentId: 'pkg:npm/left-pad@1.3.0',
    ruleId: 'R-DEN-LEFT-PAD-130',
    policyVersion: '2026.09',
    imageFingerprint: v1.imageFingerprint,
    boundPaths: leftPadPath.paths,
    validFrom: '2026-09-12T00:00:00Z',
    validUntil: '2026-12-31T23:59:59+09:00',
    reason: 'Emergency hotfix image: vulnerable build path unreachable at runtime, tracked by INC-77',
    at: '2026-09-11T10:30:00Z'
  });
  push('exception.approved', '2026-09-12T02:15:00Z', 'ori.legal', {
    exceptionId: 'EX-001',
    validFrom: '2026-09-12T00:00:00Z',
    validUntil: '2026-12-31T23:59:59+09:00',
    reason: 'Approved for this exact image fingerprint and dependency path only',
    at: '2026-09-12T02:15:00Z'
  });

  const approvedExceptions = [
    {
      id: 'EX-002',
      state: 'approved',
      componentId: 'pkg:npm/left-pad@1.3.0',
      ruleId: 'R-LIC-GPL',
      policyVersion: '2026.09',
      imageFingerprint: v1.imageFingerprint,
      boundPaths: gplFinding.paths,
      validFrom: '2026-09-03T00:00:00Z',
      validUntil: '2026-09-20T00:00:00Z',
      reason: 'Time-boxed approval',
      operator: 'ori.legal'
    },
    {
      id: 'EX-001',
      state: 'approved',
      componentId: 'pkg:npm/left-pad@1.3.0',
      ruleId: 'R-DEN-LEFT-PAD-130',
      policyVersion: '2026.09',
      imageFingerprint: v1.imageFingerprint,
      boundPaths: leftPadPath.paths,
      validFrom: '2026-09-12T00:00:00Z',
      validUntil: '2026-12-31T23:59:59+09:00',
      reason: 'Approved for this exact image fingerprint and dependency path only',
      operator: 'ori.legal'
    }
  ];
  const currentEval = await evaluate({
    model: v1.model,
    policy: policyV1,
    exceptions: approvedExceptions,
    at: '2026-09-21T03:00:00Z',
    fingerprint: v1.imageFingerprint
  });
  push('scan.recorded', '2026-09-21T03:00:00Z', 'scanner-bot', {
    scan: {
      scanId: 'SCN-20260921-01',
      imageId: v1.id,
      imageFingerprint: v1.imageFingerprint,
      manifestSha256: v1.manifestSha256,
      policyId: policyV1.policyId,
      policyVersion: policyV1.version,
      evaluatedAt: '2026-09-21T03:00:00Z',
      conclusion: currentEval.conclusion,
      result: currentEval,
      appliedExceptions: ['EX-001']
    }
  });

  // EX-003: pending request awaiting security review.
  push('exception.requested', '2026-09-18T07:45:00Z', 'maria.dev', {
    exceptionId: 'EX-003',
    componentId: 'pkg:npm/rogue-source-vendor@1.0.0',
    ruleId: 'R-SRC-UNTRUSTED-MIRROR',
    policyVersion: '2026.09',
    imageFingerprint: v1.imageFingerprint,
    boundPaths: null,
    validFrom: '2026-09-18T00:00:00Z',
    validUntil: '2026-10-18T00:00:00Z',
    reason: 'Mirror reference is stale metadata; actual artifact fetched from npmjs',
    at: '2026-09-18T07:45:00Z'
  });

  // EX-004: approved then revoked (history retained as two separate events).
  push('exception.requested', '2026-09-05T11:00:00Z', 'kenji.ito', {
    exceptionId: 'EX-004',
    componentId: 'pkg:npm/ms@2.1.2',
    ruleId: 'R-DEPTH-3',
    policyVersion: '2026.09',
    imageFingerprint: v1.imageFingerprint,
    boundPaths: null,
    validFrom: '2026-09-05T00:00:00Z',
    validUntil: '2026-11-05T00:00:00Z',
    reason: 'Transitive ms at depth 4; refactor scheduled',
    at: '2026-09-05T11:00:00Z'
  });
  push('exception.approved', '2026-09-05T12:30:00Z', 'ori.legal', {
    exceptionId: 'EX-004',
    validFrom: '2026-09-05T00:00:00Z',
    validUntil: '2026-11-05T00:00:00Z',
    reason: 'Approved pending tree flattening',
    at: '2026-09-05T12:30:00Z'
  });
  push('exception.revoked', '2026-09-17T06:20:00Z', 'ori.legal', {
    exceptionId: 'EX-004',
    reason: 'Revoked: flattening not delivered and another deep chain was found in review',
    at: '2026-09-17T06:20:00Z'
  });

  return {
    policies: [
      ['2026.09', policyV1],
      ['2026.10', policyV2]
    ],
    catalogs: [...upgradeCatalog.entries()],
    images,
    events
  };
}
