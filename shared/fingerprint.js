import { canonicalize } from './canonical.js';
import { hashCanonical, hashText, sha256Hex } from './id.js';

// Fingerprint of an SBOM submission:
//   rawSha256      — integrity of the exact bytes saved on disk (audit)
//   modelSha256    — canonical model hash: same logical SBOM in CDX or SPDX
//                    yields the same model hash (format-independent)
//   imageDigest    — container image digest from the document metadata
// Exceptions and evaluations bind to imageDigest when present, else to
// manifestFingerprint (the combined digest) so an unsigned document is still
// bound to its exact content.
export function manifestFingerprint(manifest, rawText) {
  const rawSha256 = sha256Hex(rawText);
  const model = modelHashInput(manifest);
  const modelSha256 = hashCanonical(model);
  const imageDigest = (manifest.image && manifest.image.digest) || null;
  const combined = hashText([rawSha256, modelSha256, imageDigest || ''].join('\n'));
  return { rawSha256, modelSha256, imageDigest, manifestFingerprint: combined };
}

export function modelHashInput(manifest) {
  return {
    image: {
      repository: manifest.image.repository || null,
      digest: manifest.image.digest || null,
      tag: manifest.image.tag || null,
    },
    components: manifest.components.map((c) => ({
      k: c.key,
      p: c.purl,
      h: c.hashes,
      l: c.licenses.map((l) => ({ e: l.expression, r: l.refs })),
      s: c.supplier,
      d: c.downloadLocation,
      x: c.externalRefs.map((r) => ({ t: r.type, l: r.locator })),
    })),
    edges: manifest.edges.map((e) => ({ f: e.from, t: e.to, k: e.kind })),
  };
}

// The token exceptions/evaluations actually bind to: prefer the immutable
// image digest; fall back to combined manifest fingerprint.
export function bindFingerprint(fp) {
  return fp.imageDigest || fp.manifestFingerprint;
}
