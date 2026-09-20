import { createHash } from 'node:crypto';
import { canonicalize } from './canonical.js';

// Every identifier/derived fact is a SHA-256 over canonical inputs.
// No wall-clock, no randomness => recomputable from saved inputs.
export function sha256Hex(data) {
  return createHash('sha256').update(data).digest('hex');
}

export function hashCanonical(value) {
  return sha256Hex(canonicalize(value));
}

export function hashText(text) {
  return sha256Hex(text);
}

export function shortId(hex) {
  return hex.slice(0, 12);
}
