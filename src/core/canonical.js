// Deterministic primitives. Everything that ends up hashed or exported goes
// through canonicalJson: object keys are sorted recursively, no whitespace is
// emitted, and numbers are serialized by JSON.stringify (all numbers in this
// system are integers, so there is no float-representation ambiguity).

export function stableCompare(a, b) {
  const sa = String(a);
  const sb = String(b);
  if (sa < sb) return -1;
  if (sa > sb) return 1;
  return 0;
}

export function canonicalJson(value) {
  if (value === null || typeof value !== 'object') {
    return JSON.stringify(value ?? null);
  }
  if (Array.isArray(value)) {
    return '[' + value.map(canonicalJson).join(',') + ']';
  }
  const keys = Object.keys(value).sort(stableCompare);
  const parts = keys.map((key) => JSON.stringify(key) + ':' + canonicalJson(value[key]));
  return '{' + parts.join(',') + '}';
}

export async function sha256Text(text) {
  const { createHash } = await import('node:crypto');
  return createHash('sha256').update(text, 'utf8').digest('hex');
}

export async function sha256Canonical(value) {
  return sha256Text(canonicalJson(value));
}
