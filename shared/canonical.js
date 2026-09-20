// Canonical JSON serialization (RFC 8785-style, simplified):
// - object keys sorted lexicographically by UTF-16 code unit
// - no insignificant whitespace
// - stable number handling (integers vs fixed JSON numbers)
// Deterministic across platforms; used for fingerprints and audit digests.
export function canonicalize(value) {
  if (value === null) return 'null';
  const t = typeof value;
  if (t === 'string') return JSON.stringify(value);
  if (t === 'number' || t === 'boolean') return JSON.stringify(value);
  if (t === 'bigint') return JSON.stringify(value.toString());
  if (Array.isArray(value)) {
    return '[' + value.map((v) => canonicalize(v ?? null)).join(',') + ']';
  }
  if (t === 'object') {
    const keys = Object.keys(value).sort();
    return (
      '{' +
      keys
        .map((k) => JSON.stringify(k) + ':' + canonicalize(value[k] ?? null))
        .join(',') +
      '}'
    );
  }
  // functions / undefined are unsupported in canonical data
  throw new TypeError('cannot canonicalize value of type ' + t);
}

// Code-unit level lexicographic sort (stable across platforms; no locale).
export function sorted(items, keyFn) {
  const arr = [...items];
  arr.sort((a, b) => {
    const ka = keyFn(a);
    const kb = keyFn(b);
    return ka < kb ? -1 : ka > kb ? 1 : 0;
  });
  return arr;
}

// Numeric byte-wise comparison for two hex strings (SHA digests etc.).
export function hexCompare(a, b) {
  return a < b ? -1 : a > b ? 1 : 0;
}
