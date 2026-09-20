// Time semantics. Effective time is always an explicit RFC 3339 string; core
// evaluation never reads the wall clock.
//
// Exception validity is the half-open interval [validFrom, validUntil):
// an exception is active at validFrom itself and EXPIRED exactly at validUntil.
// Pinning the boundary here is deliberate and covered by tests (see
// src/test/time.test.js), including instant values expressed in other zones
// (e.g. 2026-12-31T23:59:59+09:00 is one minute before the UTC day boundary).

export function instantMillis(value) {
  if (value instanceof Date) return value.getTime();
  const millis = Date.parse(value);
  if (Number.isNaN(millis)) throw new Error('Invalid RFC 3339 instant: ' + value);
  return millis;
}

export function instantEqual(a, b) {
  return instantMillis(a) === instantMillis(b);
}

export function isActiveAt(exception, at) {
  const atMillis = instantMillis(at);
  return instantMillis(exception.validFrom) <= atMillis && atMillis < instantMillis(exception.validUntil);
}

export function compareInstants(a, b) {
  return instantMillis(a) - instantMillis(b);
}
