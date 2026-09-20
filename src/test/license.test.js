import { describe, it, expect } from 'vitest';
import { toDnf, normalizeExpression, evaluateAlternatives, comboSatisfied } from '../core/license.js';

describe('license expressions', () => {
  it('normalizes ordering of AND clauses', () => {
    expect(normalizeExpression('Apache-2.0 AND MIT')).toBe('Apache-2.0 AND MIT');
    expect(normalizeExpression('MIT AND Apache-2.0')).toBe('Apache-2.0 AND MIT');
  });

  it('distributes OR over AND into DNF alternatives', () => {
    const dnf = toDnf('(MIT OR Apache-2.0) AND BSD-3-Clause');
    expect(dnf).toEqual([
      ['BSD-3-Clause', 'MIT'],
      ['Apache-2.0', 'BSD-3-Clause']
    ]);
  });

  it('treats WITH exceptions as atomic tokens', () => {
    const dnf = toDnf('GPL-2.0-only WITH Classpath-exception-2.0 OR MIT');
    expect(dnf).toEqual([['GPL-2.0-only WITH Classpath-exception-2.0'], ['MIT']]);
  });

  it('blocklist accepts when at least one alternative avoids blocked tokens', () => {
    const blocked = new Set(['GPL-3.0-only']);
    expect(evaluateAlternatives('MIT OR GPL-3.0-only', 'blocklist', blocked).satisfied).toBe(true);
    expect(evaluateAlternatives('MIT AND GPL-3.0-only', 'blocklist', blocked).satisfied).toBe(false);
  });

  it('allowlist requires all tokens of one alternative', () => {
    const allowed = new Set(['MIT', 'Apache-2.0']);
    expect(evaluateAlternatives('MIT OR GPL-3.0-only', 'allowlist', allowed).satisfied).toBe(true);
    expect(evaluateAlternatives('(MIT OR GPL-3.0-only) AND Apache-2.0', 'allowlist', allowed).satisfied).toBe(true);
    expect(evaluateAlternatives('MIT AND GPL-3.0-only', 'allowlist', allowed).satisfied).toBe(false);
  });

  it('evaluates combo rules over observed closure tokens', () => {
    expect(comboSatisfied(['MIT', 'BSD-3-Clause'], '(MIT OR Apache-2.0)')).toBe(true);
    expect(comboSatisfied(['GPL-3.0-only'], 'MIT')).toBe(false);
  });
});
