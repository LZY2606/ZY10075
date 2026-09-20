import { describe, it, expect } from 'vitest';
import {
  parseExpression, canonicalExpression, toDnf,
  exprSelects, exprAllAllowed,
} from '../shared/license.js';

describe('SPDX expression parser', () => {
  it('parses simple ids case-insensitively', () => {
    expect(canonicalExpression('mit')).toBe('MIT');
    expect(canonicalExpression('Apache-2.0')).toBe('APACHE-2.0');
  });

  it('canonicalizes OR with sorted alternatives', () => {
    expect(canonicalExpression('(MIT OR AGPL-3.0-only)')).toBe('(AGPL-3.0-ONLY OR MIT)');
    expect(canonicalExpression('(AGPL-3.0-only OR mit)')).toBe('(AGPL-3.0-ONLY OR MIT)');
  });

  it('canonicalizes WITH exceptions', () => {
    expect(canonicalExpression('GPL-3.0-only WITH Classpath-exception-2.0'))
      .toBe('GPL-3.0-ONLY WITH CLASSPATH-EXCEPTION-2.0');
  });

  it('handles nested AND/OR and is order independent', () => {
    const a = canonicalExpression('Apache-2.0 AND (MIT OR ISC)');
    const b = canonicalExpression('(ISC OR MIT) AND Apache-2.0');
    expect(a).toBe(b);
  });

  it('throws on malformed expressions', () => {
    expect(() => parseExpression('(MIT OR')).toThrow();
    expect(() => parseExpression('MIT OR')).toThrow();
    expect(() => parseExpression('')).toThrow();
  });

  it('expands to deterministic DNF', () => {
    const dnf = toDnf('(MIT OR ISC) AND Apache-2.0');
    expect(dnf).toEqual([
      ['APACHE-2.0', 'ISC'],
      ['APACHE-2.0', 'MIT'],
    ]);
  });
});

describe('policy license matching', () => {
  it('detects a selectable GPL inside an OR expression', () => {
    expect(exprSelects('(MIT OR AGPL-3.0-only)', ['AGPL-3.0-only'])).toBe(true);
    expect(exprSelects('MIT', ['GPL-3.0-only'])).toBe(false);
  });

  it('Classpath-exception GPL still selects GPL base', () => {
    expect(exprSelects('GPL-3.0-only WITH Classpath-exception-2.0', ['GPL-3.0-only'])).toBe(true);
  });

  it('allow-list requires every selectable license allowed', () => {
    expect(exprAllAllowed('(MIT OR Apache-2.0)', ['MIT', 'Apache-2.0'])).toBe(true);
    expect(exprAllAllowed('(MIT OR AGPL-3.0-only)', ['MIT'])).toBe(false);
  });
});
