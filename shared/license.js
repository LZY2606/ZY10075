// SPDX license expressions (subset of the SPDX v2.3 expression grammar):
//   expr  := term (OR term | AND term)*
//   term  := '(' expr ')' | ident [WITH ident]
// Case-insensitive keywords/license ids; canonical form upper-cases ids,
// keeps WITH exceptions, and fully parenthesizes with sorted AND operands so
// equivalent inputs compare equal.
const TOKEN_RE = /\(\)|[A-Za-z0-9.\-+_:]+/g;

export function tokenize(text) {
  const toks = [];
  const re = /[A-Za-z0-9.+_:-]+|[()]/g;
  let m;
  while ((m = re.exec(text)) !== null) {
    const t = m[0];
    if (t === '(' || t === ')') toks.push({ type: t });
    else toks.push({ type: 'word', value: t });
  }
  return toks;
}

class Parser {
  constructor(tokens) {
    this.t = tokens;
    this.i = 0;
  }
  peek() {
    return this.t[this.i];
  }
  next() {
    return this.t[this.i++];
  }
  parse() {
    const node = this.parseOr();
    if (this.i !== this.t.length) throw new Error('unexpected token in license expression');
    return node;
  }
  parseOr() {
    let left = this.parseAnd();
    for (;;) {
      const t = this.peek();
      if (t && t.type === 'word' && t.value.toUpperCase() === 'OR') {
        this.next();
        const right = this.parseAnd();
        left = { type: 'OR', children: flatten(left, 'OR').concat(flatten(right, 'OR')) };
      } else return left;
    }
  }
  parseAnd() {
    let left = this.parseTerm();
    for (;;) {
      const t = this.peek();
      if (t && t.type === 'word' && t.value.toUpperCase() === 'AND') {
        this.next();
        const right = this.parseTerm();
        left = { type: 'AND', children: flatten(left, 'AND').concat(flatten(right, 'AND')) };
      } else return left;
    }
  }
  parseTerm() {
    const t = this.next();
    if (!t) throw new Error('unexpected end of license expression');
    if (t.type === '(') {
      const node = this.parseOr();
      const close = this.next();
      if (!close || close.type !== ')') throw new Error('missing closing parenthesis');
      return node;
    }
    if (t.type !== 'word') throw new Error('expected license identifier');
    const upper = t.value.toUpperCase();
    if (upper === 'AND' || upper === 'OR' || upper === 'WITH') {
      throw new Error('unexpected keyword ' + upper);
    }
    let node = { type: 'LICENSE', id: upper };
    const w = this.peek();
    if (w && w.type === 'word' && w.value.toUpperCase() === 'WITH') {
      this.next();
      const exc = this.next();
      if (!exc || exc.type !== 'word') throw new Error('WITH requires exception id');
      node = { type: 'WITH', license: upper, exception: exc.value.toUpperCase() };
    }
    return node;
  }
}

function flatten(node, type) {
  return node.type === type ? node.children : [node];
}

export function parseExpression(text) {
  const tokens = tokenize(text);
  if (!tokens.length) throw new Error('empty license expression');
  return new Parser(tokens).parse();
}

// Canonical string. AND operands are sorted; OR keeps author order semantically
// irrelevant but canonicalizes to sorted order too (OR is a set of alternatives).
export function canonicalExpression(node) {
  const n = typeof node === 'string' ? parseExpression(node) : node;
  return render(sortNode(n));
}

function sortNode(node) {
  if (node.type === 'LICENSE' || node.type === 'WITH') return node;
  const children = node.children.map(sortNode);
  children.sort((a, b) => {
    const ra = render(a);
    const rb = render(b);
    return ra < rb ? -1 : ra > rb ? 1 : 0;
  });
  return { type: node.type, children };
}

function render(node) {
  if (node.type === 'LICENSE') return node.id;
  if (node.type === 'WITH') return `${node.license} WITH ${node.exception}`;
  return '(' + node.children.map(render).join(` ${node.type} `) + ')';
}

// DNF: array of alternatives, each alternative is an array of leaf strings.
export function toDnf(node) {
  const n = typeof node === 'string' ? parseExpression(node) : node;
  const dnf = expand(n);
  // de-duplicate alternatives deterministically
  const seen = new Set();
  const out = [];
  for (const alt of dnf) {
    const leaves = [...new Set(alt.map(leafText))].sort();
    const sig = leaves.join('\u0000');
    if (!seen.has(sig)) {
      seen.add(sig);
      out.push(leaves);
    }
  }
  out.sort((a, b) => a.join('\u0000') < b.join('\u0000') ? -1 : a.join('\u0000') > b.join('\u0000') ? 1 : 0);
  return out;
}

function leafText(node) {
  if (node.type === 'LICENSE') return node.id;
  if (node.type === 'WITH') return `${node.license} WITH ${node.exception}`;
  throw new Error('unexpected operator in DNF leaf');
}

function expand(node) {
  if (node.type === 'LICENSE') return [[node]];
  if (node.type === 'WITH') return [[node]];
  if (node.type === 'OR') return node.children.flatMap(expand);
  if (node.type === 'AND') {
    let combos = [[]];
    for (const child of node.children) {
      const childAlts = expand(child);
      const next = [];
      for (const acc of combos) {
        for (const alt of childAlts) next.push(acc.concat(alt));
      }
      combos = next;
    }
    return combos;
  }
  throw new Error('unknown node type ' + node.type);
}

// deny: expression is satisfied if ANY license id in denyIds is selectable
// (present in at least one DNF alternative => the consumer can choose GPL).
// Also catches "GPL-3.0-only WITH Classpath-exception-2.0" as GPL base.
export function exprSelects(expression, denyIds) {
  const deny = new Set(denyIds.map((d) => d.toUpperCase()));
  const alts = safeDnf(expression);
  if (!alts) return null;
  return alts.some((leaves) => leaves.some((leaf) => deny.has(leaf) || deny.has(baseId(leaf))));
}

// allow: selectable licenses must ALL be within the allowed set; an
// "X OR Y" is allowed if every alternative leaf is allowed.
export function exprAllAllowed(expression, allowIds) {
  const allow = new Set(allowIds.map((d) => d.toUpperCase()));
  const alts = safeDnf(expression);
  if (!alts) return null;
  return alts.every((leaves) => leaves.every((leaf) => allow.has(leaf)));
}

function safeDnf(expression) {
  try {
    return toDnf(expression);
  } catch {
    return null;
  }
}

function baseId(leaf) {
  return leaf.includes(' WITH ') ? leaf.slice(0, leaf.indexOf(' WITH ')) : leaf;
}

// Component license normalization: prefers the first parseable expression,
// falls back to declared SPDX refs. Returns { expression (canonical string or
// null), rawRefs, parseable }.
export function componentLicenseInfo(component) {
  for (const lic of component.licenses || []) {
    if (lic.expression) {
      try {
        return {
          expression: canonicalExpression(lic.expression),
          rawExpression: lic.expression,
          refs: lic.refs || [],
          parseable: true,
        };
      } catch {
        return {
          expression: null,
          rawExpression: lic.expression,
          refs: lic.refs || [],
          parseable: false,
        };
      }
    }
    if (lic.refs && lic.refs.length) {
      return { expression: lic.refs.slice().sort().join(' OR '), refs: lic.refs, parseable: true };
    }
  }
  return { expression: null, rawExpression: null, refs: [], parseable: true };
}
