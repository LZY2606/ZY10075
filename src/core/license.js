// SPDX license expression handling (SPDX 2.3 grammar, subset):
//   <expr>   := <or>
//   <or>     := <and> (OR <and>)*
//   <and>    := <member> (AND <member>)*
//   <member> := '(' <expr> ')' | license-id ['WITH' exception-id]
// Unknown / absent licenses normalize to NOASSERTION.

export const UNKNOWN_LICENSE = 'NOASSERTION';

function tokenize(expression) {
  if (typeof expression !== 'string') return [];
  return expression.replace(/[()]/g, (ch) => ' ' + ch + ' ').trim().split(/\s+/).filter(Boolean);
}

class Parser {
  constructor(tokens) {
    this.tokens = tokens;
    this.pos = 0;
  }
  parseOr() {
    const children = [this.parseAnd()];
    while (this.peekKeyword() === 'OR') {
      this.pos++;
      children.push(this.parseAnd());
    }
    return children.length === 1 ? children[0] : { op: 'OR', children };
  }
  parseAnd() {
    const children = [this.parseMember()];
    while (this.peekKeyword() === 'AND') {
      this.pos++;
      children.push(this.parseMember());
    }
    return children.length === 1 ? children[0] : { op: 'AND', children };
  }
  parseMember() {
    const tok = this.tokens[this.pos++];
    if (tok === '(') {
      const node = this.parseOr();
      if (this.tokens[this.pos++] !== ')') throw new Error('Unbalanced license expression parentheses');
      return node;
    }
    if (!tok) throw new Error('Unexpected end of license expression');
    if (this.peekKeyword() === 'WITH') {
      this.pos++;
      const exception = this.tokens[this.pos++];
      if (!exception) throw new Error('WITH without exception id');
      return { op: 'LICENSE', id: tok + ' WITH ' + exception };
    }
    return { op: 'LICENSE', id: tok };
  }
  peekKeyword() {
    const t = this.tokens[this.pos];
    if (t === '(' || t === ')') return t;
    const upper = typeof t === 'string' ? t.toUpperCase() : undefined;
    return upper === 'OR' || upper === 'AND' || upper === 'WITH' ? upper : undefined;
  }
}

export function parseExpression(expression) {
  const tokens = tokenize(expression);
  if (!tokens.length) return { op: 'LICENSE', id: UNKNOWN_LICENSE };
  const parser = new Parser(tokens);
  const node = parser.parseOr();
  if (parser.pos !== tokens.length) throw new Error('Trailing tokens in license expression: ' + expression);
  return node;
}

function canonToken(id) {
  const parts = id.split(/\s+WITH\s+/i);
  // SPDX license ids keep canonical mixed case ("GPL-3.0-only"); only the WITH
  // keyword and expression operators are uppercase.
  return parts[0] + (parts[1] ? ' WITH ' + parts[1] : '');
}

export function normalizeExpression(expression) {
  if (expression === null || expression === undefined || expression === '') return UNKNOWN_LICENSE;
  const node = parseExpression(expression);
  return printNode(node);
}

function printNode(node) {
  if (node.op === 'LICENSE') return canonToken(node.id);
  if (node.op === 'AND') {
    return node.children.map(printNode).sort((a, b) => a.toLowerCase().localeCompare(b.toLowerCase())).join(' AND ');
  }
  return node.children
    .map((child) => (child.op === 'AND' ? '(' + printNode(child) + ')' : printNode(child)))
    .sort((a, b) => a.toLowerCase().localeCompare(b.toLowerCase()))
    .join(' OR ');
}

// Disjunctive normal form: array of alternatives; each alternative is a
// sorted, de-duplicated array of atomic tokens ("ID" or "ID WITH EXCEPTION").
export function toDnf(expression) {
  // Alternative order follows the document (deterministic given the input);
  // tokens inside an alternative are sorted and de-duplicated.
  const dnf = dnfNode(parseExpression(expression ?? UNKNOWN_LICENSE));
  const seenAlternatives = new Set();
  const out = [];
  for (const alternative of dnf) {
    const sorted = [...new Set(alternative.map(canonToken))].sort();
    const key = sorted.join('|');
    if (seenAlternatives.has(key)) continue;
    seenAlternatives.add(key);
    out.push(sorted);
  }
  return out;
}

function dnfNode(node) {
  if (node.op === 'LICENSE') return [[canonToken(node.id)]];
  if (node.op === 'OR') return node.children.flatMap(dnfNode);
  let combinations = [[]];
  for (const child of node.children) {
    const childAlts = dnfNode(child);
    const next = [];
    for (const prefix of combinations) {
      for (const alt of childAlts) next.push([...prefix, ...alt]);
    }
    combinations = next;
  }
  return combinations;
}

// Evaluate a declared expression against an allowed (or forbidden) token set.
// With allowlist mode every token of at least one DNF alternative must be in
// the set; with blocklist mode at least one alternative must have no token in
// the set (i.e. there exists a way to comply without a forbidden license).
export function evaluateAlternatives(expression, mode, licenseSet) {
  const dnf = toDnf(expression ?? UNKNOWN_LICENSE);
  const accepted = dnf.filter((alt) =>
    alt.every((token) => (mode === 'allowlist' ? licenseSet.has(token) : !licenseSet.has(token)))
  );
  return { satisfied: accepted.length > 0, chosenAlternative: accepted[0] ?? null, alternatives: dnf };
}

// license.combo: a required SPDX expression is satisfiable by the observed
// tokens found across a dependency closure.
export function comboSatisfied(observedTokens, requiredExpression) {
  const { satisfied } = evaluateAlternatives(requiredExpression, 'allowlist', new Set(observedTokens));
  return satisfied;
}
