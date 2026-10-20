import _traverse from '@babel/traverse';
import type { BabelFile } from '../types.js';

// @babel/traverse ships CJS; under ESM the callable is on `.default`.
const traverse = ((_traverse as any).default ?? _traverse) as typeof _traverse;

export type NodeVisitor = (node: any, line: number | undefined) => void;

/** Walk every CallExpression, invoking cb with the node + line. */
export function forEachCall(file: BabelFile, cb: NodeVisitor): void {
  try {
    traverse(file.ast, {
      CallExpression(path: any) {
        cb(path.node, path.node.loc?.start.line);
      },
    });
  } catch {
    /* errorRecovery ASTs can be partial; ignore traversal faults */
  }
}

/** Get the dotted callee name of a call, e.g. `stripe.webhooks.constructEvent`. */
export function calleeName(node: any): string {
  const parts: string[] = [];
  let cur = node.callee;
  while (cur) {
    if (cur.type === 'Identifier') {
      parts.unshift(cur.name);
      break;
    }
    if (cur.type === 'MemberExpression') {
      if (cur.property?.type === 'Identifier') parts.unshift(cur.property.name);
      cur = cur.object;
    } else {
      break;
    }
  }
  return parts.join('.');
}

/**
 * A value that can't carry user input: a literal, or a SCREAMING_CASE constant
 * (`TABLE`, `Config.TABLE_NAME`, `LIMIT`). Interpolating these is not taint.
 */
export function isConstantNode(n: any): boolean {
  if (!n) return true;
  if (n.type === 'StringLiteral' || n.type === 'NumericLiteral' || n.type === 'BooleanLiteral') return true;
  if (n.type === 'Identifier') return /^[A-Z][A-Z0-9_]*$/.test(n.name);
  if (n.type === 'MemberExpression' && !n.computed && n.property?.type === 'Identifier') {
    return /^[A-Z][A-Z0-9_]*$/.test(n.property.name) && (n.object?.type === 'Identifier' || n.object?.type === 'MemberExpression');
  }
  return false;
}

/** True if a node is (or contains) string concatenation with a non-constant part. */
export function isTaintedTemplateOrConcat(node: any): boolean {
  if (!node) return false;
  if (node.type === 'TemplateLiteral') {
    // Interpolated expressions → tainted (unless all are literals/constants).
    return node.expressions.some((e: any) => !isConstantNode(e));
  }
  if (node.type === 'BinaryExpression' && node.operator === '+') {
    const hasIdentifier = (n: any): boolean =>
      ((n.type === 'Identifier' || n.type === 'MemberExpression' || n.type === 'CallExpression') && !isConstantNode(n)) ||
      (n.type === 'BinaryExpression' && (hasIdentifier(n.left) || hasIdentifier(n.right)));
    return hasIdentifier(node);
  }
  return false;
}

/** True when the node's source text references request/user input directly. */
export function referencesUserInput(node: any, content: string): boolean {
  if (typeof node?.start !== 'number' || typeof node?.end !== 'number') return false;
  return /\b(req|request|params|searchParams|query|body|input|args|formData|ctx\.(query|params|request))\b/.test(content.slice(node.start, node.end));
}

/** Collect all string-literal + identifier args flattened for quick checks. */
export function argToText(node: any): string {
  if (!node) return '';
  if (node.type === 'StringLiteral') return node.value;
  if (node.type === 'TemplateLiteral') return node.quasis.map((q: any) => q.value.cooked).join('${…}');
  if (node.type === 'Identifier') return node.name;
  return '';
}

export type TextRegion = 'code' | 'comment' | 'string';

const regionCache = new WeakMap<BabelFile, (index: number) => TextRegion>();

/**
 * Classify a character offset in a parsed file as code, comment, or string
 * text. Text-regex rules use this to ignore matches that only appear in prose
 * (comments, docs, error messages) — e.g. a detector's own example snippet.
 * With no AST (unparseable / non-JS file) everything is treated as code.
 */
export function regionAt(file: BabelFile | null): (index: number) => TextRegion {
  if (!file) return () => 'code';
  const cached = regionCache.get(file);
  if (cached) return cached;

  const ranges: { start: number; end: number; kind: TextRegion }[] = [];
  for (const c of (file.ast as any).comments ?? []) {
    if (c.start != null && c.end != null) ranges.push({ start: c.start, end: c.end, kind: 'comment' });
  }
  try {
    traverse(file.ast, {
      StringLiteral(path: any) {
        const n = path.node;
        // Content only: the opening quote itself counts as code.
        if (n.start != null && n.end != null) ranges.push({ start: n.start + 1, end: n.end - 1, kind: 'string' });
      },
      TemplateElement(path: any) {
        const n = path.node;
        if (n.start != null && n.end != null) ranges.push({ start: n.start, end: n.end, kind: 'string' });
      },
    });
  } catch {
    /* partial AST; use whatever ranges we collected */
  }

  const fn = (index: number): TextRegion => {
    for (const r of ranges) if (index >= r.start && index < r.end) return r.kind;
    return 'code';
  };
  regionCache.set(file, fn);
  return fn;
}
