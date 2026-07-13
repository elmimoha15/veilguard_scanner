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

/** True if a node is (or contains) string concatenation with a non-literal part. */
export function isTaintedTemplateOrConcat(node: any): boolean {
  if (!node) return false;
  if (node.type === 'TemplateLiteral') {
    // Interpolated expressions → tainted (unless all are simple literals).
    return node.expressions.some((e: any) => e.type !== 'StringLiteral' && e.type !== 'NumericLiteral');
  }
  if (node.type === 'BinaryExpression' && node.operator === '+') {
    const hasIdentifier = (n: any): boolean =>
      n.type === 'Identifier' ||
      n.type === 'MemberExpression' ||
      n.type === 'CallExpression' ||
      (n.type === 'BinaryExpression' && (hasIdentifier(n.left) || hasIdentifier(n.right)));
    return hasIdentifier(node);
  }
  return false;
}

/** Collect all string-literal + identifier args flattened for quick checks. */
export function argToText(node: any): string {
  if (!node) return '';
  if (node.type === 'StringLiteral') return node.value;
  if (node.type === 'TemplateLiteral') return node.quasis.map((q: any) => q.value.cooked).join('${…}');
  if (node.type === 'Identifier') return node.name;
  return '';
}
