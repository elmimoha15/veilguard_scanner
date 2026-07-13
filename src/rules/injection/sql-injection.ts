import type { Rule, Finding, ScanContext } from '../../types.js';
import { forEachCall, calleeName, isTaintedTemplateOrConcat } from '../../engine/ast.js';
import { safeRegexScan } from '../../engine/helpers.js';
import { isSourceFile } from '../_shared.js';

const RAW_UNSAFE = /\$(queryRawUnsafe|executeRawUnsafe)$/;
const QUERY_METHOD = /(^|\.)(query|execute|raw|exec)$/;
// Text fallback: a SQL string literal concatenated with a variable, e.g.
//   'SELECT * FROM orders WHERE id = ' + userId
const SQL_CONCAT = /["'`][^"'`\n]*\b(SELECT|INSERT|UPDATE|DELETE|DROP|WHERE|FROM)\b[^"'`\n]*["'`]\s*\+\s*[A-Za-z_$]/gi;

/**
 * White-box SQL-injection detection:
 *  - Prisma `$queryRawUnsafe` / `$executeRawUnsafe` (unsafe by name),
 *  - query/execute/raw calls whose SQL argument is a tainted template literal
 *    or string concatenation (user input spliced into SQL).
 */
export const sqlInjection: Rule = {
  id: 'INJECTION_SQL',
  category: 'injection',
  mode: 'whitebox',
  async run(ctx: ScanContext): Promise<Finding[]> {
    const repo = ctx.repo;
    if (!repo) return [];
    const out: Finding[] = [];

    for (const path of repo.files) {
      if (!isSourceFile(path)) continue;
      const ast = repo.astFor(path);
      if (!ast) continue;

      forEachCall(ast, (node, line) => {
        const name = calleeName(node);
        const firstArg = node.arguments?.[0];

        if (RAW_UNSAFE.test(name)) {
          out.push(mkFinding(path, line, `${name}(…)`, 'critical',
            'You’re using a raw, unescaped SQL query',
            'Prisma’s $queryRawUnsafe/$executeRawUnsafe run SQL without escaping — user input reaches your database verbatim.'));
          return;
        }

        if (QUERY_METHOD.test(name) && firstArg && isTaintedTemplateOrConcat(firstArg)) {
          out.push(mkFinding(path, line, `${name}(…)`, 'critical',
            'SQL is built by gluing strings together',
            'Concatenating user input into a SQL string lets an attacker rewrite your query (SQL injection).'));
        }
      });

      // Text fallback: catches concatenation assigned to a variable that the
      // AST pass can't follow into the later query() call.
      const content = repo.readFile(path);
      if (content) {
        for (const m of safeRegexScan(content, SQL_CONCAT)) {
          out.push(mkFinding(path, m.line, `${m.match.slice(0, 44)}…`, 'critical',
            'SQL is built by gluing strings together',
            'Concatenating user input into a SQL string lets an attacker rewrite your query (SQL injection).'));
        }
      }
    }
    return out;
  },
};

function mkFinding(file: string, line: number | undefined, evidence: string, severity: Finding['severity'], title: string, why: string): Finding {
  return {
    ruleId: 'INJECTION_SQL',
    category: 'injection',
    severity,
    cwe: 'CWE-89',
    owasp: 'A03:2021',
    title,
    whyItMatters: why,
    evidence,
    location: { file, line },
    fix: 'Use parameterized queries / prepared statements (e.g. Prisma’s tagged `$queryRaw`, or `db.query(sql, [params])`).',
    fixPrompt:
      'Rewrite this database query to use parameterized/prepared statements so user input is passed as bound parameters, never concatenated into the SQL string. If using Prisma, switch $queryRawUnsafe to the tagged-template $queryRaw.',
    confidence: 'high',
    mode: 'whitebox',
    source: 'native',
  };
}
