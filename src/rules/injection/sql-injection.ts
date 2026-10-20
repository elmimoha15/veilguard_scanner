import type { Rule, Finding, ScanContext } from '../../types.js';
import { forEachCall, calleeName, isTaintedTemplateOrConcat, referencesUserInput, regionAt } from '../../engine/ast.js';
import { safeRegexScan } from '../../engine/helpers.js';
import { isSourceFile } from '../_shared.js';

const RAW_UNSAFE = /\$(queryRawUnsafe|executeRawUnsafe)$/;
const QUERY_METHOD = /(^|\.)(query|execute|raw|exec)$/;
// Text fallback: a string literal that BEGINS with a real SQL statement shape
// and is concatenated with a variable, e.g. 'SELECT * FROM orders WHERE id = ' + userId.
// Anchoring on the statement shape (SELECT…FROM / INSERT INTO / UPDATE…SET /
// DELETE FROM / DROP TABLE) avoids matching prose that merely contains a word
// like "from"/"where"/"update" (e.g. 'with certificates from ' + issuer).
const SQL_CONCAT = /["'`]\s*(?:SELECT\b[^"'`\n]*?\bFROM\s+[A-Za-z_"[][^"'`\n]*|INSERT\s+INTO\s+[A-Za-z_"[][^"'`\n]*|UPDATE\s+[A-Za-z_"[][\w".]*\s+SET\s+\w+\s*=[^"'`\n]*|DELETE\s+FROM\s+[A-Za-z_"[][^"'`\n]*|DROP\s+TABLE\b[^"'`\n]*)["'`]\s*\+\s*[A-Za-z_$.]/gi;
/** A real query, not UI copy: SQL operators/clauses beyond the opening keyword. */
const SQL_SHAPE = /\bWHERE\b|\bVALUES\b|=|\*|\bJOIN\b|\bLIMIT\b|\bORDER\s+BY\b|\bIN\s*\(|\bSET\b|\bDROP\s+TABLE\b/i;
/** `.exec` on a regex is pattern matching, not SQL. */
const REGEX_RECEIVER = /(^|\.)(re|regex|regexp|pattern|matcher|[A-Za-z]*(Re|Regex|RE|Pattern))\.exec$/;

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

        const content0 = ast.content;
        if (RAW_UNSAFE.test(name)) {
          // A literal query with positional parameters ($1, ?) is parameterized: safe.
          if (firstArg?.type === 'StringLiteral' && (node.arguments?.length ?? 0) > 1) return;
          const userInput = !!firstArg && isTaintedTemplateOrConcat(firstArg) && referencesUserInput(firstArg, content0);
          out.push({ ...mkFinding(path, line, `${name}(…)`, 'critical',
            'You’re using a raw, unescaped SQL query',
            'Prisma’s $queryRawUnsafe/$executeRawUnsafe run SQL without escaping, so user input can reach your database verbatim.'),
            confidence: userInput ? 'high' : 'medium' });
          return;
        }

        // `.exec` is SQL only on a database object; bare exec() is child_process
        // (INJECTION_COMMAND) and `re.exec()` is a regex.
        const isExec = /(^|\.)exec$/.test(name);
        const receiver = name.replace(/\.exec$/, '').split('.').pop() ?? '';
        const regexReceiver = REGEX_RECEIVER.test(name) || /(^|_)(re|regex|regexp|pattern)$/i.test(receiver) ||
          new RegExp(`\\b(const|let|var)\\s+${receiver.replace(/[^\w$]/g, '')}\\s*=\\s*(\\/|new\\s+RegExp)`).test(ast.content);
        const execIsDb = isExec && name.includes('.') && !regexReceiver && !/child_process|['"]node:child_process['"]/.test(ast.content);
        if (QUERY_METHOD.test(name) && (!isExec || execIsDb) && firstArg?.type !== 'RegExpLiteral' && firstArg && isTaintedTemplateOrConcat(firstArg)) {
          // The unsafe pattern itself is the evidence: a non-constant value glued
          // into SQL (constants like ${TABLE} were already excluded above).
          out.push(mkFinding(path, line, `${name}(…)`, 'critical',
            'SQL is built by gluing strings together',
            'Concatenating user input into a SQL string lets an attacker rewrite your query (SQL injection).'));
        }
      });

      // Text fallback: catches concatenation assigned to a variable that the
      // AST pass can't follow into the later query() call. The SQL_CONCAT pattern
      // requires a real statement shape (SELECT…FROM etc.), so prose that merely
      // contains "from"/"where" no longer trips it.
      const content = repo.readFile(path);
      if (content) {
        const region = regionAt(ast);
        for (const m of safeRegexScan(content, SQL_CONCAT)) {
          if (region(m.index) !== 'code') continue; // example in a comment/message, not a query
          if (!SQL_SHAPE.test(m.match.replace(/^["'`]\s*\w+/, ''))) continue; // UI copy, not a query
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
