import type { Rule, Finding, ScanContext } from '../../types.js';
import { safeRegexScan } from '../../engine/helpers.js';
import { isSourceFile } from '../_shared.js';

// dangerouslySetInnerHTML={{ __html: <expr> }} where expr isn't an obvious
// sanitizer call (DOMPurify / sanitize*).
const DANGEROUS_HTML = /dangerouslySetInnerHTML\s*=\s*\{\{\s*__html\s*:\s*([^}]+)\}\}/g;

// Expressions that are STATIC/safe to inject: JSON.stringify(...) of an object
// (the standard JSON-LD structured-data pattern), a bare string/template literal,
// or a template literal with no ${...} interpolation. None of these are user data.
function isStaticHtmlExpr(expr: string): boolean {
  if (/^JSON\.stringify\s*\(/.test(expr)) return true; // JSON-LD / structured data
  if (/^["']/.test(expr)) return true; // plain string literal
  if (/^`[^`]*`$/.test(expr) && !/\$\{/.test(expr)) return true; // template literal, no interpolation
  return false;
}

// Signals that the injected value is (or could be) user- / request-derived — the
// only case that is a real XSS sink and fires at HIGH.
const USER_DERIVED =
  /\b(props|params|searchParams|useSearchParams|query|req|request|body|formData|location|window|document\.|input|state|useState|router|ctx|context|params\.|marked|markdownToHtml|renderMarkdown|userInput|comment|message|description|bio|content\b)/i;

export const xss: Rule = {
  id: 'INJECTION_XSS',
  category: 'injection',
  mode: 'whitebox',
  async run(ctx: ScanContext): Promise<Finding[]> {
    const repo = ctx.repo;
    if (!repo) return [];
    const out: Finding[] = [];

    for (const path of repo.files) {
      if (!isSourceFile(path)) continue;
      const content = repo.readFile(path);
      if (!content) continue;

      for (const m of safeRegexScan(content, DANGEROUS_HTML)) {
        const expr = (m.groups[0] ?? '').trim();
        if (/DOMPurify|sanitize|sanitizeHtml|purify/i.test(expr)) continue; // already sanitized → ok
        if (isStaticHtmlExpr(expr)) continue; // JSON.stringify / literal / static → not user data, safe

        // A dynamic value that is clearly user/request-derived is a real XSS sink
        // (HIGH). Anything else non-static we can't prove is safe → a low-confidence
        // "possible — verify" note rather than a scary HIGH false positive.
        const userDerived = USER_DERIVED.test(expr);
        const short = expr.length > 48 ? expr.slice(0, 48) + '…' : expr;
        out.push({
          ruleId: 'INJECTION_XSS',
          category: 'injection',
          severity: userDerived ? 'high' : 'low',
          cwe: 'CWE-79',
          owasp: 'A03:2021',
          title: userDerived
            ? 'Unsanitized user input is injected as HTML'
            : 'Dynamic HTML injection — verify the source is not user input',
          whyItMatters: userDerived
            ? 'dangerouslySetInnerHTML with user-derived content lets an attacker run scripts in your users’ browsers (XSS).'
            : 'This value is injected as raw HTML. If it can ever contain user input it is an XSS risk; if it is fully static it is safe — verify the source.',
          evidence: `__html: ${short}`,
          location: { file: path, line: m.line },
          fix:
            `Sanitize before rendering with DOMPurify:\n\n` +
            `import DOMPurify from 'isomorphic-dompurify';\n\n` +
            `<div dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(${short}) }} />\n\n` +
            `Or, if HTML isn't needed, render it as text instead: <div>{${short}}</div>`,
          fixPrompt:
            `Wrap the value passed to dangerouslySetInnerHTML in DOMPurify.sanitize() — add \`import DOMPurify from 'isomorphic-dompurify'\` and change \`__html: ${short}\` to \`__html: DOMPurify.sanitize(${short})\`. If the value never needs to be HTML, render it as plain text ({value}) instead.`,
          confidence: userDerived ? 'high' : 'low',
          mode: 'whitebox',
          source: 'native',
        });
      }
    }
    return out;
  },
};
