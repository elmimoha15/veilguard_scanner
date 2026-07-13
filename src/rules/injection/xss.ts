import type { Rule, Finding, ScanContext } from '../../types.js';
import { safeRegexScan } from '../../engine/helpers.js';
import { isSourceFile } from '../_shared.js';

// dangerouslySetInnerHTML={{ __html: <expr> }} where expr isn't an obvious
// sanitizer call (DOMPurify / sanitize*).
const DANGEROUS_HTML = /dangerouslySetInnerHTML\s*=\s*\{\{\s*__html\s*:\s*([^}]+)\}\}/g;

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
        if (/DOMPurify|sanitize|sanitizeHtml|purify/i.test(expr)) continue; // sanitized → ok
        if (/^["'`]/.test(expr)) continue; // a static string literal → not user data
        out.push({
          ruleId: 'INJECTION_XSS',
          category: 'injection',
          severity: 'high',
          cwe: 'CWE-79',
          owasp: 'A03:2021',
          title: 'Unsanitized HTML is injected into the page',
          whyItMatters: 'dangerouslySetInnerHTML with dynamic content lets an attacker run scripts in your users’ browsers (XSS).',
          evidence: `__html: ${expr.slice(0, 40)}`,
          location: { file: path, line: m.line },
          fix: 'Sanitize the HTML with DOMPurify before rendering, or render as text instead of HTML.',
          fixPrompt: 'Sanitize this value with DOMPurify.sanitize() before passing it to dangerouslySetInnerHTML, or render it as plain text instead of HTML.',
          confidence: 'medium',
          mode: 'whitebox',
          source: 'native',
        });
      }
    }
    return out;
  },
};
