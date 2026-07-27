import type { Rule, Finding, ScanContext } from '../../types.js';
import { forEachCall, calleeName, isTaintedTemplateOrConcat } from '../../engine/ast.js';
import { safeRegexScan } from '../../engine/helpers.js';
import { isSourceFile } from '../_shared.js';

/**
 * White-box SSRF detection, tuned for low false positives:
 *
 *  1. HIGH confidence — an outbound request whose URL string points at a cloud
 *     metadata endpoint (AWS/GCP/Alibaba). Fetching 169.254.169.254 is almost
 *     never legitimate and leaks instance credentials.
 *
 *  2. MEDIUM confidence — a fetch/axios/http request whose URL argument is built
 *     from untrusted input (a tainted template/concat referencing
 *     req/searchParams/params/query/body). Static literal URLs never fire.
 */

// A hardcoded cloud-metadata URL inside a string literal.
const METADATA_URL =
  /['"`]https?:\/\/(169\.254\.169\.254|metadata\.google\.internal|100\.100\.100\.200)[^'"`]*['"`]/gi;

// Call names that issue an outbound HTTP request.
const REQUEST_CALL = /(^|\.)(fetch|request|got)$|axios|https?\.(get|request|post)$/i;
// User-controlled sources that make a URL tainted.
const USER_INPUT = /\b(req|request|searchParams|params|query|body|nextUrl)\b/;

export const ssrf: Rule = {
  id: 'INJECTION_SSRF',
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

      // 1. Cloud-metadata literal (report once per file).
      const metaHit = safeRegexScan(content, METADATA_URL)[0];
      if (metaHit) {
        out.push(mk(path, metaHit.line, `request to ${metaHit.match.slice(0, 48)}`, 'high', 'high',
          'Your code makes a request to the cloud metadata endpoint',
          'A request to 169.254.169.254 (or the GCP/Alibaba equivalent) can read your cloud instance’s credentials — a classic SSRF-to-credential-theft path. Fetching it directly is almost never legitimate.'));
      }

      // 2. Tainted URL into an outbound request (AST).
      const ast = repo.astFor(path);
      if (!ast) continue;
      forEachCall(ast, (node, line) => {
        const name = calleeName(node);
        if (!REQUEST_CALL.test(name)) return;
        const arg = node.arguments?.[0];
        if (!arg || !isTaintedTemplateOrConcat(arg)) return;
        // Only when the tainted part references user input.
        const src =
          typeof arg.start === 'number' && typeof arg.end === 'number' ? content.slice(arg.start, arg.end) : '';
        if (!USER_INPUT.test(src)) return;
        out.push(mk(path, line, `${name}(<user-controlled url>)`, 'high', 'medium',
          'A server request is built from untrusted input (SSRF)',
          'Passing user-controlled data into the URL of a server-side request lets an attacker make your server call internal hosts or the cloud metadata endpoint (SSRF).'));
      });
    }
    return out;
  },
};

function mk(
  file: string,
  line: number | undefined,
  evidence: string,
  severity: Finding['severity'],
  confidence: Finding['confidence'],
  title: string,
  why: string,
): Finding {
  return {
    ruleId: 'INJECTION_SSRF',
    category: 'injection',
    severity,
    cwe: 'CWE-918',
    owasp: 'A10:2021',
    title,
    whyItMatters: why,
    evidence,
    location: { file, line },
    fix: 'Validate the target URL against an allowlist of exact hosts before requesting it, and block link-local/private ranges (169.254.0.0/16, 10/8, 127/8, ::1).',
    fixPrompt:
      'Before making this server-side request, validate the destination URL: allow only an explicit list of trusted hosts and reject any URL resolving to private/link-local ranges (including 169.254.169.254). Never pass user input straight into fetch/axios.',
    confidence,
    mode: 'whitebox',
    source: 'native',
  };
}
