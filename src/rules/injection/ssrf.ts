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
/** A user-input ROOT in an interpolated expression (not just the word in literal text). */
const USER_INPUT = /^\s*(?:await\s+)?(?:req|request|searchParams|params|query|body|nextUrl|ctx\.(?:query|params|request))\b/;

/**
 * Where user input lands in the URL. Controlling the scheme/host is real SSRF
 * (call any internal host); a user value only in the PATH of a fixed host is
 * usually just an API lookup.
 */
function taintPosition(arg: any, content: string): 'host' | 'path' | null {
  const text = (n: any) => (typeof n?.start === 'number' && typeof n?.end === 'number' ? content.slice(n.start, n.end) : '');
  const userExpr = (n: any) => USER_INPUT.test(text(n));
  // Literal text BEFORE the first user-controlled piece decides host vs path:
  // "https://api.example.com/..." or a relative "/..." means the host is fixed.
  const hostFixed = (prefix: string) => /^[a-z][a-z0-9+.-]*:\/\/[^/\s]*[a-z0-9-]\.[a-z]{2,}[^/\s]*\//i.test(prefix) || /^\//.test(prefix);
  if (arg.type === 'TemplateLiteral') {
    let prefix = '';
    for (let i = 0; i < arg.expressions.length; i++) {
      prefix += arg.quasis[i]?.value?.cooked ?? '';
      if (userExpr(arg.expressions[i])) return hostFixed(prefix) ? 'path' : 'host';
      prefix += '${}';
    }
    return null;
  }
  if (arg.type === 'BinaryExpression') {
    const parts: any[] = [];
    const walk = (n: any): void => {
      if (n?.type === 'BinaryExpression' && n.operator === '+') { walk(n.left); walk(n.right); } else parts.push(n);
    };
    walk(arg);
    let prefix = '';
    for (const part of parts) {
      if (part.type === 'StringLiteral') { prefix += part.value; continue; }
      if (userExpr(part)) return hostFixed(prefix) ? 'path' : 'host';
      prefix += '${}';
    }
  }
  return null;
}

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
      // A metadata address inside a blocklist (array, includes/has check) is the
      // DEFENCE against SSRF, not a request to it.
      const lines = content.split('\n');
      const metaHit = safeRegexScan(content, METADATA_URL).find(
        (h) => !/\[|includes\(|\.has\(|block|deny|forbid|disallow|reject/i.test(lines[h.line - 1] ?? ''),
      );
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
        if (!arg) return;
        // The whole URL straight from the request (fetch(req.query.url)) = host control.
        const whole = (arg.type === 'MemberExpression' || arg.type === 'CallExpression') && USER_INPUT.test(typeof arg.start === 'number' ? content.slice(arg.start, arg.end) : '');
        if (!whole && !isTaintedTemplateOrConcat(arg)) return;
        const pos = whole ? 'host' : taintPosition(arg, content);
        if (!pos) return;
        if (pos === 'host') {
          out.push(mk(path, line, `${name}(<user-controlled url>)`, 'high', 'high',
            'A server request goes to a host chosen by the user (SSRF)',
            'User input decides which host your server calls, so an attacker can make it reach internal services or the cloud metadata endpoint (SSRF).'));
        } else {
          out.push({
            ...mk(path, line, `${name}(<fixed host>/<user path>)`, 'medium', 'low',
              'A server request path includes user input',
              'The host is fixed, but user input is placed in the request path. Usually fine; it matters only if the input can add "../", "@" or reach another endpoint.'),
            verifyHint: 'Check that the user value is validated (for example an id or slug pattern) so it cannot change the path to another endpoint.',
          });
        }
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
