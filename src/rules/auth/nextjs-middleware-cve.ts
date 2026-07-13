import type { Rule, Finding, ScanContext } from '../../types.js';
import { parseVersion, inRange, v, format } from '../../engine/version.js';

/**
 * CVE-2025-29927 — Next.js middleware authorization bypass via the
 * `x-middleware-subrequest` header. Fixed in 15.2.3 / 14.2.25 / 13.5.9.
 */
const AFFECTED: { min: ReturnType<typeof v>; fixed: ReturnType<typeof v> }[] = [
  { min: v(15, 0, 0), fixed: v(15, 2, 3) },
  { min: v(14, 0, 0), fixed: v(14, 2, 25) },
  { min: v(13, 0, 0), fixed: v(13, 5, 9) },
];

export const nextjsMiddlewareCve: Rule = {
  id: 'AUTH_NEXTJS_MIDDLEWARE_BYPASS',
  category: 'auth',
  mode: 'whitebox',
  async run(ctx: ScanContext): Promise<Finding[]> {
    const manifest = ctx.repo?.packageManifest;
    const nextVer = manifest?.allDeps['next'];
    const parsed = parseVersion(nextVer);
    if (!parsed) return [];

    const vulnerable = AFFECTED.some((a) => inRange(parsed, a.min, a.fixed));
    if (!vulnerable) return [];

    return [
      {
        ruleId: 'AUTH_NEXTJS_MIDDLEWARE_BYPASS',
        category: 'auth',
        severity: 'critical',
        cwe: 'CWE-285',
        owasp: 'A01:2021',
        title: `Your Next.js version is vulnerable to a middleware auth bypass (CVE-2025-29927)`,
        whyItMatters: `Next.js ${format(parsed)} lets an attacker skip middleware (including auth checks) by sending an x-middleware-subrequest header.`,
        evidence: `next@${nextVer}`,
        location: { file: manifest!.path },
        fix: 'Upgrade Next.js to 15.2.3+, 14.2.25+, or 13.5.9+.',
        fixPrompt: 'Upgrade Next.js to a patched version (15.2.3+, 14.2.25+, or 13.5.9+) to fix the CVE-2025-29927 middleware authorization bypass.',
        confidence: 'high',
        mode: 'whitebox',
        source: 'native',
      },
    ];
  },
};
