import type { Rule, Finding, ScanContext } from '../../types.js';
import { parseVersion, inRange, v, format, installedVersion } from '../../engine/version.js';

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
    const repo = ctx.repo;
    const manifest = repo?.packageManifest;
    if (!repo || !manifest) return [];
    const inst = installedVersion(repo, 'next');
    const parsed = parseVersion(inst?.version);
    if (!inst || !parsed) return [];

    const vulnerable = AFFECTED.some((a) => inRange(parsed, a.min, a.fixed));
    if (!vulnerable) return [];

    // The bypass skips MIDDLEWARE. With no middleware file there's nothing to skip.
    const hasMiddleware = repo.files.some((f) => /(^|\/)(src\/)?middleware\.(ts|js|mjs)$/.test(f));
    // Only a declared range like ^15.1.4 → it may already resolve to a patched release.
    const confidence: Finding['confidence'] = !hasMiddleware ? 'low' : inst.source === 'range' ? 'medium' : 'high';
    const exact = inst.source === 'range' ? `declared ${inst.version}` : `${format(parsed)} (${inst.source === 'lockfile' ? 'from your lockfile' : 'pinned'})`;

    return [
      {
        ruleId: 'AUTH_NEXTJS_MIDDLEWARE_BYPASS',
        category: 'auth',
        severity: 'critical',
        cwe: 'CWE-285',
        owasp: 'A01:2021',
        title: inst.source === 'range'
          ? 'Your Next.js version may be vulnerable to a middleware auth bypass (CVE-2025-29927)'
          : 'Your Next.js version is vulnerable to a middleware auth bypass (CVE-2025-29927)',
        whyItMatters: `Next.js ${exact} lets an attacker skip middleware (including auth checks) by sending an x-middleware-subrequest header.`,
        evidence: `next@${inst.version}${inst.source === 'lockfile' ? ' (lockfile)' : ''}${hasMiddleware ? ', middleware present' : ', no middleware file found'}`,
        location: { file: manifest.path },
        fix: 'Upgrade Next.js to 15.2.3+, 14.2.25+, or 13.5.9+.',
        fixPrompt: 'Upgrade Next.js to a patched version (15.2.3+, 14.2.25+, or 13.5.9+) to fix the CVE-2025-29927 middleware authorization bypass.',
        confidence,
        ...(confidence !== 'high'
          ? { verifyHint: !hasMiddleware
              ? 'This only matters if your app uses Next.js middleware (for example for auth). If it does, upgrade.'
              : 'Check the installed version (npm ls next). If it is 15.2.3+, 14.2.25+ or 13.5.9+, you are already patched.' }
          : {}),
        mode: 'whitebox',
        source: 'native',
      },
    ];
  },
};
