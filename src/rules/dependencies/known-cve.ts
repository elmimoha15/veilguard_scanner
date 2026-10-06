import type { Rule, Finding, ScanContext } from '../../types.js';
import { parseVersion, inRange, v, format, type SemVer } from '../../engine/version.js';

interface Advisory {
  pkg: string;
  ranges: { min: SemVer; fixed: SemVer }[];
  id: string;
  severity: Finding['severity'];
  summary: string;
}

/**
 * A tiny list of CONFIRMED advisories so the most common Next.js CVEs are caught
 * with zero external tools — a native floor. osv-scanner (when installed) is the
 * real source of dependency CVEs and covers everything else; keep this list
 * deliberately small and verified.
 *
 * NEVER add an unverified or AI-sourced advisory here. Every entry must have a
 * real, published CVE/GHSA id whose affected range is confirmed against the
 * official vendor advisory / GitHub Advisory DB.
 */
const ADVISORIES: Advisory[] = [
  // NOTE: CVE-2025-29927 (middleware bypass) is reported by the dedicated auth
  // rule (AUTH_NEXTJS_MIDDLEWARE_BYPASS), so it is intentionally omitted here to
  // avoid a duplicate finding.
  {
    pkg: 'next',
    id: 'CVE-2024-34351',
    ranges: [{ min: v(13, 0, 0), fixed: v(14, 1, 1) }],
    severity: 'high',
    summary: 'SSRF in the Next.js image optimizer via crafted host header / remotePatterns.',
  },
];

export const knownCve: Rule = {
  id: 'DEPENDENCIES_KNOWN_CVE',
  category: 'dependencies',
  mode: 'whitebox',
  async run(ctx: ScanContext): Promise<Finding[]> {
    const manifest = ctx.repo?.packageManifest;
    if (!manifest) return [];
    const out: Finding[] = [];

    for (const adv of ADVISORIES) {
      const declared = manifest.allDeps[adv.pkg];
      const parsed = parseVersion(declared);
      if (!parsed) continue;
      if (!adv.ranges.some((r) => inRange(parsed, r.min, r.fixed))) continue;

      out.push({
        ruleId: `DEPENDENCIES_${adv.id.replace(/[^A-Z0-9]/gi, '_').toUpperCase()}`,
        category: 'dependencies',
        severity: adv.severity,
        cwe: 'CWE-1035',
        owasp: 'A06:2021',
        title: `Outdated dependency with a known vulnerability: ${adv.pkg}@${declared}`,
        whyItMatters: `${adv.summary} Attackers scan for exactly these versions.`,
        evidence: `${adv.pkg}@${declared} (${adv.id}), current parsed ${format(parsed)}`,
        location: { file: manifest.path },
        fix: `Upgrade ${adv.pkg} to a patched release and re-run your tests.`,
        fixPrompt: `Upgrade the ${adv.pkg} dependency to the latest patched version to resolve ${adv.id}, then run the test suite.`,
        confidence: 'high',
        mode: 'whitebox',
        source: 'native',
      });
    }
    return out;
  },
};
