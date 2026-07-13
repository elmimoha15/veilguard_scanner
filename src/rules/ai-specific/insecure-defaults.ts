import type { Rule, Finding, ScanContext } from '../../types.js';
import { safeRegexScan } from '../../engine/helpers.js';
import { isSourceFile } from '../_shared.js';

const PATTERNS: { re: RegExp; title: string; why: string }[] = [
  {
    re: /rejectUnauthorized\s*:\s*false/g,
    title: 'TLS certificate verification is turned off',
    why: '`rejectUnauthorized: false` disables certificate checks, exposing you to man-in-the-middle attacks.',
  },
  {
    re: /NODE_TLS_REJECT_UNAUTHORIZED\s*[:=]\s*["']?0["']?/g,
    title: 'TLS verification is globally disabled',
    why: 'Setting NODE_TLS_REJECT_UNAUTHORIZED=0 disables TLS validation for the entire process.',
  },
];

/** White-box: insecure defaults AI tools commonly generate. */
export const insecureDefaults: Rule = {
  id: 'AI_INSECURE_DEFAULTS',
  category: 'ai_specific',
  mode: 'whitebox',
  async run(ctx: ScanContext): Promise<Finding[]> {
    const repo = ctx.repo;
    if (!repo) return [];
    const out: Finding[] = [];

    for (const path of repo.files) {
      if (!isSourceFile(path) && !/\.env/.test(path)) continue;
      const content = repo.readFile(path);
      if (!content) continue;
      for (const p of PATTERNS) {
        for (const m of safeRegexScan(content, p.re)) {
          out.push({
            ruleId: 'AI_INSECURE_DEFAULTS',
            category: 'ai_specific',
            severity: 'high',
            cwe: 'CWE-295',
            owasp: 'A05:2021',
            title: p.title,
            whyItMatters: p.why,
            evidence: m.match,
            location: { file: path, line: m.line },
            fix: 'Remove the flag and fix the underlying certificate/trust issue properly.',
            fixPrompt: 'Remove this setting that disables TLS certificate verification and instead configure the correct CA/trust chain so certificates validate normally.',
            confidence: 'high',
            mode: 'whitebox',
            source: 'native',
          });
        }
      }
    }
    return out;
  },
};
