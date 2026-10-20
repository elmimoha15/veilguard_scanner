import type { Rule, Finding, ScanContext } from '../../types.js';
import { safeRegexScan } from '../../engine/helpers.js';
import { regionAt } from '../../engine/ast.js';
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
      const region = regionAt(isSourceFile(path) ? repo.astFor(path) : null);
      // A DB driver config (pg, knex, sequelize, prisma…) where managed Postgres
      // providers document ssl.rejectUnauthorized=false as a workaround.
      const dbFile = /\b(pg|postgres|Pool|knex|sequelize|typeorm|drizzle|DATABASE_URL|connectionString)\b/.test(content);
      for (const p of PATTERNS) {
        for (const m of safeRegexScan(content, p.re)) {
          const dbSsl = dbFile && /ssl\s*:\s*\{[^}]*$/.test(content.slice(Math.max(0, m.index - 120), m.index));
          if (region(m.index) !== 'code') continue; // mentioned in a comment/message, not set
          out.push({
            ruleId: 'AI_INSECURE_DEFAULTS',
            category: 'ai_specific',
            severity: dbSsl ? 'medium' : 'high',
            cwe: 'CWE-295',
            owasp: 'A05:2021',
            title: dbSsl ? 'Your database connection skips TLS certificate checks' : p.title,
            whyItMatters: dbSsl
              ? 'The connection is still encrypted, but the server’s certificate isn’t checked, so a network attacker could impersonate your database. Some managed Postgres providers suggest this as a quick workaround.'
              : p.why,
            evidence: m.match,
            location: { file: path, line: m.line },
            fix: 'Remove the flag and fix the underlying certificate/trust issue properly.',
            fixPrompt: 'Remove this setting that disables TLS certificate verification and instead configure the correct CA/trust chain so certificates validate normally.',
            confidence: dbSsl ? 'medium' : 'high',
            ...(dbSsl ? { verifyHint: 'Download your provider’s CA certificate and pass it as ssl.ca with rejectUnauthorized: true. If the database is only reachable on a private network, the risk is lower.' } : {}),
            mode: 'whitebox',
            source: 'native',
          });
        }
      }
    }
    return out;
  },
};
