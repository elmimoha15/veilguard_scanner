import type { Rule, Finding, ScanContext } from '../../types.js';
import { safeRegexScan } from '../../engine/helpers.js';
import { SENSITIVE_NAME } from '../../engine/secret-matrix.js';
import { CODE_AND_CONFIG_EXT } from '../_shared.js';

// Any NEXT_PUBLIC_/VITE_/PUBLIC_/REACT_APP_ variable name.
const PUBLIC_VAR = /\b((?:NEXT_PUBLIC_|VITE_|PUBLIC_|REACT_APP_)[A-Z0-9_]+)\b/g;

/**
 * Platform gotcha: a secret-named variable behind a public prefix. On
 * Vercel/Netlify/Vite, these are inlined into the browser bundle at build time,
 * so anything sensitive is effectively published.
 */
export const publicSecretVar: Rule = {
  id: 'PLATFORM_PUBLIC_SECRET_VAR',
  category: 'platform',
  mode: 'both',
  async run(ctx: ScanContext): Promise<Finding[]> {
    const out: Finding[] = [];
    const seen = new Set<string>();

    const scan = (text: string, loc: { file?: string; url?: string }, mode: 'whitebox' | 'blackbox') => {
      for (const m of safeRegexScan(text, PUBLIC_VAR)) {
        const name = m.groups[0]!;
        if (!SENSITIVE_NAME.test(name)) continue;
        const key = `${loc.file ?? loc.url}|${name}`;
        if (seen.has(key)) continue;
        seen.add(key);
        out.push({
          ruleId: 'PLATFORM_PUBLIC_SECRET_VAR',
          category: 'platform',
          severity: 'high',
          cwe: 'CWE-200',
          owasp: 'A05:2021',
          title: `"${name}" is a secret exposed to the browser`,
          whyItMatters: 'Variables with a public prefix are bundled into your client JavaScript, so this "secret" is visible to every visitor.',
          evidence: name,
          location: loc,
          fix: `Rename ${name} to a server-only variable (drop the public prefix) and read it only in server code.`,
          fixPrompt: `Rename the ${name} environment variable to remove the public prefix so it isn't bundled into the client, and access it only from server-side code. Rotate the value.`,
          confidence: 'high',
          mode,
          source: 'native',
        });
      }
    };

    if (ctx.repo) {
      for (const path of ctx.repo.files) {
        if (!CODE_AND_CONFIG_EXT.test(path) && !/\.env/.test(path)) continue;
        const content = ctx.repo.readFile(path);
        if (content) scan(content, { file: path }, 'whitebox');
      }
    }
    if (ctx.http) {
      for (const b of ctx.http.jsBundles) scan(b.content, { url: b.url }, 'blackbox');
    }
    return out;
  },
};
