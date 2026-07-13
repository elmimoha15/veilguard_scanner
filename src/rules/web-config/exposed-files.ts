import type { Rule, Finding, ScanContext } from '../../types.js';
import { classifySecret } from '../../engine/secret-matrix.js';

const TARGETS = [
  { path: '/.env', label: '.env' },
  { path: '/.env.local', label: '.env.local' },
  { path: '/.env.production', label: '.env.production' },
  { path: '/.git/config', label: '.git/config' },
];

/** Black-box: sensitive dotfiles served publicly. */
export const exposedFiles: Rule = {
  id: 'WEB_CONFIG_EXPOSED_FILE',
  category: 'web_config',
  mode: 'blackbox',
  async run(ctx: ScanContext): Promise<Finding[]> {
    const http = ctx.http;
    if (!http || !http.reachable) return [];
    const out: Finding[] = [];

    await Promise.all(
      TARGETS.map(async (t) => {
        const url = new URL(t.path, http.baseUrl).toString();
        const res = await ctx.helpers.httpGet(url);
        if (!res || res.status !== 200) return;
        // Must actually look like the file, not an SPA fallback returning index.html.
        const looksReal =
          (t.path.startsWith('/.env') && /^[A-Z0-9_]+=/m.test(res.body)) ||
          (t.path === '/.git/config' && /\[core\]|\[remote /.test(res.body));
        if (!looksReal) return;

        const hasSecret = /=(.*)/.test(res.body) && classifySecret(res.body).verdict === 'dangerous';
        out.push({
          ruleId: 'WEB_CONFIG_EXPOSED_FILE',
          category: 'web_config',
          severity: t.path.startsWith('/.env') ? 'critical' : 'high',
          cwe: 'CWE-538',
          owasp: 'A05:2021',
          title: `Your ${t.label} file is publicly downloadable`,
          whyItMatters: `Anyone can fetch ${t.label} from your site${hasSecret ? ' — and it contains secrets' : ''}.`,
          location: { url },
          fix: `Stop serving ${t.label}. Ensure your host blocks dotfiles and that secrets are only in server env vars.`,
          fixPrompt: `Block public access to ${t.label} at the web-server/CDN level and rotate any secrets it exposed.`,
          confidence: 'high',
          mode: 'blackbox',
          source: 'native',
        });
      }),
    );
    return out;
  },
};
