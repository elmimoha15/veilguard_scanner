import type { Rule, Finding, ScanContext } from '../../types.js';

const HEADER_NAMES = [
  'content-security-policy',
  'strict-transport-security',
  'x-frame-options',
  'x-content-type-options',
  'referrer-policy',
  'permissions-policy',
];

/**
 * White-box config review of next.config.*:
 *  - no security headers configured,
 *  - wildcard CORS combined with credentials.
 */
export const nextConfig: Rule = {
  id: 'WEB_CONFIG_NEXTCONFIG',
  category: 'web_config',
  mode: 'whitebox',
  async run(ctx: ScanContext): Promise<Finding[]> {
    const repo = ctx.repo;
    if (!repo) return [];

    const configPath = repo.files.find((f) => /(^|\/)next\.config\.(js|ts|mjs|cjs)$/.test(f));
    const out: Finding[] = [];

    // Wildcard CORS + credentials (scan config + any source).
    for (const path of repo.files) {
      if (!/\.(ts|tsx|js|jsx|mjs|cjs)$/.test(path)) continue;
      const content = repo.readFile(path);
      if (!content) continue;
      // Tolerant of header-object formatting like `key:'…', value:'*'`.
      const wildcardOrigin =
        /access-control-allow-origin[\s\S]{0,40}?['"`]\*['"`]/i.test(content) ||
        /\borigin\s*:\s*['"`]\*['"`]/i.test(content);
      const credentials =
        /access-control-allow-credentials[\s\S]{0,40}?['"`]?true/i.test(content) ||
        /\bcredentials\s*:\s*true/i.test(content);
      if (wildcardOrigin && credentials) {
        out.push({
          ruleId: 'WEB_CONFIG_CORS_WILDCARD_CREDENTIALS',
          category: 'web_config',
          severity: 'high',
          cwe: 'CWE-942',
          owasp: 'A05:2021',
          title: 'Your CORS policy lets any website make credentialed requests',
          whyItMatters: 'Allowing `*` origin together with credentials means any malicious site can call your API as your logged-in users.',
          location: { file: path },
          fix: 'Never combine `Access-Control-Allow-Origin: *` with credentials. Allowlist specific trusted origins instead.',
          fixPrompt: 'Fix this CORS configuration: replace the `*` origin with an explicit allowlist of trusted origins when credentials are enabled, or disable credentials.',
          confidence: 'high',
          mode: 'whitebox',
          source: 'native',
        });
      }
    }

    // Missing security headers in next.config.
    if (configPath) {
      const content = repo.readFile(configPath) ?? '';
      const hasHeadersFn = /async\s+headers\s*\(|headers\s*:\s*async|headers\s*\(\)\s*\{/.test(content);
      const present = HEADER_NAMES.filter((h) => content.toLowerCase().includes(h));
      if (!hasHeadersFn || present.length < 2) {
        out.push({
          ruleId: 'WEB_CONFIG_MISSING_SECURITY_HEADERS',
          category: 'web_config',
          severity: 'medium',
          cwe: 'CWE-693',
          owasp: 'A05:2021',
          title: 'Your app doesn’t set security headers',
          whyItMatters: 'Headers like CSP, HSTS and X-Frame-Options block common attacks (clickjacking, protocol downgrade, injection). None are configured.',
          evidence: present.length ? `only found: ${present.join(', ')}` : 'no security headers configured',
          location: { file: configPath },
          fix: 'Add an async headers() function to next.config that sets Content-Security-Policy, Strict-Transport-Security, X-Frame-Options, X-Content-Type-Options, Referrer-Policy and Permissions-Policy.',
          fixPrompt: 'Add an async headers() function to next.config that applies these security headers to all routes: Content-Security-Policy, Strict-Transport-Security (max-age >= 1 year), X-Frame-Options: DENY, X-Content-Type-Options: nosniff, Referrer-Policy, and Permissions-Policy.',
          confidence: 'medium',
          mode: 'whitebox',
          source: 'native',
        });
      }
    }

    return out;
  },
};
