import type { Rule, Finding, ScanContext } from '../../types.js';

const REQUIRED: { header: string; label: string; sev: Finding['severity']; pass: string }[] = [
  { header: 'content-security-policy', label: 'Content-Security-Policy', sev: 'medium', pass: 'Content-Security-Policy is set' },
  { header: 'strict-transport-security', label: 'Strict-Transport-Security (HSTS)', sev: 'medium', pass: 'HTTPS is enforced (HSTS)' },
  { header: 'x-frame-options', label: 'X-Frame-Options', sev: 'medium', pass: 'Clickjacking protection is on (X-Frame-Options)' },
  { header: 'x-content-type-options', label: 'X-Content-Type-Options', sev: 'low', pass: 'MIME-sniffing protection is on' },
  { header: 'referrer-policy', label: 'Referrer-Policy', sev: 'low', pass: 'Referrer-Policy is set' },
  { header: 'permissions-policy', label: 'Permissions-Policy', sev: 'low', pass: 'Permissions-Policy is set' },
];

/** Black-box: which recommended security headers are missing from the live response. */
export const httpHeaders: Rule = {
  id: 'WEB_CONFIG_HEADERS_LIVE',
  category: 'web_config',
  mode: 'blackbox',
  async run(ctx: ScanContext): Promise<Finding[]> {
    const http = ctx.http;
    if (!http || !http.reachable) return [];
    const out: Finding[] = [];

    for (const r of REQUIRED) {
      if (!(r.header in http.headers)) {
        out.push({
          ruleId: `WEB_CONFIG_MISSING_${r.header.toUpperCase().replace(/-/g, '_')}`,
          category: 'web_config',
          severity: r.sev,
          cwe: 'CWE-693',
          owasp: 'A05:2021',
          title: `Missing security header: ${r.label}`,
          whyItMatters: `The ${r.label} header helps block a class of common web attacks; your site doesn’t send it.`,
          location: { url: http.baseUrl },
          fix: `Set the ${r.label} response header on all routes.`,
          fixPrompt: `Configure your server/framework to send the ${r.label} security header on every response.`,
          confidence: 'high',
          mode: 'blackbox',
          source: 'native',
        });
      } else {
        // The header IS present — a positive result to show the user.
        ctx.reportPass?.({
          id: `PASS_WEB_CONFIG_${r.header.toUpperCase().replace(/-/g, '_')}`,
          category: 'web_config',
          title: r.pass,
          detail: `Your site sends the ${r.label} response header.`,
          mode: 'blackbox',
        });
      }
    }

    // Cookies without HttpOnly/Secure/SameSite.
    for (const cookie of http.cookies) {
      const lc = cookie.toLowerCase();
      if (/session|auth|token|sid/.test(lc) && (!lc.includes('httponly') || !lc.includes('secure'))) {
        out.push({
          ruleId: 'WEB_CONFIG_WEAK_COOKIE',
          category: 'web_config',
          severity: 'medium',
          cwe: 'CWE-1004',
          title: 'A session cookie is missing HttpOnly/Secure flags',
          whyItMatters: 'Cookies without HttpOnly can be stolen by XSS; without Secure they can leak over plain HTTP.',
          evidence: cookie.split('=')[0],
          location: { url: http.baseUrl },
          fix: 'Set HttpOnly, Secure and SameSite on session cookies.',
          fixPrompt: 'Set the HttpOnly, Secure, and SameSite=Lax (or Strict) attributes on this session cookie.',
          confidence: 'medium',
          mode: 'blackbox',
          source: 'native',
        });
      }
    }

    return out;
  },
};
