import type { Rule, Finding, ScanContext } from '../../types.js';
import type { SuppressibleFinding } from '../../engine/suppress.js';
import { classifySecret } from '../../engine/secret-matrix.js';
import { safeRegexScan, redact } from '../../engine/helpers.js';
import { CODE_AND_CONFIG_EXT } from '../_shared.js';

/** Raw token patterns that are dangerous the moment they appear in text. */
const DANGEROUS_TOKENS: { id: string; re: RegExp; title: string; why: string; cwe: string }[] = [
  {
    id: 'SECRETS_STRIPE_SECRET_KEY',
    re: /\b(sk|rk)_(live|test)_[A-Za-z0-9]{10,}/g,
    title: 'Your Stripe secret key is exposed',
    why: 'Anyone with this key can create charges, issue refunds, and read customer data as you.',
    cwe: 'CWE-798',
  },
  {
    id: 'SECRETS_STRIPE_WEBHOOK_SECRET',
    re: /\bwhsec_[A-Za-z0-9]{10,}/g,
    title: 'Your Stripe webhook signing secret is exposed',
    why: 'An attacker who has this can forge valid-looking Stripe webhook events.',
    cwe: 'CWE-798',
  },
  {
    id: 'SECRETS_SUPABASE_SERVICE_ROLE',
    re: /\bsb_secret_[A-Za-z0-9]{10,}/g,
    title: 'Your Supabase secret (service-role) key is exposed',
    why: 'This key bypasses all Row Level Security — the holder can read and write every row in your database.',
    cwe: 'CWE-798',
  },
  {
    id: 'SECRETS_AWS_ACCESS_KEY',
    re: /\bAKIA[0-9A-Z]{16}\b/g,
    title: 'An AWS access key is exposed',
    why: 'AWS keys let an attacker run up bills or reach your cloud resources.',
    cwe: 'CWE-798',
  },
  {
    id: 'SECRETS_DB_CONNECTION_STRING',
    re: /\b(postgres|postgresql|mysql|mongodb(\+srv)?):\/\/[^\s:@/"']+:[^\s:@/"']+@[^\s"']+/g,
    title: 'A database connection string with a password is exposed',
    why: 'Anyone who sees it can connect directly to your database.',
    cwe: 'CWE-798',
  },
  {
    id: 'SECRETS_PRIVATE_KEY',
    re: /-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----/g,
    title: 'A private key (service-account credential) is exposed',
    why: 'Private keys authenticate as a trusted service — leaking one is a full credential compromise.',
    cwe: 'CWE-798',
  },
];

const FIX_PROMPT =
  'Move this secret out of the codebase into an environment variable that is NEVER prefixed with NEXT_PUBLIC_/VITE_. Rotate the leaked key in the provider dashboard immediately, and load it server-side only.';

function mk(id: string, opts: { title: string; why: string; cwe: string; file?: string; line?: number; url?: string; raw: string; source: 'blackbox' | 'whitebox' }): SuppressibleFinding {
  return {
    ruleId: id,
    category: 'secrets',
    severity: 'critical',
    cwe: opts.cwe,
    owasp: 'A05:2021',
    title: opts.title,
    whyItMatters: opts.why,
    evidence: redact(opts.raw),
    location: opts.source === 'whitebox' ? { file: opts.file, line: opts.line } : { url: opts.url },
    fix: 'Remove the secret from source, rotate it at the provider, and load it from a server-only env var.',
    fixPrompt: FIX_PROMPT,
    confidence: 'high',
    mode: opts.source,
    source: 'native',
    _raw: opts.raw,
  };
}

function scanText(
  text: string,
  loc: { file?: string; url?: string },
  mode: 'blackbox' | 'whitebox',
): SuppressibleFinding[] {
  const out: SuppressibleFinding[] = [];

  // 1. Known-dangerous raw tokens.
  for (const t of DANGEROUS_TOKENS) {
    for (const hit of safeRegexScan(text, t.re)) {
      out.push(mk(t.id, { title: t.title, why: t.why, cwe: t.cwe, file: loc.file, url: loc.url, line: hit.line, raw: hit.match, source: mode }));
    }
  }

  // 2. Supabase-style JWTs whose role claim is service_role (looks anon, isn't).
  for (const hit of safeRegexScan(text, /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{5,}/g)) {
    const c = classifySecret(hit.match);
    if (c.verdict === 'dangerous') {
      out.push(
        mk('SECRETS_SUPABASE_SERVICE_ROLE_JWT', {
          title: 'A Supabase service_role token is exposed',
          why: 'This token bypasses Row Level Security and grants full database access.',
          cwe: 'CWE-798',
          file: loc.file,
          url: loc.url,
          line: hit.line,
          raw: hit.match,
          source: mode,
        }),
      );
    }
  }

  return out;
}

export const hardcodedSecrets: Rule = {
  id: 'SECRETS_HARDCODED',
  category: 'secrets',
  mode: 'both',
  async run(ctx: ScanContext): Promise<Finding[]> {
    const out: SuppressibleFinding[] = [];

    // White-box: scan repo source + config + env files.
    if (ctx.repo) {
      for (const path of ctx.repo.files) {
        if (!CODE_AND_CONFIG_EXT.test(path) && !/(^|\/)\.env/.test(path) && !/service-account|serviceAccount|credentials/.test(path)) {
          continue;
        }
        const content = ctx.repo.readFile(path);
        if (content === null) continue;
        out.push(...scanText(content, { file: path }, 'whitebox'));
      }
    }

    // Black-box: scan fetched JS bundles + homepage HTML.
    if (ctx.http) {
      const sources = [
        { url: ctx.http.baseUrl, content: ctx.http.homepageHtml },
        ...ctx.http.jsBundles,
      ];
      for (const s of sources) {
        out.push(...scanText(s.content, { url: s.url }, 'blackbox'));
      }
    }

    return out as Finding[];
  },
};
