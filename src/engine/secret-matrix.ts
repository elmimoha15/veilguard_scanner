/**
 * The single source of truth for "is this token a real leaked secret, or is it
 * public-by-design?". Used by the secret-detection rules to decide what to emit
 * and by suppress.ts as a final safety pass. Kept as per-provider tables so new
 * providers are a one-line addition.
 */

export type Verdict = 'dangerous' | 'public' | 'unknown';

export interface Classification {
  verdict: Verdict;
  provider: string;
  reason: string;
}

export interface SecretContext {
  /** Variable / property / env-var name the value was assigned to, if known. */
  name?: string;
  /** Surrounding snippet (e.g. the whole line) for extra signal. */
  line?: string;
  /** Repo-relative file path the value came from, if known. */
  path?: string;
}

// A placeholder PASSWORD segment — the actual secret in a connection string. We
// key example-detection on the password (not the username: `admin`/`root`/`user`
// can all be real), so a real password like `Xk9fJ2Lm` still fires as a leak.
const EXAMPLE_PASS =
  /^(password|passwd|pass|pwd|your[_-]?password|changeme|change_?me|example|placeholder|redacted|secret|s3cret|xxx+|test|dummy|mypassword|123456)$/i;

/**
 * True for an example/placeholder DB connection string like
 * `postgres://user:password@host` or `mongodb+srv://x:${DB_PASS}@…` — the password
 * is a generic placeholder, a bracket/interpolation token (`<pass>`, `${...}`,
 * `%VAR%`), or a repeated-char mask. A real string (high-entropy password) does
 * NOT match, so it still fires. Value-based → works regardless of the file.
 */
export function looksLikeExampleConnString(v: string): boolean {
  const m = v.match(/^(?:postgres|postgresql|mysql|mongodb(?:\+srv)?):\/\/([^:@/\s]+):([^@/\s]+)@/i);
  if (!m) return false;
  const pass = m[2]!;
  if (/^[<${%]/.test(pass)) return true; // ${DB_PASSWORD}, <password>, %PASS%
  if (EXAMPLE_PASS.test(pass)) return true; // literal placeholder word
  if (/^(.)\1{2,}$/.test(pass)) return true; // xxxx / **** mask
  return false;
}

/** Patterns that are ALWAYS dangerous — never suppressed. */
const DANGEROUS: { provider: string; re: RegExp; reason: string }[] = [
  { provider: 'stripe', re: /\b(sk|rk)_(live|test)_[A-Za-z0-9]{24,}/, reason: 'Stripe secret/restricted key' },
  { provider: 'stripe', re: /\bwhsec_[A-Za-z0-9]{10,}/, reason: 'Stripe webhook signing secret' },
  { provider: 'supabase', re: /\bsb_secret_[A-Za-z0-9]{10,}/, reason: 'Supabase secret key' },
  { provider: 'aws', re: /\bAKIA[0-9A-Z]{16}\b/, reason: 'AWS access key id' },
  { provider: 'db', re: /\b(postgres|postgresql|mysql|mongodb(\+srv)?):\/\/[^\s:@/]+:[^\s:@/]+@/, reason: 'DB connection string with embedded password' },
  { provider: 'firebase', re: /-----BEGIN (RSA )?PRIVATE KEY-----/, reason: 'Private key (service-account)' },
];

/** Patterns that are public-by-design — suppressed unless proven otherwise. */
const PUBLIC: { provider: string; re: RegExp; reason: string }[] = [
  { provider: 'stripe', re: /\bpk_(live|test)_[A-Za-z0-9]{10,}/, reason: 'Stripe publishable key (public by design)' },
  { provider: 'supabase', re: /\bsb_publishable_[A-Za-z0-9]{10,}/, reason: 'Supabase publishable key (public by design)' },
  { provider: 'firebase', re: /\bAIza[0-9A-Za-z_-]{35}\b/, reason: 'Firebase web apiKey (public by design)' },
  { provider: 'posthog', re: /\bphc_[A-Za-z0-9]{20,}/, reason: 'PostHog project key (public by design)' },
  { provider: 'sentry', re: /https:\/\/[a-f0-9]{16,}@[a-z0-9.-]+\.ingest\.sentry\.io\/\d+/, reason: 'Sentry DSN (public by design)' },
];

const PLACEHOLDERS = /^(your[_-]?key[_-]?here|example|changeme|change_me|placeholder|abc123|x{3,}|test|dummy|todo|sk_live_xxx|foo|bar)$/i;

const FIREBASE_WEB_CONFIG_KEYS = new Set([
  'apikey',
  'authdomain',
  'projectid',
  'storagebucket',
  'messagingsenderid',
  'appid',
  'measurementid',
]);

const SENSITIVE_NAME = /(secret|private|service_?role|password|passwd|token|admin|credential)/i;

/** Decode a JWT payload's `role` claim, if this looks like a Supabase JWT. */
function jwtRole(token: string): string | null {
  const parts = token.split('.');
  if (parts.length !== 3) return null;
  try {
    const payload = JSON.parse(Buffer.from(parts[1]!, 'base64url').toString('utf8'));
    return typeof payload.role === 'string' ? payload.role : null;
  } catch {
    return null;
  }
}

/**
 * Classify a matched token given optional context (variable/env name, line).
 * Order of precedence: explicit dangerous patterns → JWT role → placeholders →
 * public patterns → NEXT_PUBLIC-style name rules → unknown.
 */
export function classifySecret(value: string, ctx: SecretContext = {}): Classification {
  const v = value.trim().replace(/^["'`]|["'`]$/g, '');
  const name = ctx.name ?? '';

  // 0. Example/placeholder connection strings (postgres://user:password@host) are
  //    teaching samples, not leaks — checked BEFORE the dangerous DB pattern.
  if (looksLikeExampleConnString(v)) {
    return { verdict: 'public', provider: 'placeholder', reason: 'Example connection string (placeholder credentials)' };
  }

  // 1. Always-dangerous providers.
  for (const d of DANGEROUS) {
    if (d.re.test(v)) return { verdict: 'dangerous', provider: d.provider, reason: d.reason };
  }

  // 2. Supabase JWT: role claim decides. service_role is dangerous even though
  //    it "looks like" an anon key.
  const role = jwtRole(v);
  if (role) {
    if (role === 'service_role') {
      return { verdict: 'dangerous', provider: 'supabase', reason: 'Supabase JWT with service_role claim' };
    }
    if (role === 'anon') {
      return { verdict: 'public', provider: 'supabase', reason: 'Supabase anon JWT (public by design)' };
    }
  }

  // 3. Obvious placeholders are never real secrets.
  if (PLACEHOLDERS.test(v)) {
    return { verdict: 'public', provider: 'placeholder', reason: 'Placeholder value, not a real secret' };
  }

  // 4. Firebase web-config field names are public.
  if (FIREBASE_WEB_CONFIG_KEYS.has(name.toLowerCase())) {
    return { verdict: 'public', provider: 'firebase', reason: `Firebase web config field "${name}" (public by design)` };
  }

  // 5. Known public token shapes.
  for (const p of PUBLIC) {
    if (p.re.test(v)) return { verdict: 'public', provider: p.provider, reason: p.reason };
  }

  // 6. NEXT_PUBLIC_/VITE_/PUBLIC_ prefixed names are public UNLESS the name also
  //    screams "secret". A secret-named var behind NEXT_PUBLIC_ is dangerous
  //    (it gets inlined into the browser bundle).
  if (/^(NEXT_PUBLIC_|VITE_|PUBLIC_|REACT_APP_)/.test(name)) {
    if (SENSITIVE_NAME.test(name)) {
      return { verdict: 'dangerous', provider: 'platform', reason: `Secret-named var "${name}" exposed via a public prefix` };
    }
    return { verdict: 'public', provider: 'platform', reason: `"${name}" is behind a public prefix and not secret-named` };
  }

  return { verdict: 'unknown', provider: 'generic', reason: 'Unclassified token' };
}

export { SENSITIVE_NAME };
