/**
 * Evidence helpers shared by every rule. The precision principle: a finding at
 * medium+ needs PROOF. A variable name, a word in prose, or a placeholder value
 * is never proof. These helpers answer "is this a real-looking secret VALUE?"
 * and "is this obviously a placeholder/example?" in one place, so rules stay
 * consistent and every false positive fixed here is fixed everywhere.
 */
import { entropy } from './helpers.js';
import { classifySecret, looksLikeExampleConnString } from './secret-matrix.js';

const CONN_STRING = /^(?:postgres|postgresql|mysql|mongodb(?:\+srv)?):\/\//i;

/**
 * A PEM private key is only real when the header is followed by an actual
 * base64 key body. A bare header is what PEM-parsing code and crypto libraries
 * contain (`'-----BEGIN PRIVATE KEY-----\n' + b64`), not a leaked key.
 */
export function hasPemBody(text: string, headerIndex: number): boolean {
  const after = text.slice(headerIndex, headerIndex + 400).replace(/\\n|\\r/g, '\n');
  const m = after.match(/-----BEGIN [A-Z ]*PRIVATE KEY-----\s*([A-Za-z0-9+/=\s]{40,})/);
  return !!m && m[1]!.replace(/\s/g, '').length >= 40;
}

/** Words that mark a value as an example/placeholder, wherever they appear in it. */
const PLACEHOLDER_WORD =
  /(example|sample|dummy|placeholder|changeme|change[_-]?me|redacted|your[_-]?(key|secret|token|password|api)|insert[_-]?(key|here)|replace[_-]?me|fake|mock|lorem|todo|xxxx|\*{3,}|<[^>]+>|\$\{[^}]+\}|%[A-Z_]+%|\{\{[^}]+\}\})/i;

/** Whole-value placeholders that are short/common enough to match exactly. */
const PLACEHOLDER_EXACT = /^(test|testing|secret|password|passwd|pass|pwd|token|key|apikey|api_key|foo|bar|baz|abc123|123456|null|undefined|none|n\/a|tbd|-|\.\.\.|…)$/i;

/** AWS's documented example credentials (appear in thousands of docs/tutorials). */
const KNOWN_EXAMPLES = /AKIAIOSFODNN7EXAMPLE|wJalrXUtnFEMI\/K7MDENG\/bPxRfiCYEXAMPLEKEY|sk_(live|test)_(4eC39HqLyjWDarjtT1zdp7dc|51H)?x{6,}/i;

/** True when the value is one character repeated, e.g. `xxxxxxxx`, `00000000`. */
function isRepeated(v: string): boolean {
  return v.length >= 4 && /^(.)\1+$/.test(v);
}

/** True for long ascending/descending runs like `abcdefgh`, `123456789`. */
function isSequential(v: string): boolean {
  if (v.length < 6) return false;
  let up = 0;
  let down = 0;
  for (let i = 1; i < v.length; i++) {
    const d = v.charCodeAt(i) - v.charCodeAt(i - 1);
    if (d === 1) up++;
    else if (d === -1) down++;
  }
  return up >= v.length - 2 || down >= v.length - 2;
}

/** Strip quotes and a provider prefix so the checks look at the random body. */
function body(v: string): string {
  return v
    .trim()
    .replace(/^["'`]|["'`]$/g, '')
    .replace(/^(sk|rk|pk)_(live|test)_|^whsec_|^sb_(secret|publishable)_|^AKIA|^ghp_|^xox[abp]-/i, '');
}

/**
 * True when a value is obviously a placeholder/example, not a credential:
 * example words anywhere, template tokens (`${X}`, `<key>`), repeated or
 * sequential characters, AWS's documented example keys, or a connection string
 * pointing at localhost with a default password.
 */
export function isPlaceholder(value: string): boolean {
  const v = value.trim().replace(/^["'`]|["'`]$/g, '');
  if (!v) return true;
  // Connection strings are judged on the PASSWORD and host only: a real password
  // to `db.internal.example.com` is still a real leak.
  if (CONN_STRING.test(v)) return looksLikeExampleConnString(v) || isLocalDevConnString(v);
  if (KNOWN_EXAMPLES.test(v)) return true;
  if (PLACEHOLDER_EXACT.test(v)) return true;
  if (PLACEHOLDER_WORD.test(v)) return true;
  const b = body(v);
  if (isRepeated(b) || isSequential(b)) return true;
  // A long mask run inside the body (sk_live_51Hxxxxxxxxxx…) is a demo value.
  if (/(.)\1{7,}/.test(b)) return true;
  return false;
}

/**
 * A DB URL to localhost / docker-compose defaults (`postgres:postgres@localhost`)
 * is local-dev scaffolding, not a production credential.
 */
export function isLocalDevConnString(v: string): boolean {
  const m = v.match(/^(?:postgres|postgresql|mysql|mongodb(?:\+srv)?):\/\/([^:@/\s]+):([^@/\s]+)@([^:/?\s]+)/i);
  if (!m) return false;
  const host = m[3]!.toLowerCase();
  return host === 'localhost' || host === '127.0.0.1' || host === '0.0.0.0' || host === 'db' || host === 'host.docker.internal' || host === 'postgres' || host === 'mysql' || host === 'mongo';
}

/**
 * True when `value` looks like a REAL secret: not a placeholder, not
 * public-by-design (Stripe pk_, Supabase anon/publishable, Firebase AIza,
 * PostHog phc_, Sentry DSN), long enough, and random enough. Provider-format
 * tokens (sk_live_…, whsec_…) only need to pass the placeholder check, because
 * their format is already the proof; generic values also need length + entropy.
 */
export function looksLikeSecretValue(value: string): boolean {
  const v = value.trim().replace(/^["'`]|["'`]$/g, '');
  if (isPlaceholder(v)) return false;
  const c = classifySecret(v);
  if (c.verdict === 'public') return false;
  if (c.verdict === 'dangerous') return true;
  // A URL is only secret if it carries credentials or a token parameter; an
  // email address never is.
  if (/^[a-z][a-z0-9+.-]*:\/\//i.test(v)) return /:\/\/[^/\s:@]+:[^/\s@]+@|[?&](key|token|secret|sig|signature|password|access_token)=/i.test(v);
  if (/^[^\s@]+@[^\s@]+\.[a-z]{2,}$/i.test(v)) return false;
  const b = body(v);
  if (b.length < 16) return false;
  if (/\s/.test(b)) return false; // prose, not a token
  return entropy(b) >= 3.5;
}

/**
 * Redact a secret so only a short, recognisable prefix remains, e.g.
 * `sk_live_51Ab****`. Never returns enough of the value to use it.
 */
export function redactSecret(value: string): string {
  const v = value.trim().replace(/^["'`]|["'`]$/g, '');
  const prefix = v.match(/^((?:sk|rk|pk)_(?:live|test)_|whsec_|sb_(?:secret|publishable)_|AKIA|ghp_|xox[abp]-|eyJ|-----BEGIN [A-Z ]*-----)/)?.[0] ?? '';
  const rest = v.slice(prefix.length);
  const keep = prefix.startsWith('-----') ? 0 : Math.min(4, Math.max(0, rest.length - 8));
  return `${prefix}${rest.slice(0, keep)}****`;
}
