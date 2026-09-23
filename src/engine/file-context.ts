/**
 * File-context classification for confidence weighting.
 *
 * A pattern that looks like a secret/vuln is NOT the same risk depending on WHERE
 * it appears. A `postgres://user:password@host` example inside a docs/content file
 * is a teaching sample, not a live credential; the same string in `config.ts` is a
 * real leak. This module classifies a file path and DOWNGRADES findings in
 * clearly-non-production contexts — it only ever downgrades, never upgrades, so
 * real source is untouched. It is the path-based safety net that complements the
 * value-based guards in the rules themselves (JSON-LD/static XSS, example creds).
 */
import type { Finding } from '../types.js';

export type FileClass =
  | 'source'
  | 'config'
  | 'credential'
  | 'content'
  | 'docs'
  | 'example'
  | 'test'
  | 'unknown';

// Example / sample / demo / story files, and `*.example`/`.env.example` — never
// production code. Checked FIRST so `.env.example` is an example, not a credential.
const EXAMPLE =
  /(^|\/)(examples?|demos?|samples?|\.storybook)(\/|$)|\.(example|sample|template)(\.|$)|\.stories\.[cm]?[jt]sx?$|(^|\/)\.env\.(example|sample|template|local|dist)$/i;

// Test / fixture / mock trees (most .test/.spec are already glob-ignored upstream).
const TEST =
  /(^|\/)(tests?|__tests__|__mocks__|spec|cypress|e2e|fixtures?|test-fixtures)(\/|$)|\.(test|spec)\.[cm]?[jt]sx?$/i;

// Documentation / prose that does not execute in production.
const DOCS_EXT = /\.(md|mdx|markdown|mdown|rst|txt|adoc)$/i;
const DOCS_DIR = /(^|\/)(docs?|documentation)(\/|$)/i;
const DOCS_FILE = /(^|\/)(readme|changelog|contributing|license|licence|code_of_conduct|security|authors|notice)(\.[^/]+)?$/i;

// Content / marketing / copy that ships as DATA, not executed sinks (e.g. Veilguard's
// own src/content/*.ts, learn/*). Code-pattern findings here are usually samples in
// article strings — downgraded, but real leaked secrets are still decided by value.
const CONTENT_DIR =
  /(^|\/)(content|contents|blog|articles?|posts?|learn|guides?|marketing|copy|i18n|locales?|translations?)(\/|$)/i;

// Real credential FILES (the file IS the secret). `.env.example` is excluded (EXAMPLE wins).
const CREDENTIAL =
  /(^|\/)(\.env(\.[^/]+)?|id_rsa|id_ed25519)$|-adminsdk-[^/]*\.json$|service-?account[^/]*\.json$|credentials[^/]*\.json$|\.(pem|key|p12|pfx|keystore|jks)$/i;

const CONFIG_EXT = /\.(json|ya?ml|toml|ini|env|conf)$/i;
const CONFIG_FILE = /(^|\/)[^/]*\.config\.[cm]?[jt]sx?$/i;
const SOURCE_EXT_RE = /\.(ts|tsx|js|jsx|mjs|cjs)$/i;

/** Classify a repo-relative file path. Precedence chosen so the safest bucket wins. */
export function classifyFile(path?: string): FileClass {
  if (!path) return 'unknown';
  const p = path.replace(/\\/g, '/');
  if (EXAMPLE.test(p)) return 'example';
  if (TEST.test(p)) return 'test';
  if (DOCS_EXT.test(p) || DOCS_DIR.test(p) || DOCS_FILE.test(p)) return 'docs';
  if (CREDENTIAL.test(p)) return 'credential';
  if (CONTENT_DIR.test(p)) return 'content';
  if (CONFIG_FILE.test(p) || CONFIG_EXT.test(p)) return 'config';
  if (SOURCE_EXT_RE.test(p)) return 'source';
  return 'unknown';
}

/** True for classes that never run in production (safe to downgrade wholesale). */
function isNonShipping(cls: FileClass): boolean {
  return cls === 'docs' || cls === 'example' || cls === 'test';
}

function capLow(sev: Finding['severity']): Finding['severity'] {
  return sev === 'critical' || sev === 'high' || sev === 'medium' ? 'low' : sev;
}

const NOTE: Record<'docs' | 'example' | 'test' | 'content', string> = {
  docs: 'Found in a documentation file — likely a teaching example, not live code. Verify it is not a real value before acting. ',
  example: 'Found in an example/sample file — likely a template, not live code. Verify it is not a real value before acting. ',
  test: 'Found in a test/fixture file — likely intentional test data, not live code. Verify before acting. ',
  content: 'Found in a content/marketing file — likely a sample in copy, not an executed code path. Verify before acting. ',
};

// Code-pattern categories whose matches inside CONTENT prose are usually samples
// in an article/marketing copy (e.g. a "don't do this" NEXT_PUBLIC_ example).
// Secrets are intentionally NOT here: a real leaked key in a content .ts is still a
// real leak, so secrets are left to the value-based classifier (secret-matrix).
const CONTENT_DOWNGRADE_CATEGORIES = new Set(['injection', 'api_webhooks', 'business_logic', 'platform']);

/**
 * Downgrade a finding based on where it was found. Returns the finding unchanged
 * for real source/config/credential/unknown. Never raises severity/confidence.
 */
export function contextualize(f: Finding): Finding {
  const cls = classifyFile(f.location?.file);

  if (isNonShipping(cls)) {
    return {
      ...f,
      severity: capLow(f.severity),
      confidence: 'low',
      whyItMatters: NOTE[cls as 'docs' | 'example' | 'test'] + f.whyItMatters,
    };
  }

  if (cls === 'content' && CONTENT_DOWNGRADE_CATEGORIES.has(f.category)) {
    return {
      ...f,
      severity: capLow(f.severity),
      confidence: 'low',
      whyItMatters: NOTE.content + f.whyItMatters,
    };
  }

  return f;
}
