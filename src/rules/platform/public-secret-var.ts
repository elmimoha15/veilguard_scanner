import type { Rule, Finding, ScanContext } from '../../types.js';
import { safeRegexScan } from '../../engine/helpers.js';
import { SENSITIVE_NAME } from '../../engine/secret-matrix.js';
import { looksLikeSecretValue, isPlaceholder, redactSecret } from '../../engine/evidence.js';
import { regionAt } from '../../engine/ast.js';
import { SOURCE_EXT } from '../_shared.js';

const PREFIX = '(?:NEXT_PUBLIC_|VITE_|PUBLIC_|REACT_APP_)';

/**
 * Names that match the "secret-ish" word list but are public by design, so they
 * never mean a leak: map tokens meant for the browser, admin contact emails and
 * feature flags, password-policy numbers, web3 contract addresses, CSRF header
 * names, and publishable/anon keys.
 */
const PUBLIC_BY_DESIGN =
  /(MAPBOX[A-Z0-9_]*TOKEN|ADMIN_(EMAIL|EMAILS|USER_?ID|URL|PATH|ROUTE)|ENABLE_ADMIN|ADMIN_(ENABLED|PANEL|MODE)|PRIVATE_BETA|PASSWORD_(MIN|MAX)_?LENGTH|PASSWORD_POLICY|CONTRACT_ADDRESS|TOKEN_(ADDRESS|SYMBOL|DECIMALS|LIST|ID)|CSRF[A-Z0-9_]*(HEADER|COOKIE|NAME)|ANON_KEY|PUBLISHABLE|PUBLIC_KEY|TOKEN_(URL|ENDPOINT|EXPIRY|TTL)|SITE_KEY|RECAPTCHA)/;

function sensitive(name: string): boolean {
  return SENSITIVE_NAME.test(name) && !PUBLIC_BY_DESIGN.test(name);
}

const WHY = 'Variables with a public prefix are bundled into your client JavaScript, so their value is visible to every visitor.';

function mkFinding(o: {
  name: string;
  severity: Finding['severity'];
  confidence: Finding['confidence'];
  evidence: string;
  loc: { file?: string; line?: number; url?: string };
  mode: 'whitebox' | 'blackbox';
  title: string;
  verifyHint?: string;
}): Finding {
  return {
    ruleId: 'PLATFORM_PUBLIC_SECRET_VAR',
    category: 'platform',
    severity: o.severity,
    cwe: 'CWE-200',
    owasp: 'A05:2021',
    title: o.title,
    whyItMatters: WHY,
    evidence: o.evidence,
    location: o.loc,
    fix: `Rename ${o.name} to a server-only variable (drop the public prefix), read it only in server code, and rotate the value.`,
    fixPrompt: `Rename the ${o.name} environment variable to remove the public prefix so it isn't bundled into the client, and access it only from server-side code. Rotate the value.`,
    confidence: o.confidence,
    ...(o.verifyHint ? { verifyHint: o.verifyHint } : {}),
    mode: o.mode,
    source: 'native',
  };
}

/** `NAME=value` lines in an env file. */
const ENV_LINE = new RegExp(`^\\s*(?:export\\s+)?(${PREFIX}[A-Z0-9_]+)\\s*=\\s*(.*)$`, 'gm');
/** `NAME: "value"` / `NAME = "value"` / `"NAME":"value"` (source or bundles). */
const ASSIGNED = new RegExp(`["']?\\b(${PREFIX}[A-Z0-9_]+)\\b["']?\\s*[:=]\\s*(["'\`])([^"'\`\\n]{8,200})\\2`, 'g');
/** A real read of the variable in code. */
const ENV_READ = new RegExp(`\\b(?:process\\.env|import\\.meta\\.env)\\.(${PREFIX}[A-Z0-9_]+)\\b`, 'g');

/**
 * Platform gotcha: a SECRET VALUE behind a public prefix (NEXT_PUBLIC_, VITE_…).
 * Those are inlined into the browser bundle at build time, so the value is
 * published. Evidence is required:
 *   - a real-looking secret value assigned to the name (env file, source
 *     literal, or the shipped bundle): HIGH, high confidence;
 *   - code that reads a secret-named public var with no value visible:
 *     LOW, "verify" (we can't see what's set in the hosting dashboard);
 *   - the name merely mentioned (prose, docs, demo copy, error strings, env
 *     schemas, a bundle with no value): NOT a finding.
 */
export const publicSecretVar: Rule = {
  id: 'PLATFORM_PUBLIC_SECRET_VAR',
  category: 'platform',
  mode: 'both',
  async run(ctx: ScanContext): Promise<Finding[]> {
    const out: Finding[] = [];
    const seen = new Set<string>();
    const once = (key: string) => (seen.has(key) ? false : (seen.add(key), true));

    const withValue = (name: string, value: string, loc: { file?: string; line?: number; url?: string }, mode: 'whitebox' | 'blackbox') => {
      if (!sensitive(name) || !looksLikeSecretValue(value)) return;
      if (!once(`v|${loc.file ?? loc.url}|${name}`)) return;
      out.push(mkFinding({
        name,
        severity: 'high',
        confidence: 'high',
        evidence: `${name}=${redactSecret(value)}`,
        loc,
        mode,
        title: mode === 'blackbox' ? `A secret value for "${name}" is shipped to the browser` : `"${name}" holds a secret but is exposed to the browser`,
      }));
    };

    if (ctx.repo) {
      for (const path of ctx.repo.files) {
        const isEnv = /(^|\/)\.env(\.|$)/.test(path);
        const isSource = SOURCE_EXT.test(path);
        if (!isEnv && !isSource) continue;
        const content = ctx.repo.readFile(path);
        if (!content) continue;

        if (isEnv) {
          for (const m of safeRegexScan(content, ENV_LINE)) {
            const name = m.groups[0]!;
            const value = (m.groups[1] ?? '').trim().replace(/\s+#.*$/, '');
            if (!sensitive(name) || !value || isPlaceholder(value)) continue;
            if (looksLikeSecretValue(value)) {
              withValue(name, value, { file: path, line: m.line }, 'whitebox');
            } else if (once(`e|${path}|${name}`)) {
              out.push(mkFinding({
                name, severity: 'medium', confidence: 'low', evidence: `${name}=****`, loc: { file: path, line: m.line }, mode: 'whitebox',
                title: `"${name}" may hold a secret behind a public prefix`,
                verifyHint: `Check whether the value of ${name} is a real secret. If it is, rename the variable without the public prefix and rotate it.`,
              }));
            }
          }
          continue;
        }

        // Source: only real code counts, never comments or string prose.
        const region = regionAt(ctx.repo.astFor(path));
        for (const m of safeRegexScan(content, ASSIGNED)) {
          if (region(m.index) === 'comment') continue;
          withValue(m.groups[0]!, m.groups[2]!, { file: path, line: m.line }, 'whitebox');
        }
        for (const m of safeRegexScan(content, ENV_READ)) {
          const name = m.groups[0]!;
          if (!sensitive(name) || region(m.index) !== 'code') continue;
          if (!once(`r|${path}|${name}`)) continue;
          out.push(mkFinding({
            name, severity: 'high', confidence: 'low', evidence: `process.env.${name}`, loc: { file: path, line: m.line }, mode: 'whitebox',
            title: `"${name}" is read in code behind a public prefix`,
            verifyHint: `If a real secret is set for ${name} in your hosting dashboard, it is shipped to every visitor. Check what value it holds; if it's a secret, rename it without the public prefix and rotate it.`,
          }));
        }
      }
    }

    // URL scans: the bundle has no file paths and is full of copy and strings, so
    // only a real secret VALUE next to the name counts. A bare name never does.
    if (ctx.http) {
      for (const b of ctx.http.jsBundles) {
        for (const m of safeRegexScan(b.content, ASSIGNED)) {
          withValue(m.groups[0]!, m.groups[2]!, { url: b.url }, 'blackbox');
        }
      }
    }
    return out;
  },
};
