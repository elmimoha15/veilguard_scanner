import { relative } from 'node:path';
import type { Finding } from '../types.js';
import type { SuppressibleFinding } from './suppress.js';
import { classifySecret } from './secret-matrix.js';
import { parseVersion, compare } from './version.js';
import { debug } from './helpers.js';

function safeJson<T>(raw: string | null): T | null {
  if (!raw) return null;
  try {
    return JSON.parse(raw) as T;
  } catch {
    debug('engine output was not valid JSON');
    return null;
  }
}

/**
 * gitleaks JSON → secret Findings, routed through the SAME secret classifier as
 * our native rules. We attach the raw matched value as `_raw` so suppress.ts
 * drops public-by-design keys (Stripe `pk_`, Supabase anon/publishable, Firebase
 * `AIza`, placeholders, example connection strings), and we set severity /
 * confidence from the classification instead of hardcoding everything critical.
 */
export function normalizeGitleaks(raw: string | null, root: string): SuppressibleFinding[] {
  const data = safeJson<any[]>(raw);
  if (!Array.isArray(data)) return [];
  const out: SuppressibleFinding[] = [];
  for (const r of data) {
    const rawValue = String(r.Secret ?? r.Match ?? '');
    if (!rawValue) continue;
    const line = r.Match ? String(r.Match) : undefined;
    const c = classifySecret(rawValue, { line });

    // Public-by-design values are not leaks — drop them here (suppress.ts
    // double-guards via `_raw`, but dropping early keeps the stream clean).
    if (c.verdict === 'public') {
      debug(`gitleaks ${r.RuleID}: classified public (${c.reason}) — not a leak`);
      continue;
    }

    // Severity/confidence from the classifier, not hardcoded.
    const dangerous = c.verdict === 'dangerous';
    const severity: Finding['severity'] = dangerous ? 'critical' : 'high';
    const confidence: Finding['confidence'] = dangerous ? 'high' : 'medium';

    const desc = r.Description ?? r.RuleID ?? 'credential';
    const inHistory = r.Commit && String(r.Commit).length > 0;

    out.push({
      ruleId: `GITLEAKS_${String(r.RuleID ?? 'SECRET').toUpperCase()}`,
      category: 'secrets',
      severity,
      cwe: 'CWE-798',
      title: `Hardcoded secret in your code: ${desc}`,
      whyItMatters: dangerous
        ? 'This looks like a real credential committed to the repo. Anyone who can see the code — or its git history — can use it to access your systems.'
        : 'A value matching a known secret pattern is committed to the repo. If it is a real credential, anyone who sees the code or its git history can use it.',
      evidence: rawValue ? `${rawValue.slice(0, 8)}… (redacted)` : undefined,
      location: { file: r.File ? relative(root, r.File) : undefined, line: r.StartLine },
      fix: `Rotate this credential now, then store it in an environment variable and read it from there (never commit it).${
        inHistory ? ' It also remains in your git history — purge it (e.g. with git filter-repo) after rotating.' : ''
      }`,
      fixPrompt: `A secret (${desc}) is hardcoded in the repo. Move it to an environment variable, read it from process.env, and remove the literal from the code. Then rotate the credential since it was exposed.`,
      confidence,
      mode: 'whitebox',
      source: 'gitleaks',
      // Side channel for suppress.ts (stripped before output).
      _raw: rawValue,
      _line: line,
    });
  }
  return out;
}

/** Semgrep JSON → Findings (best-effort mapping of severity). */
export function normalizeSemgrep(raw: string | null, root: string): Finding[] {
  const data = safeJson<{ results?: any[] }>(raw);
  if (!data?.results) return [];
  const sevMap: Record<string, Finding['severity']> = { ERROR: 'high', WARNING: 'medium', INFO: 'low' };
  return data.results.map((r) => ({
    ruleId: `SEMGREP_${String(r.check_id ?? 'FINDING').split('.').pop()!.toUpperCase()}`,
    category: 'injection' as const,
    severity: sevMap[r.extra?.severity as string] ?? 'medium',
    title: r.extra?.message ? String(r.extra.message).slice(0, 120) : 'Semgrep finding',
    whyItMatters: 'A code pattern matching a known-dangerous rule was found.',
    location: { file: r.path ? relative(root, r.path) : undefined, line: r.start?.line },
    confidence: 'medium' as const,
    mode: 'whitebox' as const,
    source: 'semgrep' as const,
  }));
}

/** Map an OSV advisory to our severity band — from the advisory, not hardcoded. */
function osvSeverity(vuln: any, pkg: any): Finding['severity'] {
  const label = String(
    vuln?.database_specific?.severity ??
      pkg?.database_specific?.severity ??
      (Array.isArray(vuln?.affected) ? vuln.affected[0]?.database_specific?.severity : '') ??
      '',
  ).toUpperCase();
  if (label.includes('CRITICAL')) return 'critical';
  if (label.includes('HIGH')) return 'high';
  if (label.includes('MODERATE') || label.includes('MEDIUM')) return 'medium';
  if (label.includes('LOW')) return 'low';
  // No label: a scored CVSS entry indicates a real, rated vuln → high; otherwise
  // medium (honest default rather than an inflated hardcoded "high").
  return Array.isArray(vuln?.severity) && vuln.severity.length > 0 ? 'high' : 'medium';
}

const SEV_RANK: Record<Finding['severity'], number> = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };

/** First "fixed" version published for `pkgName` in this advisory, if any. */
function osvFixedVersion(vuln: any, pkgName: string): string | null {
  for (const aff of vuln?.affected ?? []) {
    if (aff?.package?.name && aff.package.name !== pkgName) continue;
    for (const range of aff?.ranges ?? []) {
      for (const ev of range?.events ?? []) {
        if (ev?.fixed) return String(ev.fixed);
      }
    }
  }
  return null;
}

/** Highest parseable version in the list (the lowest release that fixes them all). */
function maxVersion(versions: string[]): string | null {
  let best: string | null = null;
  let bestSv = null as ReturnType<typeof parseVersion>;
  for (const v of versions) {
    const sv = parseVersion(v);
    if (!sv) continue;
    if (!bestSv || compare(sv, bestSv) > 0) {
      bestSv = sv;
      best = v;
    }
  }
  return best;
}

/**
 * osv-scanner JSON → dependency Findings, GROUPED to one finding per vulnerable
 * package (a modern Next.js app can match dozens of advisories — one finding per
 * advisory is unusable). Severity is the worst advisory; the fix upgrades to the
 * lowest version that resolves them all; the advisory ids are listed in the body.
 */
export function normalizeOsv(raw: string | null): Finding[] {
  const data = safeJson<{ results?: any[] }>(raw);
  if (!data?.results) return [];
  const findings: Finding[] = [];
  for (const res of data.results) {
    for (const pkg of res.packages ?? []) {
      const vulns = pkg.vulnerabilities ?? [];
      if (vulns.length === 0) continue;
      const name = pkg.package?.name ?? 'dependency';
      const version = pkg.package?.version ?? 'unknown';

      const ids = vulns.map((v: any) => String(v.id ?? 'ADVISORY'));
      const sevs = vulns.map((v: any) => osvSeverity(v, pkg));
      const worst = sevs.reduce((a: Finding['severity'], b: Finding['severity']) => (SEV_RANK[b] > SEV_RANK[a] ? b : a), 'low');
      const criticalCount = sevs.filter((s: Finding['severity']) => s === 'critical').length;

      const fixedVersions = vulns.map((v: any) => osvFixedVersion(v, name)).filter((x: string | null): x is string => !!x);
      const someUnfixed = fixedVersions.length < vulns.length;
      const target = maxVersion(fixedVersions);

      const n = vulns.length;
      const plural = n === 1 ? 'y' : 'ies';
      const critNote = criticalCount > 0 ? ` (${criticalCount} critical)` : '';
      // Deterministic ruleId per package (order-independent), so re-scans overwrite.
      const ruleId = `OSV_${[...ids].sort()[0]!.toUpperCase()}`;

      findings.push({
        ruleId,
        category: 'dependencies',
        severity: worst,
        cwe: 'CWE-1035',
        owasp: 'A06:2021',
        title: `${name}@${version} has ${n} known vulnerabilit${plural}${critNote}`,
        whyItMatters: `This version of ${name} has ${n} known published vulnerabilit${plural}${critNote}. Attackers scan for exactly these versions. Advisories: ${ids.join(', ')}.`,
        // Keep evidence short (never whole-file content); the ids live in whyItMatters.
        evidence: `${n} advisor${n === 1 ? 'y' : 'ies'}; worst ${worst}`,
        // Package identity is the location so different packages (or the same
        // package at different versions) never collapse into one finding.
        location: { url: `${name}@${version}` },
        fix: target
          ? `Upgrade ${name} to ${target} or later, then re-run your tests.${someUnfixed ? ' (Some advisories have no fix yet.)' : ''}`
          : `Upgrade ${name} to a patched release, then re-run your tests.`,
        fixPrompt: `Upgrade the ${name} dependency${target ? ` to ${target} or later` : ' to the latest patched version'} to resolve these advisories (${ids.join(', ')}), then run the test suite.`,
        confidence: 'high',
        mode: 'whitebox',
        source: 'osv-scanner',
      });
    }
  }
  return findings;
}
