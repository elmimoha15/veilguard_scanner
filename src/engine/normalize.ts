import { relative } from 'node:path';
import type { Finding } from '../types.js';
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

/** gitleaks JSON → secret Findings. */
export function normalizeGitleaks(raw: string | null, root: string): Finding[] {
  const data = safeJson<any[]>(raw);
  if (!Array.isArray(data)) return [];
  return data.map((r) => ({
    ruleId: `GITLEAKS_${String(r.RuleID ?? 'SECRET').toUpperCase()}`,
    category: 'secrets' as const,
    severity: 'critical' as const,
    cwe: 'CWE-798',
    title: `Secret detected: ${r.Description ?? r.RuleID ?? 'credential'}`,
    whyItMatters: 'A committed credential can be used by anyone who sees your code or git history.',
    evidence: r.Match ? `${String(r.Match).slice(0, 12)}… (redacted)` : undefined,
    location: { file: r.File ? relative(root, r.File) : undefined, line: r.StartLine },
    confidence: 'high' as const,
    mode: 'whitebox' as const,
    source: 'gitleaks' as const,
  }));
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

/** osv-scanner JSON → dependency Findings. */
export function normalizeOsv(raw: string | null): Finding[] {
  const data = safeJson<{ results?: any[] }>(raw);
  if (!data?.results) return [];
  const findings: Finding[] = [];
  for (const res of data.results) {
    for (const pkg of res.packages ?? []) {
      for (const vuln of pkg.vulnerabilities ?? []) {
        findings.push({
          ruleId: `OSV_${String(vuln.id ?? 'CVE').toUpperCase()}`,
          category: 'dependencies',
          severity: 'high',
          title: `Vulnerable dependency: ${pkg.package?.name}@${pkg.package?.version}`,
          whyItMatters: vuln.summary ?? 'This dependency version has a known published vulnerability.',
          evidence: vuln.id,
          confidence: 'high',
          mode: 'whitebox',
          source: 'osv-scanner',
        });
      }
    }
  }
  return findings;
}
