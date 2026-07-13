import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import type { ScanContext, ScanReport, Finding } from '../types.js';
import { ScanReportSchema } from '../types.js';
import { rules } from '../rules/index.js';
import { suppress, type SuppressibleFinding } from './suppress.js';
import { grade } from './grade.js';
import { debug } from './helpers.js';
import {
  detectEngines,
  runGitleaks,
  runSemgrep,
  runOsvScanner,
} from './engines.js';
import { normalizeGitleaks, normalizeSemgrep, normalizeOsv } from './normalize.js';

function modeMatches(ruleMode: string, targetType: 'url' | 'repo'): boolean {
  if (ruleMode === 'both') return true;
  return targetType === 'url' ? ruleMode === 'blackbox' : ruleMode === 'whitebox';
}

function dedupeKey(f: Finding): string {
  return `${f.ruleId}|${f.location?.file ?? ''}|${f.location?.line ?? ''}|${f.location?.url ?? ''}`;
}

export interface RunOptions {
  /** Skip external OSS engines even if present (used by fast unit tests). */
  skipEngines?: boolean;
}

export async function runScan(ctx: ScanContext, opts: RunOptions = {}): Promise<ScanReport> {
  const startedAt = new Date().toISOString();
  const targetType = ctx.target.type;

  // 1. Native rules (parallel, each isolated — one throwing never kills the run).
  const applicable = rules.filter((r) => modeMatches(r.mode, targetType));
  debug(`running ${applicable.length} native rules for ${targetType} target`);
  const results = await Promise.all(
    applicable.map(async (rule) => {
      try {
        return await rule.run(ctx);
      } catch (err) {
        debug(`rule ${rule.id} threw`, (err as Error).message);
        return [] as Finding[];
      }
    }),
  );
  const findings: SuppressibleFinding[] = results.flat();

  // 2. Optional OSS engines (repo targets only), merged in when present.
  let engines = { semgrep: false, gitleaks: false, osvScanner: false };
  if (!opts.skipEngines && ctx.repo) {
    engines = await detectEngines();
    const root = ctx.repo.root;
    const engineFindings: Finding[] = [];
    if (engines.gitleaks) engineFindings.push(...normalizeGitleaks(await runGitleaks(root), root));
    if (engines.osvScanner) engineFindings.push(...normalizeOsv(await runOsvScanner(root)));
    if (engines.semgrep) {
      const rulesDir = join(fileURLToPath(new URL('../../semgrep-rules', import.meta.url)));
      engineFindings.push(...normalizeSemgrep(await runSemgrep(root, rulesDir), root));
    }
    findings.push(...engineFindings);
  }

  // 3. Dedupe (native wins over engine duplicates), suppress, grade.
  const seen = new Set<string>();
  const deduped: SuppressibleFinding[] = [];
  for (const f of findings) {
    const key = dedupeKey(f);
    if (seen.has(key)) continue;
    seen.add(key);
    deduped.push(f);
  }

  const clean = suppress(deduped);
  const { grade: g, score, counts } = grade(clean);

  const report: ScanReport = {
    target: ctx.target,
    startedAt,
    finishedAt: new Date().toISOString(),
    grade: g,
    score,
    counts,
    findings: clean.sort((a, b) => severityRank(b.severity) - severityRank(a.severity)),
    engines,
  };

  // 4. Validate against the schema before returning (fail loudly if we drift).
  return ScanReportSchema.parse(report);
}

function severityRank(s: Finding['severity']): number {
  return { critical: 5, high: 4, medium: 3, low: 2, info: 1 }[s];
}
