import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import type { ScanContext, ScanReport, Finding, PassedCheck } from '../types.js';
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

/**
 * A stable, deterministic identity for a finding — a short hash of its
 * ruleId + location. Consumers (e.g. the scan service) use this as a document
 * id so that re-running a scan overwrites rather than duplicates findings.
 */
export function findingId(f: Finding): string {
  const key = dedupeKey(f);
  let h = 2166136261; // FNV-1a
  for (let i = 0; i < key.length; i++) {
    h ^= key.charCodeAt(i);
    h = Math.imul(h, 16777619);
  }
  return (h >>> 0).toString(36).padStart(7, '0');
}

export interface ScanProgress {
  done: number;
  total: number;
  phase: string;
}

export interface RunOptions {
  /** Skip external OSS engines even if present (used by fast unit tests). */
  skipEngines?: boolean;
  /**
   * Called once per finding as it is produced (post-suppression, post-dedupe),
   * enabling live streaming. Awaited, so a slow sink applies backpressure.
   */
  onFinding?: (finding: Finding) => void | Promise<void>;
  /** Called after each rule completes, with cumulative progress. Awaited. */
  onProgress?: (progress: ScanProgress) => void | Promise<void>;
}

export async function runScan(ctx: ScanContext, opts: RunOptions = {}): Promise<ScanReport> {
  const startedAt = new Date().toISOString();
  const targetType = ctx.target.type;

  const applicable = rules.filter((r) => modeMatches(r.mode, targetType));
  debug(`running ${applicable.length} native rules for ${targetType} target`);

  // Engines add one extra "phase" to the progress total when they will run.
  const willRunEngines = !opts.skipEngines && !!ctx.repo;
  const total = applicable.length + (willRunEngines ? 1 : 0);

  const seen = new Set<string>();
  const collected: SuppressibleFinding[] = [];
  let done = 0;

  // Positive results: rules call ctx.reportPass() when they verify a good practice.
  // Deduped by id at the end (a rule may report the same pass more than once).
  const passSeen = new Set<string>();
  const passed: PassedCheck[] = [];
  ctx.reportPass = (check: PassedCheck) => {
    if (passSeen.has(check.id)) return;
    passSeen.add(check.id);
    passed.push(check);
  };

  // Add-if-new + suppress happens synchronously before any await, so concurrent
  // rule callbacks can't race the `seen` set.
  const emit = async (raw: SuppressibleFinding[]): Promise<void> => {
    const kept = suppress(raw);
    for (const f of kept) {
      const key = dedupeKey(f);
      if (seen.has(key)) continue;
      seen.add(key);
      collected.push(f);
      if (opts.onFinding) await opts.onFinding(f);
    }
  };

  // 1. Native rules (parallel, each isolated — one throwing never kills the run).
  await Promise.all(
    applicable.map(async (rule) => {
      let ruleFindings: SuppressibleFinding[] = [];
      try {
        ruleFindings = (await rule.run(ctx)) as SuppressibleFinding[];
      } catch (err) {
        debug(`rule ${rule.id} threw`, (err as Error).message);
      }
      await emit(ruleFindings);
      const progress: ScanProgress = { done: ++done, total, phase: rule.category };
      if (opts.onProgress) await opts.onProgress(progress);
    }),
  );

  // 2. Optional OSS engines (repo targets only), merged in when present.
  let engines = { semgrep: false, gitleaks: false, osvScanner: false };
  if (willRunEngines && ctx.repo) {
    engines = await detectEngines();
    const root = ctx.repo.root;
    const engineFindings: Finding[] = [];
    if (engines.gitleaks) engineFindings.push(...normalizeGitleaks(await runGitleaks(root), root));
    if (engines.osvScanner) engineFindings.push(...normalizeOsv(await runOsvScanner(root)));
    if (engines.semgrep) {
      const rulesDir = join(fileURLToPath(new URL('../../semgrep-rules', import.meta.url)));
      engineFindings.push(...normalizeSemgrep(await runSemgrep(root, rulesDir), root));
    }
    await emit(engineFindings as SuppressibleFinding[]);
    const progress: ScanProgress = { done: ++done, total, phase: 'dependencies' };
    if (opts.onProgress) await opts.onProgress(progress);
  }

  // 3. Grade the fully-collected (already deduped + suppressed) set. Passed checks
  //    carry no weight — they only populate counts.passed for display.
  const { grade: g, score, counts } = grade(collected);
  counts.passed = passed.length;

  const report: ScanReport = {
    target: ctx.target,
    startedAt,
    finishedAt: new Date().toISOString(),
    grade: g,
    score,
    counts,
    findings: collected.sort((a, b) => severityRank(b.severity) - severityRank(a.severity)),
    passed: passed.sort((a, b) => a.category.localeCompare(b.category) || a.title.localeCompare(b.title)),
    engines,
  };

  // 4. Validate against the schema before returning (fail loudly if we drift).
  return ScanReportSchema.parse(report);
}

function severityRank(s: Finding['severity']): number {
  return { critical: 5, high: 4, medium: 3, low: 2, info: 1 }[s];
}
