import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import type { ScanContext, ScanReport, Finding, PassedCheck, Category } from '../types.js';
import { ScanReportSchema } from '../types.js';
import { rules } from '../rules/index.js';
import { suppress, type SuppressibleFinding } from './suppress.js';
import { contextualize } from './file-context.js';
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
 * A source-agnostic identity for de-duplicating the SAME real issue reported by
 * both a native rule and an external engine (which carry different ruleIds, so
 * dedupeKey alone keeps both). Returns null when a finding has no stable
 * cross-source identity (so it is never merged away).
 *  - secrets: file:line, so a native secret and a gitleaks hit at the same spot
 *    collapse to one.
 * (Dependencies are reconciled separately — package-level — in flushDeps, because
 *  OSV groups many advisories into one finding and must win over the native floor.)
 */
function canonicalIdentity(f: Finding): string | null {
  if (f.category === 'secrets' && f.location?.file) {
    return `secret|${f.location.file}|${f.location.line ?? ''}`;
  }
  return null;
}

/** Package name a dependency finding is about (OSV sets location.url `name@version`;
 *  native rules carry it in title/evidence). Used to dedupe OSV vs the native floor. */
function depPackage(f: Finding): string | null {
  const src = `${f.location?.url ?? ''} ${f.evidence ?? ''} ${f.title}`;
  const m = src.match(/(@?[a-z0-9._/-]+)@\d[\w.-]*/i);
  return m ? m[1]!.toLowerCase() : null;
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
   * Per-engine wall-clock budget (ms). Bounds each external tool so one huge
   * repo can't hang the scan; a tool that exceeds it is dropped and the scan
   * completes with the remaining results. Defaults to the engine module's own.
   */
  engineTimeoutMs?: number;
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
  const seenIdentity = new Set<string>();
  const collected: SuppressibleFinding[] = [];
  // Dependency findings are held and reconciled after the engine phase (so a
  // grouped OSV finding supersedes the native advisory floor for the same
  // package), then streamed/collected like everything else. See flushDeps.
  const depBuffer: SuppressibleFinding[] = [];
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

  // Dedupe (by location + cross-source identity), then collect + stream one
  // finding. The add-if-new bookkeeping is synchronous before any await, so
  // concurrent rule callbacks can't race the `seen` set.
  const commit = async (f: SuppressibleFinding): Promise<void> => {
    const key = dedupeKey(f);
    if (seen.has(key)) return;
    // Cross-source dedupe: skip an engine finding that restates an issue a
    // native rule already reported (native rules run first, so they win).
    const ident = canonicalIdentity(f);
    if (ident && seenIdentity.has(ident)) {
      debug(`deduped ${f.ruleId} @ ${f.location?.file ?? f.location?.url ?? '?'} against native finding`);
      return;
    }
    seen.add(key);
    if (ident) seenIdentity.add(ident);
    collected.push(f);
    if (opts.onFinding) await opts.onFinding(f);
  };

  const emit = async (raw: SuppressibleFinding[]): Promise<void> => {
    const kept = suppress(raw);
    for (const f0 of kept) {
      // Downgrade findings by file context (docs/content/example/test) BEFORE
      // streaming + collecting, so the persisted finding and the grade agree.
      const f = contextualize(f0);
      // Hold dependency findings for cross-source reconciliation (flushDeps).
      if (f.category === 'dependencies') {
        depBuffer.push(f);
        continue;
      }
      await commit(f);
    }
  };

  // Reconcile buffered dependency findings: when OSV produced a grouped finding
  // for a package, drop the native advisory-floor finding for that same package
  // (OSV is comprehensive and wins). Then stream/collect the survivors.
  const flushDeps = async (): Promise<void> => {
    const osvPkgs = new Set<string>();
    for (const f of depBuffer) {
      if (f.source === 'osv-scanner') {
        const p = depPackage(f);
        if (p) osvPkgs.add(p);
      }
    }
    for (const f of depBuffer) {
      if (f.source !== 'osv-scanner') {
        const p = depPackage(f);
        if (p && osvPkgs.has(p)) {
          debug(`deduped native dep ${f.ruleId} (${p}) against OSV finding`);
          continue;
        }
      }
      await commit(f);
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
    const t = opts.engineTimeoutMs;
    const engineFindings: SuppressibleFinding[] = [];
    if (engines.gitleaks) engineFindings.push(...normalizeGitleaks(await runGitleaks(root, t), root));
    if (engines.osvScanner) engineFindings.push(...normalizeOsv(await runOsvScanner(root, t)));
    if (engines.semgrep) {
      const rulesDir = join(fileURLToPath(new URL('../../semgrep-rules', import.meta.url)));
      engineFindings.push(...normalizeSemgrep(await runSemgrep(root, rulesDir, t), root));
    }
    await emit(engineFindings);
    const progress: ScanProgress = { done: ++done, total, phase: 'dependencies' };
    if (opts.onProgress) await opts.onProgress(progress);
  }

  // 2.1 Reconcile + stream the buffered dependency findings (native floor vs
  //     grouped OSV) now that both the native and engine phases are done.
  await flushDeps();

  // 2.5 Category "clean" passes: for check families we ACTUALLY ran (a rule of
  //     that category was applicable to this target) and that produced zero
  //     findings, record an honest "we checked X and found none" pass. Categories
  //     with their own presence passes (secrets/database/web_config) are excluded
  //     to avoid double-reporting.
  const COVERAGE: { category: Category; title: string; detail: string }[] = [
    { category: 'injection', title: 'No injection vulnerabilities found', detail: 'We checked for SQL injection, XSS, command injection and SSRF and found none.' },
    { category: 'auth', title: 'No authentication weaknesses found', detail: 'We checked your auth and access-control code and found no obvious gaps.' },
    { category: 'api_webhooks', title: 'No API or webhook security issues found', detail: 'We checked your API routes and webhooks and found no obvious problems.' },
    { category: 'business_logic', title: 'No business-logic issues found', detail: 'We checked for risky patterns like unrestricted uploads and found none.' },
    { category: 'dependencies', title: 'No known-vulnerable dependencies', detail: 'We checked your dependencies against known advisories and none were flagged.' },
  ];
  const ranCats = new Set(applicable.map((r) => r.category));
  const foundCats = new Set(collected.map((f) => f.category));
  for (const c of COVERAGE) {
    if (ranCats.has(c.category) && !foundCats.has(c.category)) {
      ctx.reportPass?.({
        id: `PASS_CLEAN_${c.category.toUpperCase()}`,
        category: c.category,
        title: c.title,
        detail: c.detail,
        mode: targetType === 'url' ? 'blackbox' : 'whitebox',
      });
    }
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
