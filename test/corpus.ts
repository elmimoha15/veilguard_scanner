/**
 * Precision/recall corpus runner, shared by test/corpus.test.ts and the gate.
 *
 *   test-fixtures/corpus/safe/<case>/        real-world SAFE patterns: must produce
 *                                            NO finding at medium+ (low "verify" is ok)
 *   test-fixtures/corpus/vulnerable/<case>/  real vulnerabilities: each expected rule
 *                                            must fire at >= its severity and confidence
 *   test-fixtures/corpus/cases.json          per-case metadata (why it exists, URL-scan
 *                                            inputs, expectations)
 *
 * Every false positive reported by a user becomes a new safe case here.
 */
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { join } from 'node:path';
import { buildContext, extractDiscovered } from '../src/engine/recon.js';
import { runScan } from '../src/engine/runner.js';
import { helpers } from '../src/engine/helpers.js';
import type { Finding, ScanContext, Severity, Confidence } from '../src/types.js';

/** VG_ENGINES=1 runs every scan with the real gitleaks + osv-scanner (as the worker does). */
export const ENGINES = process.env.VG_ENGINES === '1';

export const CORPUS = fileURLToPath(new URL('../test-fixtures/corpus/', import.meta.url));

export interface Expectation { ruleId: string; minSeverity: Severity; minConfidence: Confidence }
export interface CaseMeta {
  kind: 'safe' | 'vulnerable';
  why?: string;
  /** Present for URL-scan cases: what the live site serves. */
  url?: { headers: Record<string, string>; bundles: string[]; html?: string; responses?: Record<string, string> };
  expect?: Expectation[];
  /** Sources whose findings this case doesn't judge (e.g. live OSV advisories). */
  ignoreSources?: Finding['source'][];
}

export const SEV_RANK: Record<Severity, number> = { info: 0, low: 1, medium: 2, high: 3, critical: 4 };
export const CONF_RANK: Record<Confidence, number> = { low: 0, medium: 1, high: 2 };

export function loadCases(): [string, CaseMeta][] {
  return Object.entries(JSON.parse(readFileSync(join(CORPUS, 'cases.json'), 'utf8')) as Record<string, CaseMeta>);
}

/** Scan one case through the real engine (URL cases get a stubbed, offline network). */
export async function scanCase(name: string, meta: CaseMeta): Promise<Finding[]> {
  const dir = join(CORPUS, name);
  const keep = (fs: Finding[]) => fs.filter((f) => !meta.ignoreSources?.includes(f.source));
  if (!meta.url) {
    const ctx = await buildContext({ type: 'repo', value: dir });
    return keep((await runScan(ctx, { skipEngines: !ENGINES })).findings);
  }
  const base = 'https://app.test';
  const read = (f: string) => readFileSync(join(dir, f), 'utf8');
  const jsBundles = meta.url.bundles.map((f) => ({ url: `${base}/_next/static/chunks/${f}`, content: read(f) }));
  const homepageHtml = meta.url.html ? read(meta.url.html) : '<html></html>';
  const responses = meta.url.responses ?? {};
  const ctx: ScanContext = {
    target: { type: 'url', value: base },
    http: { baseUrl: base, reachable: true, status: 200, homepageHtml, headers: meta.url.headers, jsBundles, cookies: [] },
    discovered: extractDiscovered([homepageHtml, ...jsBundles.map((b) => b.content)]),
    helpers: {
      ...helpers,
      // Offline: only the paths a case declares respond; everything else is a 404.
      httpGet: async (url: string) => {
        const u = new URL(url);
        const body = responses[u.pathname + u.search] ?? responses[u.pathname];
        return body === undefined ? { status: 404, headers: {}, body: '' } : { status: 200, headers: {}, body };
      },
    },
  };
  return (await runScan(ctx, { skipEngines: !ENGINES })).findings;
}

/** Medium+ findings a SAFE case must never produce. */
export function precisionViolations(findings: Finding[]): Finding[] {
  return findings.filter((f) => SEV_RANK[f.severity] >= SEV_RANK.medium);
}

/** Expectations a VULNERABLE case failed to meet. */
export function recallMisses(findings: Finding[], expect: Expectation[]): Expectation[] {
  return expect.filter(
    (e) =>
      !findings.some(
        (f) => f.ruleId === e.ruleId && SEV_RANK[f.severity] >= SEV_RANK[e.minSeverity] && CONF_RANK[f.confidence] >= CONF_RANK[e.minConfidence],
      ),
  );
}
