/** Public library surface for veilguard-scanner (used by the CLI and later slices). */
export * from './types.js';
export { detectTargetType, buildContext } from './engine/recon.js';
export { runScan, type RunOptions } from './engine/runner.js';
export { grade } from './engine/grade.js';
export { suppress } from './engine/suppress.js';
export { classifySecret } from './engine/secret-matrix.js';
export { rules } from './rules/index.js';
export { setDebug } from './engine/helpers.js';

import { detectTargetType, buildContext } from './engine/recon.js';
import { runScan, type RunOptions } from './engine/runner.js';
import type { ScanReport } from './types.js';

/** Convenience: scan a URL or repo path in one call. */
export async function scan(target: string, opts: RunOptions = {}): Promise<ScanReport> {
  const t = detectTargetType(target);
  const ctx = await buildContext(t);
  return runScan(ctx, opts);
}
