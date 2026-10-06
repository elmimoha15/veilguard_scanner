import { existsSync, mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { execa } from 'execa';
import { debug } from './helpers.js';

export interface EngineAvailability {
  semgrep: boolean;
  gitleaks: boolean;
  osvScanner: boolean;
}

/** Default per-engine wall-clock budget. Overridable so the worker can bound a
 *  big-repo scan well under the overall deep-scan timeout. */
export const DEFAULT_ENGINE_TIMEOUT_MS = 180_000; // 3 min

async function has(bin: string, args: string[] = ['--version']): Promise<boolean> {
  try {
    await execa(bin, args, { timeout: 5000 });
    return true;
  } catch {
    return false;
  }
}

/** Probe PATH for each optional engine. Never throws. */
export async function detectEngines(): Promise<EngineAvailability> {
  const [semgrep, gitleaks, osvScanner] = await Promise.all([
    has('semgrep'),
    has('gitleaks', ['version']),
    has('osv-scanner', ['--version']),
  ]);
  const result = { semgrep, gitleaks, osvScanner };
  debug('engine availability', result);
  return result;
}

/**
 * Run a command capturing stdout; returns null when it couldn't produce usable
 * output (spawn error or timeout). A non-zero exit is NOT treated as failure —
 * several of these tools exit non-zero precisely when they find something — so
 * stdout is still returned in that case. Timeouts/errors are logged so a failed
 * engine is visible, and the caller falls back to native-only results.
 */
export async function runEngine(
  bin: string,
  args: string[],
  cwd?: string,
  timeoutMs: number = DEFAULT_ENGINE_TIMEOUT_MS,
): Promise<string | null> {
  try {
    const result = await execa(bin, args, { cwd, timeout: timeoutMs, reject: false });
    if (result.timedOut) {
      debug(`${bin} timed out after ${timeoutMs}ms — skipping its findings`);
      return null;
    }
    if (result.failed && !result.stdout) {
      debug(`${bin} failed (exit ${result.exitCode}): ${result.stderr || result.shortMessage}`);
      return null;
    }
    return result.stdout;
  } catch (err) {
    // Spawn error (e.g. binary vanished between detect and run).
    debug(`${bin} failed to run`, (err as Error).message);
    return null;
  }
}

/* --- thin wrappers; parsing lives in normalize.ts --- */

export async function runGitleaks(repoRoot: string, timeoutMs?: number): Promise<string | null> {
  // `gitleaks git` walks full commit history; `gitleaks dir` scans the working
  // tree only. Pick by whether a repo (.git) is actually present — uploads and
  // shallow copies without history get the directory scan.
  const hasGit = existsSync(join(repoRoot, '.git'));
  // gitleaks writes its JSON report to a FILE; `/dev/stdout` is unreliable in
  // `git` mode (it silently drops the report), so use a real temp file and read
  // it back. `--exit-code 0` keeps a clean exit even when leaks are found.
  const reportDir = mkdtempSync(join(tmpdir(), 'veilguard-gitleaks-'));
  const reportPath = join(reportDir, 'report.json');
  const common = ['--no-banner', '--report-format', 'json', '--report-path', reportPath, '--exit-code', '0'];
  const args = hasGit ? ['git', repoRoot, ...common] : ['dir', repoRoot, ...common];
  try {
    const result = await execa('gitleaks', args, {
      timeout: timeoutMs ?? DEFAULT_ENGINE_TIMEOUT_MS,
      reject: false,
    });
    if (result.timedOut) {
      debug(`gitleaks timed out after ${timeoutMs ?? DEFAULT_ENGINE_TIMEOUT_MS}ms — skipping its findings`);
      return null;
    }
    return readFileSync(reportPath, 'utf8');
  } catch (err) {
    debug('gitleaks failed to run', (err as Error).message);
    return null;
  } finally {
    rmSync(reportDir, { recursive: true, force: true });
  }
}

export async function runSemgrep(repoRoot: string, rulesDir: string, timeoutMs?: number): Promise<string | null> {
  return runEngine('semgrep', ['scan', '--config', rulesDir, '--json', '--quiet', repoRoot], undefined, timeoutMs);
}

export async function runOsvScanner(repoRoot: string, timeoutMs?: number): Promise<string | null> {
  return runEngine('osv-scanner', ['--format', 'json', '--recursive', repoRoot], undefined, timeoutMs);
}
