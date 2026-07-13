import { execa } from 'execa';
import { debug } from './helpers.js';

export interface EngineAvailability {
  semgrep: boolean;
  gitleaks: boolean;
  osvScanner: boolean;
}

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

/** Run a command capturing stdout; returns null on any failure. */
export async function runEngine(bin: string, args: string[], cwd?: string): Promise<string | null> {
  try {
    const { stdout } = await execa(bin, args, { cwd, timeout: 120000, reject: false });
    return stdout;
  } catch (err) {
    debug(`${bin} failed`, (err as Error).message);
    return null;
  }
}

/* --- thin wrappers; parsing lives in normalize.ts --- */

export async function runGitleaks(repoRoot: string): Promise<string | null> {
  // JSON report to stdout, scan filesystem + git history.
  return runEngine('gitleaks', ['detect', '--source', repoRoot, '--no-banner', '--report-format', 'json', '--report-path', '/dev/stdout']);
}

export async function runSemgrep(repoRoot: string, rulesDir: string): Promise<string | null> {
  return runEngine('semgrep', ['scan', '--config', rulesDir, '--json', '--quiet', repoRoot]);
}

export async function runOsvScanner(repoRoot: string): Promise<string | null> {
  return runEngine('osv-scanner', ['--format', 'json', '--recursive', repoRoot]);
}
