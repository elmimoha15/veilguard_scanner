import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { scan } from '../src/index.js';
import { detectEngines } from '../src/engine/engines.js';

/**
 * These tests exercise the REAL external engines (gitleaks / osv-scanner) end to
 * end, so they are gated on the binary being installed. They build throwaway
 * repos on disk and scan with engines ENABLED (skipEngines: false) — the opposite
 * of the fast unit suites. osv-scanner additionally needs network (OSV.dev).
 */
const engines = await detectEngines();

let root: string;
beforeAll(() => {
  root = mkdtempSync(join(tmpdir(), 'veilguard-engines-'));
});
afterAll(() => {
  if (root) rmSync(root, { recursive: true, force: true });
});

function repoDir(name: string): string {
  const dir = join(root, name);
  mkdirSync(dir, { recursive: true });
  return dir;
}

function git(dir: string, args: string[]): void {
  execFileSync('git', args, {
    cwd: dir,
    stdio: 'ignore',
    env: {
      ...process.env,
      GIT_AUTHOR_NAME: 'Test',
      GIT_AUTHOR_EMAIL: 'test@example.com',
      GIT_COMMITTER_NAME: 'Test',
      GIT_COMMITTER_EMAIL: 'test@example.com',
    },
  });
}

describe('external engines (gitleaks + osv-scanner)', () => {
  it.skipIf(!engines.gitleaks)('does NOT report public keys / example creds as critical', async () => {
    const dir = repoDir('public-keys');
    writeFileSync(
      join(dir, 'config.ts'),
      [
        "export const stripePublishable = 'pk_live_51H8xReAbCdEfGhIjKlMnOpQr12345678';",
        "export const dbExample = 'postgres://user:password@localhost:5432/mydb';",
        "export const firebaseApiKey = 'AIzaSyB1c2D3e4F5g6H7i8J9k0L1m2N3o4P5q6R';",
      ].join('\n'),
    );
    writeFileSync(join(dir, 'package.json'), JSON.stringify({ name: 'pub', version: '1.0.0' }));

    const report = await scan(dir, { skipEngines: false });
    expect(report.engines.gitleaks).toBe(true);
    expect(report.counts.critical).toBe(0);
    // Any residual secret findings must be low-confidence (never a confirmed leak).
    const confirmedSecrets = report.findings.filter(
      (f) => f.category === 'secrets' && f.confidence !== 'low',
    );
    expect(confirmedSecrets).toHaveLength(0);
  });

  it.skipIf(!engines.gitleaks)('catches a real secret that lives only in git history', async () => {
    const dir = repoDir('history');
    git(dir, ['init', '-q']);
    // A real-looking (but fake) Stripe secret key. Assembled from fragments so the
    // literal `sk_live_…` is NOT present in THIS source file — otherwise GitHub
    // push protection blocks the repo. The committed temp file below still gets
    // the full value, which is exactly what gitleaks must detect in history.
    const fakeStripeKey = ['sk', 'live', '51H8xReAbCdEfGhIjKlMnOpQrStUvWx0123456789'].join('_');
    writeFileSync(join(dir, 'secret.ts'), `export const key = '${fakeStripeKey}';\n`);
    writeFileSync(join(dir, 'package.json'), JSON.stringify({ name: 'hist', version: '1.0.0' }));
    git(dir, ['add', '.']);
    git(dir, ['commit', '-qm', 'add config']);
    // ...then remove it in a later commit so the working tree is clean.
    writeFileSync(join(dir, 'secret.ts'), "export const key = process.env.STRIPE_SECRET_KEY;\n");
    git(dir, ['add', '.']);
    git(dir, ['commit', '-qm', 'move to env']);

    const report = await scan(dir, { skipEngines: false });
    expect(report.engines.gitleaks).toBe(true);
    const gitleaksCriticals = report.findings.filter(
      (f) => f.source === 'gitleaks' && f.severity === 'critical',
    );
    expect(gitleaksCriticals.length).toBeGreaterThan(0);
  });

  function lockfileFor(pkg: string, version: string): string {
    return JSON.stringify({
      name: 'osv-fixture',
      version: '1.0.0',
      lockfileVersion: 3,
      requires: true,
      packages: {
        '': { name: 'osv-fixture', version: '1.0.0', dependencies: { [pkg]: version } },
        [`node_modules/${pkg}`]: { version, resolved: `https://registry.npmjs.org/${pkg}/-/${pkg}-${version}.tgz` },
      },
    });
  }

  it.skipIf(!engines.osvScanner)('groups a vulnerable package into ONE finding with version + fix', async () => {
    const dir = repoDir('osv');
    writeFileSync(join(dir, 'package.json'), JSON.stringify({ name: 'osv-fixture', version: '1.0.0', dependencies: { lodash: '4.17.11' } }));
    writeFileSync(join(dir, 'package-lock.json'), lockfileFor('lodash', '4.17.11'));

    const report = await scan(dir, { skipEngines: false });
    expect(report.engines.osvScanner).toBe(true);
    const lodash = report.findings.filter((f) => f.source === 'osv-scanner' && f.location?.url === 'lodash@4.17.11');
    // Requires network (OSV.dev); surface clearly if the query returned nothing.
    expect(lodash.length, 'osv-scanner returned no lodash finding (needs network to OSV.dev)').toBe(1); // GROUPED: one, not one-per-advisory
    const f = lodash[0]!;
    expect(f.title).toMatch(/known vulnerabilit/);
    expect(f.fix).toMatch(/4\.18\.0/); // lowest version fixing all lodash advisories
    expect(f.whyItMatters).toMatch(/GHSA-/); // advisory ids listed in the body
  });

  it.skipIf(!engines.osvScanner)('OSV supersedes the native advisory floor for the same package (no duplicate)', async () => {
    const dir = repoDir('osv-dedupe');
    // next@13.4.0 is flagged by BOTH the native known-cve floor (CVE-2024-34351)
    // and OSV. After reconciliation only ONE next dependency finding remains.
    writeFileSync(join(dir, 'package.json'), JSON.stringify({ name: 'osv-fixture', version: '1.0.0', dependencies: { next: '13.4.0' } }));
    writeFileSync(join(dir, 'package-lock.json'), lockfileFor('next', '13.4.0'));

    const report = await scan(dir, { skipEngines: false });
    const nextDeps = report.findings.filter((f) => f.category === 'dependencies' && /(^|[^a-z])next@13\.4\.0|next/i.test(`${f.location?.url ?? ''} ${f.title}`));
    const nextUrlFindings = report.findings.filter((f) => f.category === 'dependencies' && (f.location?.url === 'next@13.4.0' || /next@13\.4\.0/.test(f.title)));
    expect(nextUrlFindings.length).toBe(1);
    // The survivor is the richer OSV group, not the native floor.
    expect(nextDeps.every((f) => f.source === 'osv-scanner')).toBe(true);
  });
});
