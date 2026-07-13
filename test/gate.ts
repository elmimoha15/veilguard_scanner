/**
 * Slice-1 testing gate. Runs the full checklist (A–E) and prints GATE RESULTS.
 * Exits non-zero if any gate fails. Run with: `npm run gate`.
 */
import { fileURLToPath } from 'node:url';
import { existsSync, readFileSync } from 'node:fs';
import { execa } from 'execa';
import { scan } from '../src/index.js';
import { ScanReportSchema } from '../src/types.js';

const root = fileURLToPath(new URL('..', import.meta.url));
const fixture = (p: string) => fileURLToPath(new URL(`../test-fixtures/${p}`, import.meta.url));

interface GateResult {
  id: string;
  label: string;
  pass: boolean;
  detail: string;
}

const results: GateResult[] = [];
function record(id: string, label: string, pass: boolean, detail: string) {
  results.push({ id, label, pass, detail });
}

async function main() {
  // A) Unit tests (the vitest suite).
  try {
    const res = await execa('npx', ['vitest', 'run', '--reporter=dot'], { cwd: root, reject: false });
    const pass = res.exitCode === 0;
    const m = `${res.stdout}\n${res.stderr}`.match(/Tests\s+(\d+)\s+passed/i);
    record('A', 'Unit tests (one+ per rule module)', pass, pass ? `vitest suite passed${m ? ` (${m[1]} tests)` : ''}` : 'vitest suite failed');
  } catch (err) {
    record('A', 'Unit tests (one+ per rule module)', false, (err as Error).message);
  }

  // B) Suppression.
  try {
    const pub = await scan(fixture('safe/public-secrets'), { skipEngines: true });
    const danger = await scan(fixture('safe/dangerous-secrets'), { skipEngines: true });
    const pubSecrets = pub.findings.filter((f) => f.category === 'secrets').length;
    const crit = new Set(danger.findings.filter((f) => f.severity === 'critical').map((f) => f.ruleId));
    const required = ['SECRETS_STRIPE_SECRET_KEY', 'SECRETS_SUPABASE_SERVICE_ROLE', 'SECRETS_PRIVATE_KEY'];
    const pass = pubSecrets === 0 && required.every((r) => crit.has(r));
    record('B', 'False-positive suppression', pass, `public secret findings=${pubSecrets} (want 0); dangerous criticals=${[...crit].filter((c) => required.includes(c)).length}/3`);
  } catch (err) {
    record('B', 'False-positive suppression', false, (err as Error).message);
  }

  // C) E2E QuickCart.
  try {
    const report = await scan(fixture('vulnerable/quickcart'), { skipEngines: true });
    const schemaOk = ScanReportSchema.safeParse(report).success;
    const ids = new Set(report.findings.map((f) => f.ruleId));
    const criticals = new Set(report.findings.filter((f) => f.severity === 'critical').map((f) => f.ruleId));
    const checks = {
      count: report.findings.length >= 12,
      grade: report.grade === 'D' || report.grade === 'F',
      stripe: criticals.has('SECRETS_STRIPE_SECRET_KEY'),
      sql: report.findings.some((f) => f.ruleId === 'INJECTION_SQL' && f.severity === 'critical'),
      webhook: criticals.has('API_WEBHOOK_UNVERIFIED'),
      rls: report.findings.some((f) => f.category === 'database' && f.severity === 'critical'),
      creds: criticals.has('SECRETS_SUPABASE_SERVICE_ROLE') || criticals.has('SECRETS_SUPABASE_SERVICE_ROLE_JWT'),
      dep: [...ids].some((id) => id.startsWith('DEPENDENCIES_')),
      ai: ids.has('AI_RISKY_RULES_FILE'),
      schema: schemaOk,
    };
    const pass = Object.values(checks).every(Boolean);
    const failed = Object.entries(checks).filter(([, v]) => !v).map(([k]) => k);
    record('C', 'E2E on known-vulnerable QuickCart', pass, pass ? `${report.findings.length} findings, grade ${report.grade}, all required criticals present` : `missing: ${failed.join(', ')}`);
  } catch (err) {
    record('C', 'E2E on known-vulnerable QuickCart', false, (err as Error).message);
  }

  // D) No-crash clean project.
  try {
    const report = await scan(fixture('safe/clean-app'), { skipEngines: true });
    const pass = (report.grade === 'A' || report.grade === 'B') && report.counts.critical === 0;
    record('D', 'No-crash clean project → A/B, 0 criticals', pass, `grade ${report.grade}, ${report.counts.critical} criticals`);
  } catch (err) {
    record('D', 'No-crash clean project → A/B, 0 criticals', false, (err as Error).message);
  }

  // E) README documents engine install + npm test.
  try {
    const readmePath = fileURLToPath(new URL('../README.md', import.meta.url));
    const readme = existsSync(readmePath) ? readFileSync(readmePath, 'utf8') : '';
    const pass = ['semgrep', 'gitleaks', 'osv-scanner', 'npm test'].every((t) => readme.includes(t));
    record('E', 'README documents engines + npm test', pass, pass ? 'all references present' : 'README missing engine install and/or npm test docs');
  } catch (err) {
    record('E', 'README documents engines + npm test', false, (err as Error).message);
  }

  // Print summary.
  const green = '\x1b[32m';
  const red = '\x1b[31m';
  const reset = '\x1b[0m';
  console.log('\n══════════════ GATE RESULTS ══════════════');
  for (const r of results) {
    const mark = r.pass ? `${green}PASS${reset}` : `${red}FAIL${reset}`;
    console.log(`  ${r.id})  ${mark}  ${r.label}`);
    console.log(`         ${r.detail}`);
  }
  const allPass = results.every((r) => r.pass);
  console.log('═══════════════════════════════════════════');
  console.log(allPass ? `${green}  ALL GATES PASS ✓${reset}\n` : `${red}  SOME GATES FAILED ✗${reset}\n`);
  process.exit(allPass ? 0 : 1);
}

main();
