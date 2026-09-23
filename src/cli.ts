import { writeFileSync } from 'node:fs';
import { Command } from 'commander';
import { detectTargetType, buildContext } from './engine/recon.js';
import { runScan } from './engine/runner.js';
import { setDebug } from './engine/helpers.js';
import type { Finding, ScanReport, Severity } from './types.js';

const program = new Command();

program
  .name('veilguard')
  .description('Scan a live URL or a code repo for security holes and get an A–F grade.')
  .version('0.1.0');

program
  .command('scan')
  .argument('<target>', 'a URL (https://…) or a path to a code repo')
  .option('--json', 'print the full ScanReport as JSON instead of a summary')
  .option('--out <file>', 'write the full ScanReport JSON to a file')
  .option('--debug', 'verbose logging (engine detection, suppression reasons)')
  .option('--no-engines', 'skip external OSS engines even if installed')
  .action(async (target: string, opts: { json?: boolean; out?: string; debug?: boolean; engines?: boolean }) => {
    if (opts.debug) setDebug(true);

    const t = detectTargetType(target);
    const ctx = await buildContext(t);
    const report = await runScan(ctx, { skipEngines: opts.engines === false });

    if (opts.out) {
      writeFileSync(opts.out, JSON.stringify(report, null, 2));
      if (!opts.json) console.error(`Wrote report to ${opts.out}`);
    }

    if (opts.json) {
      console.log(JSON.stringify(report, null, 2));
    } else {
      printSummary(report);
    }

    // Exit non-zero when the app is failing, so CI can gate on it.
    process.exitCode = report.grade === 'F' || report.counts.critical > 0 ? 2 : 0;
  });

program.parseAsync().catch((err) => {
  console.error('veilguard: fatal error');
  console.error(err);
  process.exit(1);
});

/* -------------------------------------------------------------------------- */
/* Terminal rendering                                                          */
/* -------------------------------------------------------------------------- */

const RESET = '\x1b[0m';
const color = (c: number, s: string) => `\x1b[${c}m${s}${RESET}`;
const bold = (s: string) => `\x1b[1m${s}${RESET}`;

const GRADE_COLOR: Record<ScanReport['grade'], number> = { A: 32, B: 32, C: 33, D: 31, F: 31 };
const SEV_COLOR: Record<Severity, number> = { critical: 31, high: 31, medium: 33, low: 36, info: 90 };
const SEV_ORDER: Severity[] = ['critical', 'high', 'medium', 'low', 'info'];

function printSummary(report: ScanReport): void {
  const c = report.counts;
  console.log('');
  console.log(bold(`  Veilguard scan — ${report.target.value}`));
  console.log('');
  console.log(
    `  Grade: ${bold(color(GRADE_COLOR[report.grade], report.grade))}   Score: ${report.score}/100`,
  );
  console.log(
    `  ${color(31, `${c.critical} critical`)} · ${color(31, `${c.high} high`)} · ${color(33, `${c.medium} medium`)} · ${color(36, `${c.low} low`)} · ${color(32, `${report.passed.length} passed`)}`,
  );

  const enabled = Object.entries(report.engines)
    .filter(([, on]) => on)
    .map(([n]) => n);
  console.log(`  Engines: ${enabled.length ? enabled.join(', ') : 'native only (no OSS engines detected)'}`);
  console.log('');

  const byaSev: Record<Severity, Finding[]> = { critical: [], high: [], medium: [], low: [], info: [] };
  for (const f of report.findings) byaSev[f.severity].push(f);

  for (const sev of SEV_ORDER) {
    const list = byaSev[sev];
    if (list.length === 0) continue;
    console.log(bold(color(SEV_COLOR[sev], `  ${sev.toUpperCase()} (${list.length})`)));
    for (const f of list) {
      const loc = f.location?.file
        ? `${f.location.file}${f.location.line ? `:${f.location.line}` : ''}`
        : (f.location?.url ?? '');
      console.log(`    • ${f.title}`);
      if (loc) console.log(color(90, `        ${loc}`));
    }
    console.log('');
  }

  if (report.passed.length > 0) {
    console.log(bold(color(32, `  PASSED (${report.passed.length})`)));
    for (const p of report.passed) console.log(color(32, `    ✓ ${p.title}`));
    console.log('');
  }

  if (report.findings.length === 0) {
    console.log(color(32, '  No issues found. 🎉'));
    console.log('');
  } else {
    console.log(color(90, '  Run with --json or --out report.json for full details and fixes.'));
    console.log('');
  }
}
