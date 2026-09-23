import { describe, it, expect } from 'vitest';
import { fileURLToPath } from 'node:url';
import { scan } from '../src/index.js';
import { ScanReportSchema } from '../src/types.js';

const fixture = (p: string) => fileURLToPath(new URL(`../test-fixtures/${p}`, import.meta.url));

describe('E2E — QuickCart (gate C)', () => {
  it('produces a D/F grade with the required critical findings', async () => {
    const report = await scan(fixture('vulnerable/quickcart'), { skipEngines: true });

    // Schema validity.
    expect(() => ScanReportSchema.parse(report)).not.toThrow();

    // Volume + grade.
    expect(report.findings.length).toBeGreaterThanOrEqual(12);
    expect(['D', 'F']).toContain(report.grade);

    const ids = new Set(report.findings.map((f) => f.ruleId));
    const criticals = report.findings.filter((f) => f.severity === 'critical').map((f) => f.ruleId);

    // Required criticals.
    expect(criticals).toContain('SECRETS_STRIPE_SECRET_KEY'); // hardcoded stripe secret
    expect(report.findings.some((f) => f.ruleId === 'INJECTION_SQL' && f.severity === 'critical')).toBe(true);
    expect(criticals).toContain('API_WEBHOOK_UNVERIFIED'); // missing webhook verification
    expect(report.findings.some((f) => f.category === 'database' && f.severity === 'critical')).toBe(true); // broken RLS
    expect(
      report.findings.some(
        (f) => f.severity === 'critical' && (f.ruleId === 'SECRETS_SUPABASE_SERVICE_ROLE' || f.ruleId === 'SECRETS_SUPABASE_SERVICE_ROLE_JWT'),
      ),
    ).toBe(true); // exposed service credentials

    // Required non-criticals.
    expect([...ids].some((id) => id.startsWith('DEPENDENCIES_'))).toBe(true); // outdated dependency
    expect(ids.has('AI_RISKY_RULES_FILE')).toBe(true); // AI rules file
  });
});

describe('E2E — clean app (gate D)', () => {
  it('returns grade A/B and zero criticals', async () => {
    const report = await scan(fixture('safe/clean-app'), { skipEngines: true });
    expect(['A', 'B']).toContain(report.grade);
    expect(report.counts.critical).toBe(0);
  });
});

describe('E2E — docs/content fixture (false positives)', () => {
  it('does not flag documentation/content examples as confirmed issues', async () => {
    const report = await scan(fixture('safe/docs-content'), { skipEngines: true });

    // Example connection strings in content are NOT reported as leaked secrets.
    expect(report.findings.filter((f) => f.category === 'secrets').length).toBe(0);

    // Static JSON-LD (JSON.stringify of a static object) is NOT flagged as XSS.
    expect(report.findings.filter((f) => f.ruleId === 'INJECTION_XSS' && f.severity === 'high').length).toBe(0);

    // Any webhook match in a content/article file is downgraded to low confidence,
    // never a confirmed critical.
    expect(
      report.findings.filter((f) => f.category === 'api_webhooks' && f.confidence !== 'low').length,
    ).toBe(0);

    // Net effect: a docs/content file cannot force a bad grade.
    expect(report.counts.critical).toBe(0);
    expect(['A', 'B']).toContain(report.grade);
  });
});

describe('Suppression fixtures (gate B)', () => {
  it('reports ZERO secret findings on public-by-design values', async () => {
    const report = await scan(fixture('safe/public-secrets'), { skipEngines: true });
    expect(report.findings.filter((f) => f.category === 'secrets').length).toBe(0);
  });
  it('reports each real secret as CRITICAL', async () => {
    const report = await scan(fixture('safe/dangerous-secrets'), { skipEngines: true });
    const crit = report.findings.filter((f) => f.severity === 'critical').map((f) => f.ruleId);
    expect(crit).toContain('SECRETS_STRIPE_SECRET_KEY');
    expect(crit).toContain('SECRETS_SUPABASE_SERVICE_ROLE');
    expect(crit).toContain('SECRETS_PRIVATE_KEY');
  });
});
