import { describe, it, expect } from 'vitest';
import { normalizeOsv } from '../src/engine/normalize.js';

/** A crafted osv-scanner JSON report — no network, no binary needed. */
const OSV_JSON = JSON.stringify({
  results: [
    {
      packages: [
        {
          package: { name: 'lodash', version: '4.17.11', ecosystem: 'npm' },
          vulnerabilities: [
            {
              id: 'GHSA-jf85-cpcp-j695',
              summary: 'Prototype pollution in lodash',
              database_specific: { severity: 'CRITICAL' },
              affected: [{ package: { name: 'lodash' }, ranges: [{ type: 'ECOSYSTEM', events: [{ introduced: '0' }, { fixed: '4.17.12' }] }] }],
            },
            {
              id: 'GHSA-p6mc-m468-83gw',
              summary: 'ReDoS in lodash',
              database_specific: { severity: 'HIGH' },
              affected: [{ package: { name: 'lodash' }, ranges: [{ type: 'ECOSYSTEM', events: [{ introduced: '0' }, { fixed: '4.17.19' }] }] }],
            },
            {
              id: 'GHSA-29mw-wpgm-hmr9',
              summary: 'Command injection in lodash template',
              database_specific: { severity: 'MODERATE' },
              affected: [{ package: { name: 'lodash' }, ranges: [{ type: 'ECOSYSTEM', events: [{ introduced: '0' }, { fixed: '4.18.0' }] }] }],
            },
          ],
        },
        {
          package: { name: 'minimist', version: '1.2.0', ecosystem: 'npm' },
          vulnerabilities: [
            {
              id: 'GHSA-vh95-rmgr-6w4m',
              summary: 'Prototype pollution in minimist',
              database_specific: { severity: 'HIGH' },
              affected: [{ package: { name: 'minimist' }, ranges: [{ type: 'ECOSYSTEM', events: [{ introduced: '0' }, { fixed: '1.2.6' }] }] }],
            },
          ],
        },
      ],
    },
  ],
});

describe('normalizeOsv — grouped per package', () => {
  const findings = normalizeOsv(OSV_JSON);

  it('emits exactly one finding per vulnerable package', () => {
    expect(findings).toHaveLength(2);
  });

  it('groups lodash advisories: worst severity, count, target = lowest version fixing all', () => {
    const lodash = findings.find((f) => f.location?.url === 'lodash@4.17.11');
    expect(lodash).toBeTruthy();
    expect(lodash!.severity).toBe('critical'); // worst of CRITICAL/HIGH/MODERATE
    expect(lodash!.title).toMatch(/lodash@4\.17\.11 has 3 known vulnerabilities \(1 critical\)/);
    // Lowest version that fixes ALL three (max of 4.17.12 / 4.17.19 / 4.18.0).
    expect(lodash!.fix).toContain('4.18.0');
    // All advisory ids listed in the body (details), not in evidence.
    for (const id of ['GHSA-jf85-cpcp-j695', 'GHSA-p6mc-m468-83gw', 'GHSA-29mw-wpgm-hmr9']) {
      expect(lodash!.whyItMatters).toContain(id);
    }
    expect((lodash!.evidence ?? '').length).toBeLessThan(200);
    expect(lodash!.source).toBe('osv-scanner');
  });

  it('singular wording + no critical note for a single HIGH advisory', () => {
    const minimist = findings.find((f) => f.location?.url === 'minimist@1.2.0');
    expect(minimist).toBeTruthy();
    expect(minimist!.severity).toBe('high');
    expect(minimist!.title).toMatch(/minimist@1\.2\.0 has 1 known vulnerability$/);
    expect(minimist!.fix).toContain('1.2.6');
  });
});
