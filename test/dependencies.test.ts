import { describe, it, expect } from 'vitest';
import { knownCve } from '../src/rules/dependencies/known-cve.js';
import { makeRepoContext } from './helpers.js';

describe('DEPENDENCIES_KNOWN_CVE', () => {
  it('flags next 13.4.0 as outdated/vulnerable', async () => {
    const ctx = makeRepoContext({ 'package.json': JSON.stringify({ dependencies: { next: '13.4.0' } }) });
    const findings = await knownCve.run(ctx);
    expect(findings.length).toBeGreaterThan(0);
    expect(findings.some((f) => f.category === 'dependencies')).toBe(true);
  });
  it('does not flag a current next 15.3.0', async () => {
    const ctx = makeRepoContext({ 'package.json': JSON.stringify({ dependencies: { next: '15.3.0' } }) });
    expect((await knownCve.run(ctx)).length).toBe(0);
  });

  it('only ships confirmed advisories (no unverified/sentinel entries)', async () => {
    // Guard against re-introducing fake advisories (the removed GHSA-NEXT-OUTDATED
    // / CVE-2025-55182 / 999.x sentinels). A real install must never match a
    // placeholder range, and the fabricated ids must not come back.
    const sentinel = makeRepoContext({ 'package.json': JSON.stringify({ dependencies: { next: '999.0.0' } }) });
    expect((await knownCve.run(sentinel)).length).toBe(0);

    const react19 = makeRepoContext({
      'package.json': JSON.stringify({ dependencies: { react: '19.0.0', 'react-dom': '19.0.0' } }),
    });
    const ids = (await knownCve.run(react19)).map((f) => f.ruleId);
    expect(ids).not.toContain('DEPENDENCIES_CVE_2025_55182');
    expect(ids).not.toContain('DEPENDENCIES_GHSA_NEXT_OUTDATED');
  });
});
