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

  it('provisional TODO advisories fire against their sentinel range (999.x)', async () => {
    // The sentinel range proves the version-check MECHANISM works today; the
    // real ranges are TODO constants to be plugged in once confirmed.
    const ctx = makeRepoContext({ 'package.json': JSON.stringify({ dependencies: { next: '999.0.0' } }) });
    const ids = (await knownCve.run(ctx)).map((f) => f.ruleId);
    expect(ids).toContain('DEPENDENCIES_NEXTJS_IMAGE_RESOURCE_EXHAUSTION_TODO');
    expect(ids).toContain('DEPENDENCIES_NEXTJS_SERVER_ACTIONS_SSRF_TODO');
  });
});
