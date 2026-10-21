import { describe, it, expect } from 'vitest';
import { runScan, dependencyCoverage, DEPS_UNSUPPORTED_NOTE, DEPS_MISSING_NOTE } from '../src/engine/runner.js';
import { makeRepoContext } from './helpers.js';

const pkg = JSON.stringify({ dependencies: { next: '15.3.0' } });

describe('dependency coverage note', () => {
  it('a binary bun.lockb (unreadable) adds the "format not supported" note and no clean dependency pass', async () => {
    const ctx = makeRepoContext({ 'package.json': pkg, 'bun.lockb': '\u0000binary' });
    // makeRepoContext only lists npm/pnpm/yarn lockfiles; add bun's like recon does.
    ctx.repo!.lockfiles.push('bun.lockb');
    expect(dependencyCoverage(ctx)).toBe('unsupported');
    const r = await runScan(ctx, { skipEngines: true });
    expect(r.notes).toContain(DEPS_UNSUPPORTED_NOTE);
    expect(r.passed.some((p) => p.id === 'PASS_CLEAN_DEPENDENCIES')).toBe(false);
  });

  it('no lockfile at all adds the "no lockfile found" note', async () => {
    const ctx = makeRepoContext({ 'package.json': pkg });
    expect(dependencyCoverage(ctx)).toBe('missing');
    const r = await runScan(ctx, { skipEngines: true });
    expect(r.notes).toContain(DEPS_MISSING_NOTE);
    expect(r.passed.some((p) => p.id === 'PASS_CLEAN_DEPENDENCIES')).toBe(false);
  });

  it('a readable lockfile adds no note', async () => {
    const ctx = makeRepoContext({ 'package.json': pkg, 'package-lock.json': JSON.stringify({ lockfileVersion: 3, packages: { 'node_modules/next': { version: '15.3.0' } } }) });
    expect(dependencyCoverage(ctx)).toBe('checkable');
    const r = await runScan(ctx, { skipEngines: true });
    expect(r.notes ?? []).toEqual([]);
  });

  it('a project with no package.json (and URL scans) gets no dependency note', async () => {
    const ctx = makeRepoContext({ 'index.html': '<html></html>' });
    expect(dependencyCoverage(ctx)).toBe('n/a');
    expect((await runScan(ctx, { skipEngines: true })).notes).toBeUndefined();
  });
});
