import { describe, it, expect } from 'vitest';
import { nextjsMiddlewareCve } from '../src/rules/auth/nextjs-middleware-cve.js';
import { missingAuth } from '../src/rules/auth/missing-auth.js';
import { makeRepoContext } from './helpers.js';

describe('AUTH_NEXTJS_MIDDLEWARE_BYPASS', () => {
  it('fires on next 13.4.0 (vulnerable)', async () => {
    const ctx = makeRepoContext({ 'package.json': JSON.stringify({ dependencies: { next: '13.4.0' } }) });
    expect((await nextjsMiddlewareCve.run(ctx)).length).toBe(1);
  });
  it('does not fire on a patched next 15.2.3', async () => {
    const ctx = makeRepoContext({ 'package.json': JSON.stringify({ dependencies: { next: '15.2.3' } }) });
    expect((await nextjsMiddlewareCve.run(ctx)).length).toBe(0);
  });
});

describe('AUTH_MISSING_CHECK', () => {
  it('fires on a mutating API route with no auth check', async () => {
    const ctx = makeRepoContext({
      'pages/api/delete.ts': `export async function POST(req){ await db.orders.delete({ where: { id: req.body.id } }); }`,
    });
    expect((await missingAuth.run(ctx)).length).toBe(1);
  });
  it('does not fire when a session check is present', async () => {
    const ctx = makeRepoContext({
      'pages/api/delete.ts': `export async function POST(req){ const s = await getServerSession(); if(!s) return; await db.orders.delete({ where:{ id:req.body.id } }); }`,
    });
    expect((await missingAuth.run(ctx)).length).toBe(0);
  });
});
