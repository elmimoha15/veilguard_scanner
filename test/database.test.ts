import { describe, it, expect } from 'vitest';
import { supabaseRls } from '../src/rules/database/supabase-rls.js';
import { firebaseRules } from '../src/rules/database/firebase-rules.js';
import { rlsOpenProbe } from '../src/rules/database/rls-open-probe.js';
import { makeRepoContext } from './helpers.js';
import type { ScanContext } from '../src/types.js';
import { helpers } from '../src/engine/helpers.js';

describe('DATABASE_SUPABASE_RLS', () => {
  it('flags a public table with no RLS and an over-permissive policy', async () => {
    const ctx = makeRepoContext({
      'db/0001.sql': `
        create table public.orders (id uuid primary key);
        create policy p on public.orders for select using (auth.uid() is not null);
      `,
    });
    const findings = await supabaseRls.run(ctx);
    expect(findings.some((f) => f.ruleId === 'DATABASE_RLS_DISABLED')).toBe(true);
    expect(findings.some((f) => f.ruleId === 'DATABASE_RLS_PERMISSIVE_POLICY')).toBe(true);
  });

  it('does not flag a table with RLS enabled and an owner-scoped policy', async () => {
    const ctx = makeRepoContext({
      'db/0001.sql': `
        create table public.orders (id uuid primary key, user_id uuid);
        alter table public.orders enable row level security;
        create policy p on public.orders for select using (auth.uid() = user_id);
      `,
    });
    expect((await supabaseRls.run(ctx)).length).toBe(0);
  });
});

describe('DATABASE_FIREBASE_RULES_OPEN', () => {
  it('flags allow read, write: if true', async () => {
    const ctx = makeRepoContext({ 'firestore.rules': 'match /{d=**} { allow read, write: if true; }' });
    expect((await firebaseRules.run(ctx)).length).toBe(1);
  });
  it('does not flag ownership rules', async () => {
    const ctx = makeRepoContext({ 'firestore.rules': 'allow read: if request.auth.uid == resource.data.owner;' });
    expect((await firebaseRules.run(ctx)).length).toBe(0);
  });
});

describe('DATABASE_SUPABASE_RLS_OPEN_LIVE (black-box probe)', () => {
  function ctxWithStub(rows: unknown): ScanContext {
    return {
      target: { type: 'url', value: 'https://x.test' },
      http: { baseUrl: 'https://x.test', reachable: true, homepageHtml: '', headers: {}, jsBundles: [], cookies: [] },
      discovered: { supabaseUrl: 'https://abcdefghijklmnopqrst.supabase.co', supabaseAnonKey: 'anon.key.here' },
      helpers: { ...helpers, httpGet: async () => ({ status: 200, headers: {}, body: JSON.stringify(rows) }) },
    };
  }
  it('fires when a table returns rows to the anon key', async () => {
    const findings = await rlsOpenProbe.run(ctxWithStub([{ id: 1 }]));
    expect(findings.length).toBeGreaterThan(0);
    expect(findings[0]!.severity).toBe('critical');
  });
  it('does not fire when tables return empty arrays', async () => {
    expect((await rlsOpenProbe.run(ctxWithStub([]))).length).toBe(0);
  });
});
