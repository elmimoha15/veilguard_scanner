import { describe, it, expect } from 'vitest';
import { supabaseRls } from '../src/rules/database/supabase-rls.js';
import { firebaseRules } from '../src/rules/database/firebase-rules.js';
import { rlsOpenProbe } from '../src/rules/database/rls-open-probe.js';
import { extractDiscovered } from '../src/engine/recon.js';
import { classifySecret } from '../src/engine/secret-matrix.js';
import { makeRepoContext } from './helpers.js';
import type { ScanContext } from '../src/types.js';
import { helpers } from '../src/engine/helpers.js';

const b64url = (o: unknown): string => Buffer.from(JSON.stringify(o)).toString('base64url');
/** A realistic legacy Supabase anon JWT (role "anon"), long enough to match recon. */
const ANON_JWT = `${b64url({ alg: 'HS256', typ: 'JWT' })}.${b64url({ role: 'anon', iss: 'supabase', ref: 'abcdefghijklmnopqrst' })}.sig_${'a'.repeat(30)}`;

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

// ── Gate A: DETECT — recon extracts the project URL + public key from a bundle.
describe('black-box Supabase detection (recon)', () => {
  it('extracts the Supabase URL and legacy anon JWT from a bundle', () => {
    const bundle = `var e="https://abcdefghijklmnopqrst.supabase.co",t="${ANON_JWT}";createClient(e,t)`;
    const d = extractDiscovered([bundle]);
    expect(d.supabaseUrl).toBe('https://abcdefghijklmnopqrst.supabase.co');
    expect(d.supabaseAnonKey).toBe(ANON_JWT);
  });

  it('extracts the newer sb_publishable_ key format', () => {
    const pub = 'sb_publishable_AbCdEf0123456789xyzXYZ';
    const bundle = `supabase("https://abcdefghijklmnopqrst.supabase.co","${pub}")`;
    const d = extractDiscovered([bundle]);
    expect(d.supabaseUrl).toBe('https://abcdefghijklmnopqrst.supabase.co');
    expect(d.supabaseAnonKey).toBe(pub);
  });

  it('does not surface a key when there is no Supabase URL', () => {
    const d = extractDiscovered([`const token="${ANON_JWT}"; // no supabase here`]);
    expect(d.supabaseUrl).toBeUndefined();
    expect(d.supabaseAnonKey).toBeUndefined();
  });
});

// ── Gate E: the public anon/publishable key is NOT flagged as a leaked secret.
describe('anon key is public-by-design (not a leaked secret)', () => {
  it('classifies an anon JWT as public', () => {
    expect(classifySecret(ANON_JWT).verdict).toBe('public');
  });
  it('classifies an sb_publishable_ key as public', () => {
    expect(classifySecret('sb_publishable_AbCdEf0123456789xyzXYZ').verdict).toBe('public');
  });
});

describe('DATABASE_SUPABASE_RLS_OPEN_LIVE (black-box probe)', () => {
  interface Call {
    url: string;
    opts?: { headers?: Record<string, string>; method?: string; body?: string; timeoutMs?: number };
  }
  /** Build a probe ctx whose httpGet returns `status`/`rows` and records every call. */
  function ctxWithStub(opts: { status?: number; rows?: unknown; discovered?: ScanContext['discovered'] } = {}) {
    const { status = 200, rows = [{ id: 1, email: 'secret@user.test' }] } = opts;
    const calls: Call[] = [];
    const ctx: ScanContext = {
      target: { type: 'url', value: 'https://x.test' },
      http: { baseUrl: 'https://x.test', reachable: true, homepageHtml: '', headers: {}, jsBundles: [], cookies: [] },
      discovered: opts.discovered ?? { supabaseUrl: 'https://abcdefghijklmnopqrst.supabase.co', supabaseAnonKey: ANON_JWT },
      helpers: {
        ...helpers,
        httpGet: async (url, o) => {
          calls.push({ url, opts: o });
          return { status, headers: {}, body: JSON.stringify(rows) };
        },
      },
    };
    return { ctx, calls };
  }

  // Gate B: OPEN TABLE → CRITICAL, and no row content stored.
  it('fires critical when a table returns rows to the anon key', async () => {
    const { ctx } = ctxWithStub({ status: 200, rows: [{ id: 1 }] });
    const findings = await rlsOpenProbe.run(ctx);
    expect(findings.length).toBeGreaterThan(0);
    expect(findings[0]!.severity).toBe('critical');
    expect(findings[0]!.category).toBe('database');
    expect(findings[0]!.mode).toBe('blackbox');
  });

  it('never stores returned row content in a finding (redacted/count-only)', async () => {
    const { ctx } = ctxWithStub({ status: 200, rows: [{ id: 1, email: 'secret@user.test', ssn: '111-22-3333' }] });
    const findings = await rlsOpenProbe.run(ctx);
    const blob = JSON.stringify(findings);
    expect(findings.length).toBeGreaterThan(0);
    expect(blob).not.toContain('secret@user.test');
    expect(blob).not.toContain('111-22-3333');
    expect(findings[0]!.evidence).toMatch(/row content discarded/i);
  });

  // Gate C: PROTECTED TABLE → NO CRITICAL.
  it('does not fire when RLS returns 401/403', async () => {
    expect((await rlsOpenProbe.run(ctxWithStub({ status: 401 }).ctx)).length).toBe(0);
    expect((await rlsOpenProbe.run(ctxWithStub({ status: 403 }).ctx)).length).toBe(0);
  });

  it('does not fire when tables return empty arrays', async () => {
    expect((await rlsOpenProbe.run(ctxWithStub({ status: 200, rows: [] }).ctx)).length).toBe(0);
  });

  // Gate D: NO SUPABASE → NO-OP.
  it('no-ops (no findings, no requests) when no Supabase was discovered', async () => {
    const { ctx, calls } = ctxWithStub({ discovered: {} });
    expect((await rlsOpenProbe.run(ctx)).length).toBe(0);
    expect(calls.length).toBe(0);
  });

  // Gate F: SAFETY — read-only, limit=1, capped, short timeout, no writes.
  it('issues only capped, read-only GET requests with limit=1 and a short timeout', async () => {
    const { ctx, calls } = ctxWithStub({ status: 401 }); // walk the whole wordlist
    await rlsOpenProbe.run(ctx);
    expect(calls.length).toBeGreaterThan(0);
    expect(calls.length).toBeLessThanOrEqual(12); // hard cap = wordlist length
    for (const c of calls) {
      expect(c.url).toContain('/rest/v1/');
      expect(c.url).toContain('limit=1');
      expect(c.opts?.method).toBeUndefined(); // GET only — never a write verb
      expect(c.opts?.body).toBeUndefined(); // no request body
      expect(c.opts?.timeoutMs).toBeLessThanOrEqual(6000); // bounded
      expect(c.opts?.headers?.apikey).toBe(ANON_JWT);
    }
  });
});
