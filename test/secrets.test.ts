import { describe, it, expect } from 'vitest';
import { hardcodedSecrets } from '../src/rules/secrets/hardcoded-secrets.js';
import { committedEnv } from '../src/rules/secrets/committed-env.js';
import { suppress, type SuppressibleFinding } from '../src/engine/suppress.js';
import { makeRepoContext } from './helpers.js';

describe('SECRETS_HARDCODED', () => {
  it('fires on a hardcoded Stripe secret key', async () => {
    const ctx = makeRepoContext({ 'lib/pay.ts': `const k = 'sk_live_51QabcdEFGH1234567890ijklMNOPqrst';` });
    const findings = await hardcodedSecrets.run(ctx);
    expect(findings.some((f) => f.ruleId === 'SECRETS_STRIPE_SECRET_KEY' && f.severity === 'critical')).toBe(true);
  });

  it('fires on a service_role JWT (not on an anon JWT)', async () => {
    const serviceRole =
      'eyJhbGciOiJIUzI1NiJ9.eyJyb2xlIjoic2VydmljZV9yb2xlIiwiaWF0IjoxfQ.aaaaaaaaaaaa';
    const anon = 'eyJhbGciOiJIUzI1NiJ9.eyJyb2xlIjoiYW5vbiIsImlhdCI6MX0.bbbbbbbbbbbb';
    const danger = await hardcodedSecrets.run(makeRepoContext({ 'a.ts': `const s='${serviceRole}'` }));
    const safe = await hardcodedSecrets.run(makeRepoContext({ 'a.ts': `const s='${anon}'` }));
    expect(danger.length).toBeGreaterThan(0);
    expect(safe.length).toBe(0);
  });

  it('does NOT fire on public-by-design values', async () => {
    const ctx = makeRepoContext({
      'config.ts': `
        const pub = 'pk_live_51QabcdEFGH1234567890publishable';
        const key = { apiKey: 'AIzaSyD-1234567890abcdefghijklmnopqrstuv' };
        const ph = 'phc_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789';
      `,
    });
    const findings = await hardcodedSecrets.run(ctx);
    expect(findings.length).toBe(0);
  });
});

describe('SECRETS_COMMITTED_ENV', () => {
  it('fires when a .env with values is present and .gitignore omits it', async () => {
    const ctx = makeRepoContext({
      '.env': 'API_SECRET=supersecretvalue123',
      '.gitignore': 'node_modules/\n',
    });
    const findings = await committedEnv.run(ctx);
    expect(findings.some((f) => f.ruleId === 'SECRETS_COMMITTED_ENV')).toBe(true);
  });

  it('does not fire on .env.example', async () => {
    const ctx = makeRepoContext({ '.env.example': 'API_KEY=YOUR_KEY_HERE' });
    expect((await committedEnv.run(ctx)).length).toBe(0);
  });
});

describe('suppress()', () => {
  it('drops secrets-category findings whose raw value is public', () => {
    const input: SuppressibleFinding[] = [
      { ruleId: 'X', category: 'secrets', severity: 'critical', title: 't', whyItMatters: 'w', confidence: 'high', mode: 'whitebox', source: 'native', _raw: 'pk_live_51QabcdEFGH1234567890abcd' },
      { ruleId: 'Y', category: 'secrets', severity: 'critical', title: 't', whyItMatters: 'w', confidence: 'high', mode: 'whitebox', source: 'native', _raw: 'sk_live_51QabcdEFGH1234567890abcd' },
    ];
    const out = suppress(input);
    expect(out.map((f) => f.ruleId)).toEqual(['Y']);
    expect((out[0] as any)._raw).toBeUndefined();
  });
});
