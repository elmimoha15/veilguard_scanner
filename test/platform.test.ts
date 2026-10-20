import { describe, it, expect } from 'vitest';
import { publicSecretVar } from '../src/rules/platform/public-secret-var.js';
import { makeRepoContext } from './helpers.js';

describe('PLATFORM_PUBLIC_SECRET_VAR', () => {
  it('flags a REAL secret value behind NEXT_PUBLIC_ at high, with redacted evidence', async () => {
    const ctx = makeRepoContext({ '.env': 'NEXT_PUBLIC_STRIPE_SECRET_KEY=sk_live_51QabcdEFGH1234567890ijklMNOPqrstUVWXyz\nNEXT_PUBLIC_API_URL=https://a.b' });
    const findings = await publicSecretVar.run(ctx);
    expect(findings.length).toBe(1);
    expect(findings[0]!.severity).toBe('high');
    expect(findings[0]!.confidence).toBe('high');
    expect(findings[0]!.evidence).toBe('NEXT_PUBLIC_STRIPE_SECRET_KEY=sk_live_51Qa****');
  });
  it('a short, non-secret-looking value is only a low-confidence "verify"', async () => {
    const ctx = makeRepoContext({ '.env': 'NEXT_PUBLIC_STRIPE_SECRET_KEY=sk_live_x' });
    const findings = await publicSecretVar.run(ctx);
    expect(findings.length).toBe(1);
    expect(findings[0]!.confidence).toBe('low');
  });
  it('does not flag a non-secret public var', async () => {
    const ctx = makeRepoContext({ '.env': 'NEXT_PUBLIC_API_URL=https://a.b' });
    expect((await publicSecretVar.run(ctx)).length).toBe(0);
  });
});
