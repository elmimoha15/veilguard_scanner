import { describe, it, expect } from 'vitest';
import { publicSecretVar } from '../src/rules/platform/public-secret-var.js';
import { makeRepoContext } from './helpers.js';

describe('PLATFORM_PUBLIC_SECRET_VAR', () => {
  it('flags a secret-named var behind NEXT_PUBLIC_', async () => {
    const ctx = makeRepoContext({ '.env': 'NEXT_PUBLIC_STRIPE_SECRET_KEY=sk_live_x\nNEXT_PUBLIC_API_URL=https://a.b' });
    const findings = await publicSecretVar.run(ctx);
    expect(findings.length).toBe(1);
    expect(findings[0]!.evidence).toBe('NEXT_PUBLIC_STRIPE_SECRET_KEY');
  });
  it('does not flag a non-secret public var', async () => {
    const ctx = makeRepoContext({ '.env': 'NEXT_PUBLIC_API_URL=https://a.b' });
    expect((await publicSecretVar.run(ctx)).length).toBe(0);
  });
});
