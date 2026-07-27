import { describe, it, expect } from 'vitest';
import { suppress, type SuppressibleFinding } from '../src/engine/suppress.js';
import type { Finding } from '../src/types.js';

function base(over: Partial<SuppressibleFinding>): SuppressibleFinding {
  return {
    ruleId: 'X',
    category: 'web_config',
    severity: 'medium',
    title: 't',
    whyItMatters: 'w',
    confidence: 'high',
    mode: 'blackbox',
    source: 'native',
    ...over,
  } as SuppressibleFinding;
}

describe('suppress — rate-limit static-asset guard (scaffolding)', () => {
  it('drops a RATE_LIMIT finding on a static-asset path', () => {
    const kept = suppress([
      base({ ruleId: 'RATE_LIMIT_MISSING', category: 'api_webhooks', location: { url: 'https://x.test/_next/static/chunks/main.js' } }),
    ]);
    expect(kept.length).toBe(0);
  });
  it('keeps a RATE_LIMIT finding on a real endpoint', () => {
    const kept = suppress([
      base({ ruleId: 'RATE_LIMIT_MISSING', category: 'api_webhooks', location: { url: 'https://x.test/api/login' } }),
    ]);
    expect(kept.length).toBe(1);
  });
});

describe('suppress — wildcard-CORS confidence down-ranking', () => {
  it('lowers confidence to low on a documented public API path', () => {
    const kept = suppress([
      base({ ruleId: 'WEB_CONFIG_CORS_WILDCARD_CREDENTIALS', confidence: 'high', location: { file: 'app/api/public/route.ts' } }),
    ]);
    expect(kept[0]!.confidence).toBe('low');
  });
  it('leaves confidence high on a normal endpoint', () => {
    const kept = suppress([
      base({ ruleId: 'WEB_CONFIG_CORS_WILDCARD_CREDENTIALS', confidence: 'high', location: { file: 'app/api/account/route.ts' } }),
    ]);
    expect(kept[0]!.confidence).toBe('high');
  });
});

describe('suppress — existing secrets suppression intact', () => {
  it('still drops a public-by-design secret (pk_ / anon)', () => {
    const pubKey = 'pk_live_' + 'a'.repeat(20);
    const kept: Finding[] = suppress([
      base({ ruleId: 'SECRETS_HARDCODED', category: 'secrets', severity: 'critical', _raw: pubKey }),
    ]);
    expect(kept.length).toBe(0);
  });
  it('keeps a genuinely dangerous secret', () => {
    const kept = suppress([
      base({ ruleId: 'SECRETS_STRIPE_SECRET_KEY', category: 'secrets', severity: 'critical', _raw: 'sk_live_' + 'a'.repeat(30) }),
    ]);
    expect(kept.length).toBe(1);
  });
});
