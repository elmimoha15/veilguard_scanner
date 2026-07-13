import { describe, it, expect } from 'vitest';
import { nextConfig } from '../src/rules/web-config/nextconfig.js';
import { httpHeaders } from '../src/rules/web-config/http-headers.js';
import { exposedFiles } from '../src/rules/web-config/exposed-files.js';
import { makeRepoContext, makeHttpContext } from './helpers.js';
import { helpers } from '../src/engine/helpers.js';
import type { ScanContext } from '../src/types.js';

describe('WEB_CONFIG (next.config)', () => {
  it('flags wildcard CORS + credentials and missing headers', async () => {
    const ctx = makeRepoContext({
      'next.config.js': `module.exports = { async headers(){ return [{ source:'/api/:p*', headers:[{key:'Access-Control-Allow-Origin',value:'*'},{key:'Access-Control-Allow-Credentials',value:'true'}] }] } }`,
    });
    const ids = (await nextConfig.run(ctx)).map((f) => f.ruleId);
    expect(ids).toContain('WEB_CONFIG_CORS_WILDCARD_CREDENTIALS');
    expect(ids).toContain('WEB_CONFIG_MISSING_SECURITY_HEADERS');
  });
  it('does not flag a config with full security headers and no wildcard CORS', async () => {
    const ctx = makeRepoContext({
      'next.config.js': `module.exports = { async headers(){ return [{ source:'/:p*', headers:[{key:'Content-Security-Policy',value:"default-src 'self'"},{key:'Strict-Transport-Security',value:'max-age=1'},{key:'X-Frame-Options',value:'DENY'}] }] } }`,
    });
    expect((await nextConfig.run(ctx)).length).toBe(0);
  });
});

describe('WEB_CONFIG_HEADERS_LIVE (black-box)', () => {
  it('reports missing headers on a bare response', async () => {
    const ctx = makeHttpContext({ headers: {} });
    expect((await httpHeaders.run(ctx)).length).toBeGreaterThan(0);
  });
  it('reports nothing when all headers present', async () => {
    const ctx = makeHttpContext({
      headers: {
        'content-security-policy': "default-src 'self'",
        'strict-transport-security': 'max-age=1',
        'x-frame-options': 'DENY',
        'x-content-type-options': 'nosniff',
        'referrer-policy': 'no-referrer',
        'permissions-policy': 'geolocation=()',
      },
    });
    expect((await httpHeaders.run(ctx)).length).toBe(0);
  });
});

describe('WEB_CONFIG_EXPOSED_FILE (black-box)', () => {
  function ctxWithEnv(body: string): ScanContext {
    return {
      target: { type: 'url', value: 'https://x.test' },
      http: { baseUrl: 'https://x.test', reachable: true, homepageHtml: '', headers: {}, jsBundles: [], cookies: [] },
      helpers: {
        ...helpers,
        httpGet: async (url: string) => (url.endsWith('/.env') ? { status: 200, headers: {}, body } : { status: 404, headers: {}, body: '' }),
      },
    };
  }
  it('flags a publicly served .env', async () => {
    const findings = await exposedFiles.run(ctxWithEnv('STRIPE_SECRET_KEY=sk_live_51QabcdEFGH1234567890abcd'));
    expect(findings.some((f) => f.ruleId === 'WEB_CONFIG_EXPOSED_FILE')).toBe(true);
  });
  it('does not flag an SPA fallback (no env content)', async () => {
    expect((await exposedFiles.run(ctxWithEnv('<!doctype html><html></html>'))).length).toBe(0);
  });
});
