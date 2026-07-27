import { describe, it, expect } from 'vitest';
import { nextConfig } from '../src/rules/web-config/nextconfig.js';
import { httpHeaders } from '../src/rules/web-config/http-headers.js';
import { exposedFiles } from '../src/rules/web-config/exposed-files.js';
import { sourceMaps } from '../src/rules/web-config/source-maps.js';
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
  it('flags a wildcard image remotePatterns hostname', async () => {
    const ctx = makeRepoContext({
      'next.config.js': `module.exports = { images: { remotePatterns: [{ protocol: 'https', hostname: '**' }] } }`,
    });
    expect((await nextConfig.run(ctx)).map((f) => f.ruleId)).toContain('WEB_CONFIG_NEXT_IMAGE_WILDCARD');
  });
  it('does not flag an allowlisted image host', async () => {
    const ctx = makeRepoContext({
      'next.config.js': `module.exports = { images: { remotePatterns: [{ protocol: 'https', hostname: 'cdn.example.com' }] } }`,
    });
    expect((await nextConfig.run(ctx)).map((f) => f.ruleId)).not.toContain('WEB_CONFIG_NEXT_IMAGE_WILDCARD');
  });
});

describe('WEB_CONFIG_EXPOSED_SOURCEMAP (black-box)', () => {
  const SOURCEMAP = JSON.stringify({ version: 3, sources: ['../src/app.tsx'], mappings: 'AAAA' });
  function ctxWithMap(mapBody: string, status = 200): ScanContext {
    return {
      target: { type: 'url', value: 'https://x.test' },
      http: {
        baseUrl: 'https://x.test',
        reachable: true,
        homepageHtml: '',
        headers: {},
        jsBundles: [{ url: 'https://x.test/_next/static/chunks/main.js', content: '' }],
        cookies: [],
      },
      helpers: {
        ...helpers,
        httpGet: async (url: string) => (url.endsWith('.map') ? { status, headers: {}, body: mapBody } : { status: 404, headers: {}, body: '' }),
      },
    };
  }
  it('fires when a referenced bundle has a public .map', async () => {
    const findings = await sourceMaps.run(ctxWithMap(SOURCEMAP));
    expect(findings.some((f) => f.ruleId === 'WEB_CONFIG_EXPOSED_SOURCEMAP')).toBe(true);
  });
  it('does not fire when the .map is 404', async () => {
    expect((await sourceMaps.run(ctxWithMap(SOURCEMAP, 404))).length).toBe(0);
  });
  it('does not fire on an SPA fallback that is not a real source map', async () => {
    expect((await sourceMaps.run(ctxWithMap('<!doctype html><html></html>'))).length).toBe(0);
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
