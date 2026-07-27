import { describe, it, expect } from 'vitest';
import { sqlInjection } from '../src/rules/injection/sql-injection.js';
import { commandInjection } from '../src/rules/injection/command-injection.js';
import { xss } from '../src/rules/injection/xss.js';
import { ssrf } from '../src/rules/injection/ssrf.js';
import { makeRepoContext } from './helpers.js';

describe('INJECTION_SQL', () => {
  it('fires on Prisma $queryRawUnsafe', async () => {
    const ctx = makeRepoContext({ 'a.ts': `prisma.$queryRawUnsafe('SELECT * FROM u WHERE id = ' + id)` });
    expect((await sqlInjection.run(ctx)).length).toBeGreaterThan(0);
  });
  it('fires on string-concatenated SQL', async () => {
    const ctx = makeRepoContext({ 'a.ts': `const sql = 'SELECT * FROM orders WHERE user_id = ' + userId;` });
    expect((await sqlInjection.run(ctx)).some((f) => f.ruleId === 'INJECTION_SQL')).toBe(true);
  });
  it('does not fire on a parameterized query', async () => {
    const ctx = makeRepoContext({ 'a.ts': `pool.query('SELECT * FROM orders WHERE id = $1', [id])` });
    expect((await sqlInjection.run(ctx)).length).toBe(0);
  });
});

describe('INJECTION_COMMAND', () => {
  it('fires on exec with interpolation', async () => {
    const ctx = makeRepoContext({ 'a.ts': 'exec(`ping ${host}`)' });
    expect((await commandInjection.run(ctx)).length).toBe(1);
  });
  it('does not fire on a static exec', async () => {
    const ctx = makeRepoContext({ 'a.ts': `execFile('ls', ['-la'])` });
    expect((await commandInjection.run(ctx)).length).toBe(0);
  });
});

describe('INJECTION_XSS', () => {
  it('fires on dangerouslySetInnerHTML with a dynamic value', async () => {
    const ctx = makeRepoContext({ 'a.tsx': `<div dangerouslySetInnerHTML={{ __html: userInput }} />` });
    expect((await xss.run(ctx)).length).toBe(1);
  });
  it('does not fire when sanitized with DOMPurify', async () => {
    const ctx = makeRepoContext({ 'a.tsx': `<div dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(x) }} />` });
    expect((await xss.run(ctx)).length).toBe(0);
  });
});

describe('INJECTION_SSRF', () => {
  it('fires (high) on a request to the cloud metadata endpoint', async () => {
    const ctx = makeRepoContext({ 'a.ts': `await fetch('http://169.254.169.254/latest/meta-data/iam/security-credentials/')` });
    const findings = await ssrf.run(ctx);
    expect(findings.length).toBeGreaterThan(0);
    expect(findings[0]!.severity).toBe('high');
    expect(findings[0]!.confidence).toBe('high');
  });
  it('fires on a fetch whose URL is built directly from user input', async () => {
    const ctx = makeRepoContext({
      'app/api/proxy/route.ts': `export async function POST(req){ return fetch(\`https://\${req.query.url}/data\`); }`,
    });
    expect((await ssrf.run(ctx)).some((f) => f.ruleId === 'INJECTION_SSRF')).toBe(true);
  });
  it('does not fire on a static, trusted URL', async () => {
    const ctx = makeRepoContext({ 'a.ts': `await fetch('https://api.stripe.com/v1/charges')` });
    expect((await ssrf.run(ctx)).length).toBe(0);
  });
});
