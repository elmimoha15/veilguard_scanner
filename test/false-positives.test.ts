import { describe, it, expect } from 'vitest';
import type { Finding } from '../src/types.js';
import { classifySecret, looksLikeExampleConnString } from '../src/engine/secret-matrix.js';
import { classifyFile, contextualize } from '../src/engine/file-context.js';
import { grade, computeScore } from '../src/engine/grade.js';
import { xss } from '../src/rules/injection/xss.js';
import { makeRepoContext } from './helpers.js';

// ── Example vs real connection strings (value-based) ──────────────────────────
describe('example connection strings', () => {
  it('treats placeholder-password conn strings as examples (not leaks)', () => {
    expect(looksLikeExampleConnString('postgres://user:password@host:5432/db')).toBe(true);
    expect(looksLikeExampleConnString('mongodb+srv://username:password@cluster0.mongodb.net/test')).toBe(true);
    expect(looksLikeExampleConnString('postgres://app:${DB_PASSWORD}@db.internal/app')).toBe(true);
    expect(looksLikeExampleConnString('mysql://root:<your-password>@localhost/app')).toBe(true);
    expect(classifySecret('postgres://user:password@host/db').verdict).toBe('public');
  });

  it('STILL flags a real connection string with a real password', () => {
    // Real high-entropy password → not an example → dangerous.
    expect(looksLikeExampleConnString('postgres://admin:Xk9fJ2Lm4pQ@db.prod.internal:5432/app')).toBe(false);
    expect(classifySecret('postgres://admin:Xk9fJ2Lm4pQ@db.prod.internal:5432/app').verdict).toBe('dangerous');
  });
});

// ── XSS: static/JSON-LD safe, user input still fires ──────────────────────────
describe('INJECTION_XSS static vs dynamic', () => {
  async function run(src: string): Promise<Finding[]> {
    const ctx = makeRepoContext({ 'app/comp.tsx': src });
    return xss.run(ctx);
  }

  it('does NOT flag JSON.stringify of a static object (JSON-LD)', async () => {
    const f = await run(
      `const ld = { a: 1 };\nexport default () => <script type="application/ld+json" dangerouslySetInnerHTML={{ __html: JSON.stringify(ld) }} />;`,
    );
    expect(f.length).toBe(0);
  });

  it('does NOT flag a plain string literal', async () => {
    const f = await run(`export default () => <div dangerouslySetInnerHTML={{ __html: "<b>hi</b>" }} />;`);
    expect(f.length).toBe(0);
  });

  it('STILL flags user/request-derived input as HIGH', async () => {
    const f = await run(`export default ({ props }) => <div dangerouslySetInnerHTML={{ __html: props.bio }} />;`);
    expect(f.some((x) => x.ruleId === 'INJECTION_XSS' && x.severity === 'high' && x.confidence === 'high')).toBe(true);
  });

  it('marks an unknown non-static expr as LOW confidence, not HIGH', async () => {
    const f = await run(`export default () => <div dangerouslySetInnerHTML={{ __html: renderedHtml }} />;`);
    expect(f.length).toBe(1);
    expect(f[0]!.severity).toBe('low');
    expect(f[0]!.confidence).toBe('low');
  });
});

// ── File classification + context downgrade ───────────────────────────────────
describe('classifyFile + contextualize', () => {
  it('classifies paths', () => {
    expect(classifyFile('src/content/landing.ts')).toBe('content');
    expect(classifyFile('docs/guide.md')).toBe('docs');
    expect(classifyFile('README.md')).toBe('docs');
    expect(classifyFile('examples/demo.ts')).toBe('example');
    expect(classifyFile('src/app/api/pay/route.ts')).toBe('source');
    expect(classifyFile('.env')).toBe('credential');
    expect(classifyFile('.env.example')).toBe('example');
  });

  const mk = (over: Partial<Finding>): Finding => ({
    ruleId: 'X',
    category: 'injection',
    severity: 'critical',
    title: 't',
    whyItMatters: 'w',
    confidence: 'high',
    mode: 'whitebox',
    source: 'native',
    location: { file: 'src/app/x.ts' },
    ...over,
  });

  it('downgrades a code-pattern finding in a content file', () => {
    const out = contextualize(mk({ location: { file: 'src/content/x.ts' } }));
    expect(out.severity).toBe('low');
    expect(out.confidence).toBe('low');
  });

  it('leaves a finding in real source untouched', () => {
    const out = contextualize(mk({ location: { file: 'src/app/api/pay/route.ts' } }));
    expect(out.severity).toBe('critical');
    expect(out.confidence).toBe('high');
  });

  it('does NOT path-downgrade secrets in a content file (value decides)', () => {
    const out = contextualize(mk({ category: 'secrets', location: { file: 'src/content/x.ts' } }));
    expect(out.severity).toBe('critical'); // left for the value-based classifier
  });
});

// ── Grade: confidence weighting + confirmed-critical cap ──────────────────────
describe('confidence-weighted grade', () => {
  const f = (severity: Finding['severity'], confidence: Finding['confidence']): Finding => ({
    ruleId: 'X', category: 'injection', severity, title: 't', whyItMatters: 'w', confidence, mode: 'whitebox', source: 'native',
  });

  it('a lone LOW-confidence critical does NOT force a D', () => {
    const g = grade([f('critical', 'low')]);
    expect(g.grade).toBe('A'); // 100 − 35×0.15 ≈ 95 → A, and no confirmed critical
  });

  it('a HIGH-confidence critical STILL caps at D (or F)', () => {
    const g = grade([f('critical', 'high')]);
    expect(['D', 'F']).toContain(g.grade);
  });

  it('low-confidence findings barely move the score', () => {
    expect(computeScore([f('high', 'low')])).toBeGreaterThanOrEqual(97);
    expect(computeScore([f('high', 'high')])).toBe(85);
  });
});
