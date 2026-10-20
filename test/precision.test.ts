import { describe, it, expect } from 'vitest';
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { execFileSync } from 'node:child_process';
import { isPlaceholder, looksLikeSecretValue, redactSecret, hasPemBody } from '../src/engine/evidence.js';
import { calibrate } from '../src/engine/calibrate.js';
import { buildContext } from '../src/engine/recon.js';
import { runScan } from '../src/engine/runner.js';
import type { Finding } from '../src/types.js';

describe('evidence: placeholders vs real values', () => {
  it('recognises placeholder/example values', () => {
    for (const v of ['sk_live_xxxxxxxxxxxxxxxxxxxxxxxx', 'AKIAIOSFODNN7EXAMPLE', 'YOUR_API_KEY_HERE', '<your-token>', '${STRIPE_KEY}', 'changeme', 'abcdefghijkl', '1234567890', 'postgres://postgres:postgres@localhost:5432/db', 'postgres://user:password@db.example.com/app']) {
      expect(isPlaceholder(v), v).toBe(true);
    }
  });
  it('keeps real-looking values', () => {
    for (const v of ['sk_live_51QabcdEFGH1234567890ijklMNOPqrstUVWXyz', 'postgres://app:Xk9fJ2Lm@db.internal.example.com:5432/app', '9f8a7b6c5d4e3f2a1b0c9d8e7f6a5b4c3d2e1f0a']) {
      expect(isPlaceholder(v), v).toBe(false);
    }
  });
  it('public-by-design keys are never secret values', () => {
    for (const v of ['pk_live_51QabcdEFGH1234567890publishablekey', 'sb_publishable_AbC123dEf456GhI789jKl', 'AIzaSyA1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q', 'phc_a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8']) {
      expect(looksLikeSecretValue(v), v).toBe(false);
    }
  });
  it('a provider secret or a long random token is a secret value; prose and short words are not', () => {
    expect(looksLikeSecretValue('sk_live_51QabcdEFGH1234567890ijklMNOPqrstUVWXyz')).toBe(true);
    expect(looksLikeSecretValue('9f8a7b6c5d4e3f2a1b0c9d8e7f6a5b4c3d2e1f0a')).toBe(true);
    expect(looksLikeSecretValue('https://acme.dev')).toBe(false);
    expect(looksLikeSecretValue('this is a sentence about keys')).toBe(false);
    expect(looksLikeSecretValue('short')).toBe(false);
  });
  it('redacts to a short recognisable prefix', () => {
    expect(redactSecret('sk_live_51QabcdEFGH1234567890ijklMNOPqrstUVWXyz')).toBe('sk_live_51Qa****');
    expect(redactSecret('whsec_1a2b3c4d5e6f7g8h9i0jklmnopqrstuv')).toBe('whsec_1a2b****');
    expect(redactSecret('-----BEGIN PRIVATE KEY-----MIIE')).toBe('-----BEGIN PRIVATE KEY-----****');
  });
  it('a PEM needs a key body, not just the header', () => {
    expect(hasPemBody("'-----BEGIN PRIVATE KEY-----\\n' + b64", 1)).toBe(false);
    expect(hasPemBody('-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7k3Lq9Zx2Vt8RmPw\n', 0)).toBe(true);
  });
});

describe('calibrate: severity honesty', () => {
  const f = (severity: Finding['severity'], confidence: Finding['confidence']): Finding => ({
    ruleId: 'X', category: 'injection', severity, title: 't', whyItMatters: 'w', confidence, mode: 'whitebox', source: 'native',
  });
  it('a low-confidence finding is never medium+ (keeps potentialSeverity + a verify hint)', () => {
    const out = calibrate(f('high', 'low'));
    expect(out.severity).toBe('low');
    expect(out.potentialSeverity).toBe('high');
    expect(out.verifyHint).toBeTruthy();
  });
  it('critical requires high confidence', () => {
    expect(calibrate(f('critical', 'medium')).severity).toBe('high');
    expect(calibrate(f('critical', 'high')).severity).toBe('critical');
  });
});

describe('only files git would commit are scanned', () => {
  it('a gitignored local .env is not "committed"; a tracked one is', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'vg-git-'));
    try {
      const git = (...a: string[]) => execFileSync('git', ['-C', dir, ...a], { stdio: 'ignore' });
      git('init', '-q');
      writeFileSync(join(dir, '.gitignore'), '.env\n');
      writeFileSync(join(dir, '.env'), 'STRIPE_SECRET_KEY=sk_live_51QabcdEFGH1234567890ijklMNOPqrstUVWXyz\n');
      const ignored = await runScan(await buildContext({ type: 'repo', value: dir }), { skipEngines: true });
      expect(ignored.findings.filter((x) => x.category === 'secrets')).toEqual([]);

      // Force-added despite .gitignore → really committed → must fire.
      git('add', '-f', '.env');
      const tracked = await runScan(await buildContext({ type: 'repo', value: dir }), { skipEngines: true });
      expect(tracked.findings.some((x) => x.ruleId === 'SECRETS_COMMITTED_ENV')).toBe(true);
      expect(tracked.findings.some((x) => x.ruleId === 'SECRETS_STRIPE_SECRET_KEY' && x.severity === 'critical')).toBe(true);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});
