import { describe, it, expect } from 'vitest';
import { goodPractices } from '../src/rules/positive/good-practices.js';
import { httpHeaders } from '../src/rules/web-config/http-headers.js';
import { hardcodedSecrets } from '../src/rules/secrets/hardcoded-secrets.js';
import { makeRepoContext, makeHttpContext } from './helpers.js';
import type { ScanContext, PassedCheck } from '../src/types.js';

/** Attach a pass collector (normally provided by the runner). */
function withPasses(ctx: ScanContext): { ctx: ScanContext; passes: PassedCheck[] } {
  const passes: PassedCheck[] = [];
  ctx.reportPass = (c) => passes.push(c);
  return { ctx, passes };
}

describe('passed checks (positive results)', () => {
  it('good-practices detects input validation, ORM and rate limiting from deps', async () => {
    const { ctx, passes } = withPasses(
      makeRepoContext({ 'package.json': JSON.stringify({ dependencies: { zod: '^3', '@prisma/client': '^5', 'express-rate-limit': '^7' } }) }),
    );
    await goodPractices.run(ctx);
    const ids = passes.map((p) => p.id);
    expect(ids).toContain('PASS_INPUT_VALIDATION');
    expect(ids).toContain('PASS_ORM_PARAMETERIZED');
    expect(ids).toContain('PASS_RATE_LIMITING');
  });

  it('good-practices stays silent when nothing good is present (no false praise)', async () => {
    const { ctx, passes } = withPasses(makeRepoContext({ 'package.json': JSON.stringify({ dependencies: { lodash: '^4' } }) }));
    await goodPractices.run(ctx);
    expect(passes).toHaveLength(0);
  });

  it('http-headers reports a pass for each present header', async () => {
    const { ctx, passes } = withPasses(
      makeHttpContext({ headers: { 'content-security-policy': "default-src 'self'", 'x-frame-options': 'DENY' } }),
    );
    await httpHeaders.run(ctx);
    const ids = passes.map((p) => p.id);
    expect(ids).toContain('PASS_WEB_CONFIG_CONTENT_SECURITY_POLICY');
    expect(ids).toContain('PASS_WEB_CONFIG_X_FRAME_OPTIONS');
  });

  it('hardcoded-secrets reports a pass when a scanned repo has no secrets', async () => {
    const { ctx, passes } = withPasses(makeRepoContext({ 'index.js': 'export const x = 1;' }));
    await hardcodedSecrets.run(ctx);
    expect(passes.map((p) => p.id)).toContain('PASS_SECRETS_NONE_EXPOSED');
  });

  it('does not report a pass when the check did not run (unreachable URL)', async () => {
    const { ctx, passes } = withPasses(makeHttpContext({ reachable: false }));
    await httpHeaders.run(ctx);
    expect(passes).toHaveLength(0);
  });
});
