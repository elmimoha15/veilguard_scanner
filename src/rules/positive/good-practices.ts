import type { Rule, ScanContext, Category } from '../../types.js';

/**
 * White-box, PASS-ONLY rule. It emits no findings — it recognises good security
 * practices already present in the project (dependencies + config) so the report
 * can show the user what they did right. Every signal is conservative: it only
 * passes on a clear positive, and only when there's a package manifest to read.
 */

interface Signal {
  id: string;
  category: Category;
  title: string;
  detail: string;
  /** Dependency names; a trailing '*' matches by prefix (e.g. '@clerk/*'). */
  deps?: string[];
  /** Extra detector for signals not expressed as a dependency. */
  fileTest?: (ctx: ScanContext) => boolean;
}

function hasDep(deps: Record<string, string>, names: string[]): boolean {
  const keys = Object.keys(deps);
  return names.some((n) =>
    n.endsWith('*') ? keys.some((d) => d.startsWith(n.slice(0, -1))) : n in deps,
  );
}

function nextConfigHasHeaders(ctx: ScanContext): boolean {
  const repo = ctx.repo;
  if (!repo) return false;
  const f = repo.files.find((p) => /(^|\/)next\.config\.(js|ts|mjs|cjs)$/.test(p));
  if (!f) return false;
  const c = repo.readFile(f);
  if (!c) return false;
  return /headers\s*\(/.test(c) && /(content-security-policy|x-frame-options|strict-transport-security|x-content-type-options)/i.test(c);
}

const SIGNALS: Signal[] = [
  {
    id: 'PASS_RATE_LIMITING',
    category: 'api_webhooks',
    title: 'Rate limiting is in place',
    detail: 'A rate-limiting library is set up, which helps block brute-force and abuse.',
    deps: ['express-rate-limit', 'rate-limiter-flexible', '@upstash/ratelimit', '@fastify/rate-limit', '@nestjs/throttler', 'hono-rate-limiter', 'next-rate-limit'],
  },
  {
    id: 'PASS_INPUT_VALIDATION',
    category: 'injection',
    title: 'Input validation is in use',
    detail: 'A schema-validation library is present to check untrusted input before you use it.',
    deps: ['zod', 'yup', 'joi', '@hapi/joi', 'valibot', 'class-validator', 'superstruct', 'ajv'],
  },
  {
    id: 'PASS_ORM_PARAMETERIZED',
    category: 'injection',
    title: 'Database queries use an ORM / query builder',
    detail: 'Queries go through a library that parameterizes inputs, which guards against SQL injection.',
    deps: ['@prisma/client', 'prisma', 'drizzle-orm', 'typeorm', 'sequelize', 'kysely', 'knex', 'mongoose'],
  },
  {
    id: 'PASS_AUTH_LIBRARY',
    category: 'auth',
    title: 'Authentication uses a vetted library',
    detail: 'Sign-in is handled by an established auth library rather than hand-rolled.',
    deps: ['next-auth', '@auth/*', '@clerk/*', 'lucia', '@auth0/*', 'passport', '@workos-inc/*'],
  },
  {
    id: 'PASS_SECURITY_HEADERS_CONFIG',
    category: 'web_config',
    title: 'Security headers are configured',
    detail: 'Your app sets security response headers in code (Helmet or a headers() config).',
    deps: ['helmet'],
    fileTest: nextConfigHasHeaders,
  },
];

export const goodPractices: Rule = {
  id: 'POSITIVE_GOOD_PRACTICES',
  category: 'web_config',
  mode: 'whitebox',
  async run(ctx: ScanContext) {
    const deps = ctx.repo?.packageManifest?.allDeps;
    if (!deps) return []; // no manifest → we didn't actually evaluate these checks
    for (const s of SIGNALS) {
      const viaDep = s.deps ? hasDep(deps, s.deps) : false;
      const viaFile = s.fileTest ? s.fileTest(ctx) : false;
      if (viaDep || viaFile) {
        ctx.reportPass?.({ id: s.id, category: s.category, title: s.title, detail: s.detail, mode: 'whitebox' });
      }
    }
    return [];
  },
};
