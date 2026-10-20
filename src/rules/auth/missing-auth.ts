import type { Rule, Finding, ScanContext } from '../../types.js';
import { isSourceFile } from '../_shared.js';

const AUTH_SIGNALS = /(getServerSession|getSession|getUser|currentUser|auth\(\)|requireAuth|verifyToken|verifyJwt|jwt\.verify|withApiAuth|isAuthenticated|req\.user|ctx\.session|clerkClient|getAuth|requireUser|withAuth|getToken|auth\.getUser|\bget(Server|Current)?(User|Profile|Session)\w*\s*\(|validateRequest|protectedProcedure|authenticate\s*\()\b/;
// A DATABASE write, not any method named create/update (openai.chat.completions.create,
// stripe.customers.create and Map.delete are not data mutations).
const MUTATION =
  /\.(from|table|collection|doc)\([^)]*\)[\s\S]{0,80}?\.(update|delete|insert|upsert|remove|set)\s*\(|\b(prisma|db|knex|drizzle|tx|models?)\.\w+\.(update|delete|create|upsert|deleteMany|updateMany|createMany|destroy|insert)\s*\(|\.(destroy|deleteOne|deleteMany|updateOne|updateMany|insertOne|insertMany|findByIdAndDelete|findByIdAndUpdate)\s*\(|\b(INSERT\s+INTO|UPDATE\s+\w+\s+SET|DELETE\s+FROM)\b/;
const HANDLER = /export\s+(async\s+)?function\s+(POST|PUT|PATCH|DELETE)\b|export\s+const\s+(POST|PUT|PATCH|DELETE)\s*=/;

/**
 * White-box (heuristic): an API route handler that performs a DB mutation but
 * shows no sign of an auth/session check. Conservative — requires a mutation to
 * fire, to avoid flagging public read endpoints.
 */
export const missingAuth: Rule = {
  id: 'AUTH_MISSING_CHECK',
  category: 'auth',
  mode: 'whitebox',
  async run(ctx: ScanContext): Promise<Finding[]> {
    const repo = ctx.repo;
    if (!repo) return [];
    const out: Finding[] = [];

    // Auth enforced centrally in middleware protects every route it matches.
    const middleware = repo.files.find((f) => /(^|\/)(src\/)?middleware\.(ts|js|mjs)$/.test(f));
    const mwContent = middleware ? repo.readFile(middleware) ?? '' : '';
    const middlewareAuth = AUTH_SIGNALS.test(mwContent) && !/matcher[\s\S]{0,200}\?!api/.test(mwContent);

    for (const path of repo.files) {
      if (!isSourceFile(path)) continue;
      if (!/(api|route|server|actions?)/i.test(path)) continue;
      if (middlewareAuth) continue;
      const content = repo.readFile(path);
      if (!content) continue;

      const isHandler = HANDLER.test(content) || /['"]use server['"]/.test(content);
      if (!isHandler) continue;
      if (!MUTATION.test(content)) continue;
      if (AUTH_SIGNALS.test(content)) continue;

      out.push({
        ruleId: 'AUTH_MISSING_CHECK',
        category: 'auth',
        severity: 'high',
        cwe: 'CWE-306',
        owasp: 'A01:2021',
        title: 'An endpoint changes data without checking who’s calling',
        whyItMatters: 'A write/delete handler with no authentication check can be called by anyone to modify or destroy data.',
        location: { file: path },
        fix: 'Verify the session/token at the top of the handler and reject unauthenticated requests before any database write.',
        fixPrompt:
          'Add an authentication check at the start of this API route/server action: load the current session (e.g. getServerSession/getUser/auth()), and return 401 if there is no authenticated user before performing any database mutation.',
        confidence: 'low',
        verifyHint: 'Open the route and check that it confirms who is calling (session, token or middleware) before writing. If a helper or middleware does it, this is safe.',
        mode: 'whitebox',
        source: 'native',
      });
    }
    return out;
  },
};
