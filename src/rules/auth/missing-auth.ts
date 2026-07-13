import type { Rule, Finding, ScanContext } from '../../types.js';
import { isSourceFile } from '../_shared.js';

const AUTH_SIGNALS = /(getServerSession|getSession|getUser|currentUser|auth\(\)|requireAuth|verifyToken|verifyJwt|jwt\.verify|withApiAuth|isAuthenticated|req\.user|ctx\.session|clerkClient|getAuth)\b/;
const MUTATION = /\.(update|delete|insert|create|destroy|remove|upsert)\s*\(/;
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

    for (const path of repo.files) {
      if (!isSourceFile(path)) continue;
      if (!/(api|route|server|actions?)/i.test(path)) continue;
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
        mode: 'whitebox',
        source: 'native',
      });
    }
    return out;
  },
};
