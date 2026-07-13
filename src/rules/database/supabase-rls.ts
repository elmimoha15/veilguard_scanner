import type { Rule, Finding, ScanContext } from '../../types.js';
import { safeRegexScan } from '../../engine/helpers.js';

const CREATE_TABLE = /create\s+table\s+(?:if\s+not\s+exists\s+)?(?:public\.)?["']?([a-z_][a-z0-9_]*)["']?/gi;
const ENABLE_RLS = /alter\s+table\s+(?:public\.)?["']?([a-z_][a-z0-9_]*)["']?\s+enable\s+row\s+level\s+security/gi;
const PERMISSIVE = /using\s*\(\s*(true|1\s*=\s*1|auth\.uid\(\)\s+is\s+not\s+null)\s*\)/gi;
const SECURITY_DEFINER_VIEW = /create\s+(?:or\s+replace\s+)?view\s+(?:public\.)?["']?([a-z_][a-z0-9_]*)/gi;

/**
 * White-box Supabase Postgres RLS analysis over .sql migration files:
 *  - public tables created without RLS enabled,
 *  - over-permissive USING clauses,
 *  - SECURITY DEFINER views without security_invoker.
 */
export const supabaseRls: Rule = {
  id: 'DATABASE_SUPABASE_RLS',
  category: 'database',
  mode: 'whitebox',
  async run(ctx: ScanContext): Promise<Finding[]> {
    const repo = ctx.repo;
    if (!repo || repo.sqlFiles.length === 0) return [];

    const out: Finding[] = [];

    // Aggregate which tables get RLS enabled anywhere across all migrations.
    const rlsEnabled = new Set<string>();
    const created: { table: string; file: string; line: number }[] = [];

    for (const file of repo.sqlFiles) {
      const sql = repo.readFile(file);
      if (!sql) continue;

      for (const m of safeRegexScan(sql, ENABLE_RLS)) {
        const name = m.groups[0];
        if (name) rlsEnabled.add(name.toLowerCase());
      }
      for (const m of safeRegexScan(sql, CREATE_TABLE)) {
        const name = m.groups[0];
        if (name) created.push({ table: name.toLowerCase(), file, line: m.line });
      }

      // Over-permissive policies.
      for (const m of safeRegexScan(sql, PERMISSIVE)) {
        out.push({
          ruleId: 'DATABASE_RLS_PERMISSIVE_POLICY',
          category: 'database',
          severity: 'critical',
          cwe: 'CWE-639',
          owasp: 'A01:2021',
          title: 'A Row Level Security policy lets any logged-in user read/write everything',
          whyItMatters:
            'A policy like `using (auth.uid() is not null)` checks only that someone is signed in — any signed-up visitor can read every row, not just their own.',
          evidence: m.match,
          location: { file, line: m.line },
          fix: 'Scope the policy to the owner, e.g. `using (auth.uid() = user_id)`.',
          fixPrompt:
            'Rewrite this Supabase RLS policy so it only allows a user to access their own rows, e.g. `using (auth.uid() = user_id)` instead of checking only that the user is logged in.',
          confidence: 'high',
          mode: 'whitebox',
          source: 'native',
        });
      }

      // SECURITY DEFINER views (bypass RLS unless security_invoker is set).
      for (const m of safeRegexScan(sql, SECURITY_DEFINER_VIEW)) {
        const rest = sql.slice(m.index, m.index + 400);
        if (!/security_invoker\s*=\s*true/i.test(rest)) {
          out.push({
            ruleId: 'DATABASE_SECURITY_DEFINER_VIEW',
            category: 'database',
            severity: 'high',
            cwe: 'CWE-639',
            title: 'A view may bypass Row Level Security',
            whyItMatters:
              'Postgres views run with the creator’s permissions by default, so they can leak rows RLS would otherwise hide.',
            evidence: m.match,
            location: { file, line: m.line },
            fix: 'Create the view with `WITH (security_invoker = true)`.',
            fixPrompt: 'Add `WITH (security_invoker = true)` to this Postgres view so it respects the querying user’s RLS policies.',
            confidence: 'medium',
            mode: 'whitebox',
            source: 'native',
          });
        }
      }
    }

    for (const c of created) {
      if (!rlsEnabled.has(c.table)) {
        out.push({
          ruleId: 'DATABASE_RLS_DISABLED',
          category: 'database',
          severity: 'critical',
          cwe: 'CWE-1220',
          owasp: 'A01:2021',
          title: `Table "${c.table}" has no Row Level Security`,
          whyItMatters:
            'Without RLS, anyone with your public anon key can read (and often write) every row in this table directly over the REST API.',
          location: { file: c.file, line: c.line },
          fix: `Run: ALTER TABLE ${c.table} ENABLE ROW LEVEL SECURITY; then add owner-scoped policies.`,
          fixPrompt: `Enable Row Level Security on the "${c.table}" table and add policies so users can only access their own rows (e.g. using (auth.uid() = user_id)).`,
          confidence: 'high',
          mode: 'whitebox',
          source: 'native',
        });
      }
    }

    return out;
  },
};
