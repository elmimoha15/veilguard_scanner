import type { Rule, Finding, ScanContext } from '../../types.js';
import { safeRegexScan } from '../../engine/helpers.js';

// Match an optionally schema-qualified identifier and capture the TABLE (last)
// part — handles `tags`, `public.tags`, and the quoted `"public"."tags"` form
// (pg_dump). The old pattern grabbed the quoted schema ("public") as the name,
// so every finding read `Table "public"`.
const QUALIFIED = String.raw`(?:"?[a-z_][a-z0-9_]*"?\s*\.\s*)?"?([a-z_][a-z0-9_]*)"?`;
const CREATE_TABLE = new RegExp(String.raw`create\s+table\s+(?:if\s+not\s+exists\s+)?${QUALIFIED}`, 'gi');
const ENABLE_RLS = new RegExp(String.raw`alter\s+table\s+(?:only\s+)?${QUALIFIED}\s+enable\s+row\s+level\s+security`, 'gi');
const PERMISSIVE = /using\s*\(\s*(true|1\s*=\s*1|auth\.uid\(\)\s+is\s+not\s+null)\s*\)/gi;
/** Tables that are public by design in almost every app (storefront catalogs, CMS). */
const PUBLIC_CATALOG = /^(products?|prices?|plans?|pricing|tiers?|categories|category|tags?|features?|faqs?|countries|currencies|locales?|public_[a-z0-9_]+|catalog[a-z0-9_]*|menu[a-z0-9_]*|posts?|articles?|blog[a-z0-9_]*|changelog[a-z0-9_]*)$/i;

/** Columns that are personal data on ANY table. */
const PERSONAL_COLUMN = /^(e_?mail|email_address|phone|phone_number|mobile|tel|address|address_line\d?|street|postcode|postal_code|zip|zip_code|full_name|first_name|last_name|surname|dob|date_of_birth|birth_?date|birthday|ssn|national_id|passport|id_number|card|card_number|cc_number|iban|bank_account|account_number|payment_method|billing_address|stripe_customer_id|customer_id|tax_id|vat_id|ip|ip_address|gender)$/i;
/** Generic columns that are personal only on a person-like table (products have a `name` too). */
const PERSON_ONLY_COLUMN = /^(name|display_name|username|avatar_url|location|city|country|lat|lng|latitude|longitude|bio)$/i;
const PERSON_TABLE = /(profile|user|account|customer|member|contact|employee|patient|student|lead|people|person|client|subscriber|applicant|candidate)/i;
/** Columns that make a "catalog" table not safe to suppress. */
const SENSITIVE_COLUMN = /(user_?id|owner|created_by|secret|token|api_?key|password|passwd|private|internal|cost|margin)/i;

function personalColumns(table: string, cols: string[]): string[] {
  return cols.filter((c) => PERSONAL_COLUMN.test(c) || (PERSON_TABLE.test(table) && PERSON_ONLY_COLUMN.test(c)));
}

/** Column names from a `create table … ( … )` body (constraints skipped). */
function parseColumns(body: string): string[] {
  const parts: string[] = [];
  let depth = 0;
  let cur = '';
  for (const ch of body) {
    if (ch === '(') depth++;
    if (ch === ')') depth--;
    if (ch === ',' && depth === 0) { parts.push(cur); cur = ''; continue; }
    cur += ch;
  }
  parts.push(cur);
  return parts
    .map((p) => p.replace(/--[^\n]*/g, '').trim())
    .filter((p) => p && !/^(constraint|primary|foreign|unique|check|exclude|like)\b/i.test(p))
    .map((p) => p.match(/^"?([a-z_][a-z0-9_]*)"?/i)?.[1]?.toLowerCase() ?? '')
    .filter(Boolean);
}

/** Every table's columns across all migrations (create table + alter table add column). */
function collectColumns(repo: NonNullable<ScanContext['repo']>): Map<string, Set<string>> {
  const out = new Map<string, Set<string>>();
  const add = (t: string, c: string[]) => { const set = out.get(t) ?? new Set<string>(); c.forEach((x) => set.add(x)); out.set(t, set); };
  for (const file of repo.sqlFiles) {
    const sql = repo.readFile(file) ?? '';
    const createRe = new RegExp(String.raw`create\s+table\s+(?:if\s+not\s+exists\s+)?${QUALIFIED}\s*\(`, 'gi');
    for (const m of sql.matchAll(createRe)) {
      const start = (m.index ?? 0) + m[0].length;
      let depth = 1;
      let i = start;
      for (; i < sql.length && depth > 0; i++) { if (sql[i] === '(') depth++; else if (sql[i] === ')') depth--; }
      add(m[1]!.toLowerCase(), parseColumns(sql.slice(start, i - 1)));
    }
    const alterRe = new RegExp(String.raw`alter\s+table\s+(?:only\s+)?(?:if\s+exists\s+)?${QUALIFIED}\s+add\s+(?:column\s+)?(?:if\s+not\s+exists\s+)?"?([a-z_][a-z0-9_]*)"?`, 'gi');
    for (const m of sql.matchAll(alterRe)) add(m[1]!.toLowerCase(), [m[2]!.toLowerCase()]);
  }
  return out;
}

/** Supabase lets anyone sign up unless the project disables it (config.toml [auth] enable_signup = false). */
function signupOpen(repo: NonNullable<ScanContext['repo']>): boolean {
  const cfg = repo.files.find((f) => /(^|\/)supabase\/config\.toml$/.test(f));
  const text = cfg ? repo.readFile(cfg) ?? '' : '';
  const auth = text.split(/^\s*\[/m).find((sec) => /^auth\]/.test(sec)) ?? '';
  return !/^\s*enable_signup\s*=\s*false\b/m.test(auth);
}

/** The `create policy … on <table> [for <cmd>]` statement a USING clause belongs to. */
function policyFor(sql: string, index: number): { name: string; table: string; cmd: string; toAuthenticated: boolean } {
  const start = sql.toLowerCase().lastIndexOf('create policy', index);
  const stmt = start >= 0 ? sql.slice(start, index) : '';
  const name = stmt.match(/create\s+policy\s+"([^"]*)"/i)?.[1] ?? '';
  const table = stmt.match(new RegExp(String.raw`\son\s+${QUALIFIED}`, 'i'))?.[1]?.toLowerCase() ?? '';
  const cmd = stmt.match(/\sfor\s+(select|insert|update|delete|all)\b/i)?.[1]?.toLowerCase() ?? 'all';
  const toAuthenticated = /\sto\s+authenticated\b/i.test(stmt);
  return { name, table, cmd, toAuthenticated };
}

const SECURITY_DEFINER_VIEW = new RegExp(String.raw`create\s+(?:or\s+replace\s+)?view\s+${QUALIFIED}`, 'gi');

/**
 * The "no RLS → exposed over the anon REST API" risk is Supabase/PostgREST-
 * specific: plain Postgres tables reached only through a backend connection are
 * NOT auto-exposed, so flagging every table as critical there is a false
 * positive. Only claim REST exposure when the repo actually looks like Supabase.
 */
function looksLikeSupabase(repo: NonNullable<ScanContext['repo']>): boolean {
  const deps = repo.packageManifest?.allDeps ?? {};
  if (Object.keys(deps).some((d) => d.startsWith('@supabase/') || d === 'supabase')) return true;
  if (repo.files.some((f) => /(^|\/)supabase\//i.test(f))) return true;
  return repo.sqlFiles.some((f) => {
    const s = repo.readFile(f) ?? '';
    return /\bauth\.uid\s*\(\)|\bauth\.users\b|create\s+policy|enable\s+row\s+level\s+security|\bto\s+(anon|authenticated)\b/i.test(s);
  });
}

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
    const supabase = looksLikeSupabase(repo);
    const columns = collectColumns(repo);
    const openSignup = signupOpen(repo);

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

      // Over-permissive policies, graded by what they allow and on which table.
      for (const m of safeRegexScan(sql, PERMISSIVE)) {
        const p = policyFor(sql, m.index);
        // `to authenticated` limits even `using (true)` to signed-in users.
        const anyone = /true|1\s*=\s*1/i.test(m.match) && !p.toAuthenticated;
        const readOnly = p.cmd === 'select';
        const cols = columns.get(p.table);
        const personal = cols ? personalColumns(p.table, [...cols]) : [];
        const catalogName = PUBLIC_CATALOG.test(p.table) || /\bpublic\b/i.test(p.name);
        const sensitiveCols = cols ? [...cols].some((c) => SENSITIVE_COLUMN.test(c)) : true;

        let severity: Finding['severity'];
        let confidence: Finding['confidence'];
        let title: string;
        let verifyHint: string | undefined;
        if (!readOnly) {
          severity = 'critical';
          confidence = 'high';
          title = anyone
            ? `A Row Level Security policy lets anyone change "${p.table || 'a table'}"`
            : `A Row Level Security policy lets any signed-in user change every row of "${p.table || 'a table'}"`;
        } else if (personal.length) {
          // Personal data readable by anyone, or by any account when strangers can sign up.
          severity = anyone || openSignup ? 'critical' : 'high';
          confidence = 'high';
          title = anyone
            ? `Anyone can read the personal data in "${p.table}"`
            : `Any signed-in user can read the personal data in "${p.table}"${openSignup ? ', and anyone can sign up' : ''}`;
        } else if (!cols) {
          // We can't see this table's columns, so we can't tell what's exposed. Say so; never hide it.
          severity = 'medium';
          confidence = 'low';
          title = `"${p.table || 'A table'}" is readable by ${anyone ? 'anyone' : 'any signed-in user'}`;
          verifyHint = `We couldn't find "${p.table}"'s columns. If it only holds public data (like a catalog), this is fine. If it holds anything private or personal, scope the policy to the owner.`;
        } else if (catalogName && !sensitiveCols) {
          // A public catalog (products, prices, posts) with nothing private in it: the intended design.
          continue;
        } else {
          severity = 'high';
          confidence = 'high';
          title = `${anyone ? 'Anyone' : 'Any signed-in user'} can read every row of "${p.table}"`;
        }
        out.push({
          ruleId: 'DATABASE_RLS_PERMISSIVE_POLICY',
          category: 'database',
          severity,
          cwe: 'CWE-639',
          owasp: 'A01:2021',
          title,
          whyItMatters: anyone
            ? 'A policy of `using (true)` applies to every visitor. On Supabase anyone can call your API with the public key, so every row this policy covers is open to them.'
            : 'A policy like `using (auth.uid() is not null)` checks only that someone is signed in. On Supabase anyone can sign up, so every user can reach every row, not just their own.',
          evidence: `${p.cmd.toUpperCase()} on ${p.table || '?'}${personal.length ? ` (personal: ${personal.slice(0, 4).join(', ')})` : ''}: ${m.match}`,
          location: { file, line: m.line },
          fix: 'Scope the policy to the owner, e.g. `using (auth.uid() = user_id)`.',
          fixPrompt:
            'Rewrite this Supabase RLS policy so it only allows a user to access their own rows, e.g. `using (auth.uid() = user_id)` instead of allowing everyone or every signed-in user.',
          confidence,
          ...(verifyHint ? { verifyHint } : {}),
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

    // Distinct public tables created without RLS.
    const seen = new Set<string>();
    const missing: { table: string; file: string; line: number }[] = [];
    for (const c of created) {
      if (rlsEnabled.has(c.table) || seen.has(c.table)) continue;
      seen.add(c.table);
      missing.push(c);
    }

    // Only a real risk for Supabase/PostgREST (public anon REST exposure); a plain
    // Postgres schema reached only from a backend isn't auto-exposed. Group all
    // missing tables into ONE finding — 20 identical cards is noise, not signal.
    if (supabase && missing.length > 0) {
      const NOTE =
        ' This applies if the tables are reachable through Supabase’s API (PostgREST) with your public anon key; it is not a risk if the database is only reached from your backend.';
      const first = missing[0]!;
      if (missing.length === 1) {
        out.push({
          ruleId: 'DATABASE_RLS_DISABLED',
          category: 'database',
          severity: 'critical',
          cwe: 'CWE-1220',
          owasp: 'A01:2021',
          title: `Table "${first.table}" has no Row Level Security`,
          whyItMatters:
            'Without RLS, anyone with your public anon key can read (and often write) every row in this table directly over the REST API.' + NOTE,
          location: { file: first.file, line: first.line },
          fix: `Run: ALTER TABLE ${first.table} ENABLE ROW LEVEL SECURITY; then add owner-scoped policies.`,
          fixPrompt: `Enable Row Level Security on the "${first.table}" table and add policies so users can only access their own rows (e.g. using (auth.uid() = user_id)).`,
          confidence: 'high',
          mode: 'whitebox',
          source: 'native',
        });
      } else {
        const names = missing.map((m) => m.table);
        const list = names.map((n) => `"${n}"`).join(', ');
        out.push({
          ruleId: 'DATABASE_RLS_DISABLED',
          category: 'database',
          severity: 'critical',
          cwe: 'CWE-1220',
          owasp: 'A01:2021',
          title: `${missing.length} tables have no Row Level Security`,
          whyItMatters:
            `Without RLS, anyone with your public anon key can read (and often write) every row of these tables directly over the REST API: ${list}.` + NOTE,
          evidence: names.join(', '),
          location: { file: first.file, line: first.line },
          fix: `Enable RLS on each table (e.g. ALTER TABLE ${names[0]} ENABLE ROW LEVEL SECURITY;) then add owner-scoped policies. Tables: ${list}.`,
          fixPrompt: `Enable Row Level Security on these Supabase tables and add owner-scoped policies (e.g. using (auth.uid() = user_id)) so users can only access their own rows: ${list}.`,
          confidence: 'high',
          mode: 'whitebox',
          source: 'native',
        });
      }
    }

    return out;
  },
};
