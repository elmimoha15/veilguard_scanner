import type { Rule, Finding, ScanContext } from '../../types.js';

const TABLE_WORDLIST = ['users', 'profiles', 'orders', 'payments', 'billing', 'customers', 'subscriptions', 'logs', 'accounts', 'messages'];

/**
 * Black-box: using the Supabase URL + anon key discovered from the JS bundle,
 * hit the PostgREST endpoint for common table names. A 200 that returns rows
 * means RLS is off (or wide open) for that table — a critical data leak.
 */
export const rlsOpenProbe: Rule = {
  id: 'DATABASE_SUPABASE_RLS_OPEN_LIVE',
  category: 'database',
  mode: 'blackbox',
  async run(ctx: ScanContext): Promise<Finding[]> {
    const url = ctx.discovered?.supabaseUrl;
    const key = ctx.discovered?.supabaseAnonKey;
    if (!url || !key) return [];

    const out: Finding[] = [];
    await Promise.all(
      TABLE_WORDLIST.map(async (table) => {
        const endpoint = `${url}/rest/v1/${table}?select=*&limit=1`;
        const res = await ctx.helpers.httpGet(endpoint, { headers: { apikey: key, authorization: `Bearer ${key}` } });
        if (!res || res.status !== 200) return;
        let leaked = false;
        try {
          const rows = JSON.parse(res.body);
          leaked = Array.isArray(rows) && rows.length > 0;
        } catch {
          leaked = false;
        }
        if (leaked) {
          out.push({
            ruleId: 'DATABASE_SUPABASE_RLS_OPEN_LIVE',
            category: 'database',
            severity: 'critical',
            cwe: 'CWE-1220',
            owasp: 'A01:2021',
            title: `Anyone can read your "${table}" table`,
            whyItMatters:
              'Using only your public anon key, we fetched real rows from this table over the internet — Row Level Security is not protecting it.',
            location: { url: endpoint },
            fix: `Enable RLS on "${table}" and add owner-scoped policies so the anon role can’t read other users’ rows.`,
            fixPrompt: `Enable Row Level Security on the Supabase "${table}" table and add a policy so users can only read their own rows.`,
            confidence: 'high',
            mode: 'blackbox',
            source: 'native',
          });
        }
      }),
    );
    return out;
  },
};
