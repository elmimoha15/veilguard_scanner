import type { Rule, Finding, ScanContext } from '../../types.js';

// A SMALL, fixed list of commonly-sensitive table names. This is the ONLY
// enumeration we do — total probe requests are hard-capped at its length.
const TABLE_WORDLIST = [
  'users', 'profiles', 'accounts', 'customers',
  'orders', 'payments', 'subscriptions', 'invoices',
  'billing', 'messages', 'api_keys', 'secrets',
];

// Short per-request timeout so this stays lightweight and non-abusive against
// a live third-party backend.
const PROBE_TIMEOUT_MS = 6000;

/**
 * Black-box: using the Supabase URL + PUBLIC anon/publishable key already
 * shipped to every visitor in the JS bundle, issue READ-ONLY GET requests to
 * the PostgREST endpoint for a small fixed list of common table names. A 200
 * that returns rows means RLS is off (or wide open) for that table — a critical
 * data leak that anyone with a browser could read.
 *
 * SAFETY: strictly read-only and minimal. GET only (the helper exposes no
 * method/body), `limit=1` on every request, at most one row read then
 * discarded (never stored), requests capped at the wordlist length, short
 * timeout each. No writes, no data exfiltration, no auth bypass — only the
 * public key the app already hands to every visitor.
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
        const res = await ctx.helpers.httpGet(endpoint, {
          headers: { apikey: key, authorization: `Bearer ${key}` },
          timeoutMs: PROBE_TIMEOUT_MS,
        });
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
            // Count-only: we confirm readability then discard the row. Row
            // content is NEVER stored in a finding.
            evidence: `"${table}" returned row data to an unauthenticated request (limit=1; row content discarded)`,
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
