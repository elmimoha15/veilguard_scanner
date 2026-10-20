/**
 * Severity honesty. One invariant for every finding, whatever rule produced it:
 *
 *  - LOW confidence (a heuristic match, or anything in docs/content/examples/
 *    tests) is never shown as medium/high/critical. It is reported as `low`
 *    ("Possible: verify") with the severity it WOULD have in `potentialSeverity`
 *    and a `verifyHint` explaining how to check.
 *  - CRITICAL requires HIGH confidence. A medium-confidence "critical" is shown
 *    as high until there's proof.
 *
 * This is what guarantees "a variable name, a word in prose or a comment is
 * never enough for medium+": anything a rule can't prove lands at low.
 */
import type { Finding, Severity, Category } from '../types.js';

const RANK: Record<Severity, number> = { info: 0, low: 1, medium: 2, high: 3, critical: 4 };

/** Generic "how to check" copy per category, used when a rule didn't set one. */
const VERIFY_BY_CATEGORY: Record<Category, string> = {
  secrets: 'Open the file and check whether the value is a real key or a sample. If it is real, rotate it at the provider.',
  database: 'Check the policy or rule in your database dashboard and confirm it only allows what you intend.',
  auth: 'Open the route and confirm it checks who is calling (session, token or middleware) before changing data.',
  injection: 'Trace where the value comes from. If it can come from a user (request, URL, form), it needs escaping or parameters.',
  api_webhooks: 'Open the handler and confirm it verifies the sender and handles repeat deliveries safely.',
  web_config: 'Check the live response headers or config and confirm the setting is what you intend.',
  dependencies: 'Check the installed version in your lockfile. If it is already patched, this does not apply.',
  ai_specific: 'Read the flagged line and confirm it does not weaken security in production.',
  platform: 'Check whether a real secret value is actually shipped to the browser. A variable name alone is not a leak.',
  business_logic: 'Confirm the flow validates input (type, size, ownership) on the server.',
};

export function calibrate(f: Finding): Finding {
  if (f.confidence === 'low' && RANK[f.severity] > RANK.low) {
    return {
      ...f,
      potentialSeverity: f.potentialSeverity ?? f.severity,
      severity: 'low',
      verifyHint: f.verifyHint ?? VERIFY_BY_CATEGORY[f.category],
    };
  }
  if (f.confidence === 'medium' && f.severity === 'critical') {
    return { ...f, potentialSeverity: f.potentialSeverity ?? 'critical', severity: 'high' };
  }
  return f;
}
