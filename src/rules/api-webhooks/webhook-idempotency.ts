import type { Rule, Finding, ScanContext } from '../../types.js';
import { isSourceFile } from '../_shared.js';
import { isServerRoute } from './_webhook.js';

/**
 * White-box webhook-replay / idempotency check. SEPARATE from signature
 * verification (API_WEBHOOK_UNVERIFIED): a handler can verify the signature
 * perfectly and still be replayable if it acts on an event without de-duping.
 *
 * Insecure shape:  verify signature → credit account / grant access → return,
 * with no check that this event.id was already processed. An attacker (or
 * Stripe's own automatic retries) can replay the same signed event and get the
 * side effect applied twice (double credits, double fulfilment).
 *
 * Fires when a webhook route performs a state-changing DB write (or credits an
 * account) but shows NO dedupe guard — neither a lookup of a stored processed
 * event id nor a unique-constraint insert on the event id before acting.
 *
 * FP guard: pure logging / analytics webhooks (write only to a log/audit table,
 * no financial side effect) are expected to be idempotent-agnostic and skipped.
 */

// A state-changing DB call.
const MUTATION = /\.(update|insert|create|upsert|delete|increment|decrement)\s*\(/;
// A crediting/entitlement side effect even without an ORM call shape.
const CREDIT_ASSIGN = /\bcredits?\b[\s\S]{0,40}?[+-]?=/i;
// Money / access side effects that make replay actually harmful.
const FINANCIAL =
  /\b(credit|grant|balance|entitlement|subscription|payment|charge|order|invoice|activate|provision|premium|fulfil|fulfill|refund)\b/i;
// Log/analytics-only sinks — replay here is harmless. Stem-matched (no trailing
// boundary) so camelCase table names like `analyticsLogs` are recognised.
const LOG_TARGET = /\b(log|analytic|audit|metric|telemetry|event_?log)/i;

/** True if the handler already guards against processing the same event twice. */
function hasDedupeGuard(content: string): boolean {
  if (/idempotenc/i.test(content)) return true;
  if (/already[_-]?processed/i.test(content)) return true;
  if (/processed[_-]?events?/i.test(content)) return true;
  if (/webhook[_-]?events?/i.test(content)) return true;
  if (/\bon\s+conflict\b/i.test(content)) return true; // SQL unique-insert no-op
  if (/ignoreDuplicates|onConflictDoNothing/i.test(content)) return true;
  // event id used in a lookup (either order): findUnique/findFirst/select/where/get/has/count.
  const idLookup =
    /(event\.id|eventId|event_id)[\s\S]{0,80}?(findUnique|findFirst|\.select\(|\bwhere\b|\.get\(|\.has\(|\.count\(|exists)/i;
  const lookupId =
    /(findUnique|findFirst|\.select\(|\bwhere\b|\.get\(|\.has\(|\.count\(|exists)[\s\S]{0,80}?(event\.id|eventId|event_id)/i;
  if (idLookup.test(content) || lookupId.test(content)) return true;
  // unique-constraint insert keyed on the event id.
  if (/(insert|create|upsert)[\s\S]{0,140}?(event\.id|eventId|event_id)[\s\S]{0,140}?(unique|conflict)/i.test(content)) {
    return true;
  }
  return false;
}

export const webhookIdempotency: Rule = {
  id: 'API_WEBHOOK_NO_IDEMPOTENCY',
  category: 'api_webhooks',
  mode: 'whitebox',
  async run(ctx: ScanContext): Promise<Finding[]> {
    const repo = ctx.repo;
    if (!repo) return [];
    const out: Finding[] = [];

    for (const path of repo.files) {
      if (!isSourceFile(path)) continue;
      const content = repo.readFile(path);
      if (!content) continue;

      // Must be a real webhook route handler.
      const looksLikeWebhookPath = /webhook|hooks?\//i.test(path);
      if (!looksLikeWebhookPath && !/webhook/i.test(content)) continue;
      if (!isServerRoute(path, content)) continue;

      // Must actually change state (a DB write or a credit side effect).
      const mutation = MUTATION.test(content);
      const financial = FINANCIAL.test(content) || CREDIT_ASSIGN.test(content);
      if (!mutation && !financial) continue;

      // Pure logging/analytics webhook with no financial side effect → skip.
      if (!financial && LOG_TARGET.test(content)) continue;

      // Already de-duped → not vulnerable.
      if (hasDedupeGuard(content)) continue;

      out.push({
        ruleId: 'API_WEBHOOK_NO_IDEMPOTENCY',
        category: 'api_webhooks',
        severity: 'high',
        cwe: 'CWE-799',
        owasp: 'A04:2021',
        title: 'Your webhook can be replayed to run twice',
        whyItMatters:
          'This webhook acts on an event (credits, grants access, or writes to the database) without recording that the event was already handled — so a replay of the same signed event applies the effect again (e.g. double credits or double fulfilment). Providers like Stripe retry automatically, so this fires even without an attacker.',
        location: { file: path },
        fix: 'Persist each processed event id with a unique constraint and no-op on repeats: before acting, insert the event id (or look it up), and if it already exists, return 200 without re-applying the side effect.',
        fixPrompt:
          'Make this webhook handler idempotent: store processed Stripe event ids in a table with a unique constraint on the event id. At the start of the handler, try to insert the event.id (or look it up); if it already exists, return 200 immediately without crediting/granting again. Only apply the side effect for events not seen before.',
        confidence: 'medium',
        mode: 'whitebox',
        source: 'native',
      });
    }
    return out;
  },
};
