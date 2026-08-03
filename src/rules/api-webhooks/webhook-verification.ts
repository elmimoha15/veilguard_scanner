import type { Rule, Finding, ScanContext } from '../../types.js';
import { isSourceFile } from '../_shared.js';
import { isHandler, isServerRoute } from './_webhook.js';

/**
 * White-box: a webhook handler that reads the request body but never verifies
 * the signature. Heuristic — a file that looks like a webhook route (path or
 * content mentions webhook + a provider) and does NOT call the provider's
 * signature-verification API.
 *
 * Gated on the file being an actual server route handler. React pages and docs
 * that merely *mention* "stripe webhook" / "req.body" in rendered marketing or
 * documentation text (e.g. `<p>unsanitized req.body ...</p>`) are not handlers
 * and previously produced false-positive criticals.
 */
export const webhookVerification: Rule = {
  id: 'API_WEBHOOK_UNVERIFIED',
  category: 'api_webhooks',
  mode: 'whitebox',
  async run(ctx: ScanContext): Promise<Finding[]> {
    const repo = ctx.repo;
    if (!repo) return [];
    const out: Finding[] = [];

    // Verification is often split across files: the route is wired in one file
    // (e.g. index.ts reads the x-hub-signature header) while the HMAC check lives
    // in a handler module it delegates to (e.g. githubWebhook.ts). A per-file
    // check false-flags the wiring file. So first decide, at the REPO level,
    // whether each provider's webhook is verified ANYWHERE — the correct model
    // for the common single-webhook app. (Trade-off: a repo with one verified and
    // one unverified webhook of the same provider could be under-reported; rare,
    // and far better than crying wolf on correctly-secured code.)
    let stripeVerifiedRepo = false;
    let githubVerifiedRepo = false;
    for (const path of repo.files) {
      if (!isSourceFile(path)) continue;
      const c = repo.readFile(path);
      if (!c) continue;
      if (/stripe\.webhooks\.constructEvent\s*\(/.test(c)) stripeVerifiedRepo = true;
      // HMAC verification tied to webhook context (avoid matching password hashing etc.).
      if (/createHmac\s*\(/.test(c) && /timingSafeEqual\s*\(/.test(c) && /(webhook|x-hub-signature)/i.test(c)) {
        githubVerifiedRepo = true;
      }
    }

    for (const path of repo.files) {
      if (!isSourceFile(path)) continue;
      const looksLikeWebhookPath = /webhook|hooks?\//i.test(path);
      const content = repo.readFile(path);
      if (!content) continue;

      // Only real server route handlers can be vulnerable — not UI components.
      if (!isServerRoute(path, content)) continue;

      const mentionsWebhook = looksLikeWebhookPath || /webhook/i.test(content);
      if (!mentionsWebhook) continue;

      // Stripe — verified inline here OR anywhere in the repo it delegates to.
      const isStripe = /stripe/i.test(content);
      if (isStripe && !stripeVerifiedRepo && isHandler(content)) {
        out.push(finding(path, 'stripe'));
        continue;
      }

      // GitHub / generic HMAC — same repo-level treatment.
      const isGithub = /x-hub-signature|github/i.test(content) && /webhook/i.test(content);
      if (isGithub && !githubVerifiedRepo && isHandler(content)) {
        out.push(finding(path, 'github'));
      }
    }
    return out;
  },
};

function finding(file: string, provider: 'stripe' | 'github'): Finding {
  const p = provider === 'stripe' ? 'Stripe' : 'GitHub';
  return {
    ruleId: 'API_WEBHOOK_UNVERIFIED',
    category: 'api_webhooks',
    severity: 'critical',
    cwe: 'CWE-345',
    owasp: 'A08:2021',
    title: `Your ${p} webhook doesn’t verify signatures`,
    whyItMatters:
      provider === 'stripe'
        ? 'Without signature verification, anyone can POST a fake “payment succeeded” event and get paid products for free.'
        : 'Without signature verification, anyone can forge webhook events and trigger your handler.',
    location: { file },
    fix:
      provider === 'stripe'
        ? 'Verify every event with `stripe.webhooks.constructEvent(rawBody, sig, endpointSecret)` before processing, using the raw request body.'
        : 'Compute an HMAC of the raw body with your webhook secret and compare it to the signature header using timingSafeEqual.',
    fixPrompt:
      provider === 'stripe'
        ? 'Add Stripe webhook signature verification: read the raw request body, call stripe.webhooks.constructEvent(rawBody, stripe-signature header, STRIPE_WEBHOOK_SECRET), and reject the request if it throws.'
        : 'Verify the GitHub webhook signature: compute createHmac("sha256", secret) over the raw body and compare with the x-hub-signature-256 header using crypto.timingSafeEqual.',
    confidence: 'medium',
    mode: 'whitebox',
    source: 'native',
  };
}
