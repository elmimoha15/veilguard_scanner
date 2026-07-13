import type { Rule, Finding, ScanContext } from '../../types.js';
import { isSourceFile } from '../_shared.js';

/**
 * White-box: a webhook handler that reads the request body but never verifies
 * the signature. Heuristic — a file that looks like a webhook route (path or
 * content mentions webhook + a provider) and does NOT call the provider's
 * signature-verification API.
 */
export const webhookVerification: Rule = {
  id: 'API_WEBHOOK_UNVERIFIED',
  category: 'api_webhooks',
  mode: 'whitebox',
  async run(ctx: ScanContext): Promise<Finding[]> {
    const repo = ctx.repo;
    if (!repo) return [];
    const out: Finding[] = [];

    for (const path of repo.files) {
      if (!isSourceFile(path)) continue;
      const looksLikeWebhookPath = /webhook|hooks?\//i.test(path);
      const content = repo.readFile(path);
      if (!content) continue;

      const mentionsWebhook = looksLikeWebhookPath || /webhook/i.test(content);
      if (!mentionsWebhook) continue;

      // Stripe
      const isStripe = /stripe/i.test(content);
      const stripeVerified = /stripe\.webhooks\.constructEvent\s*\(/.test(content);
      if (isStripe && !stripeVerified && isHandler(content)) {
        out.push(finding(path, 'stripe'));
        continue;
      }

      // GitHub / generic HMAC
      const isGithub = /x-hub-signature|github/i.test(content) && /webhook/i.test(content);
      const hmacVerified = /createHmac\s*\(|timingSafeEqual\s*\(/.test(content);
      if (isGithub && !hmacVerified && isHandler(content)) {
        out.push(finding(path, 'github'));
      }
    }
    return out;
  },
};

function isHandler(content: string): boolean {
  return /req\.body|request\.body|await\s+req\.(text|json)\(\)|export\s+(async\s+)?function\s+POST|export\s+const\s+POST/.test(content);
}

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
