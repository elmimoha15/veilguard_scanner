import { describe, it, expect } from 'vitest';
import { webhookVerification } from '../src/rules/api-webhooks/webhook-verification.js';
import { massAssignment } from '../src/rules/api-webhooks/mass-assignment.js';
import { makeRepoContext } from './helpers.js';

describe('API_WEBHOOK_UNVERIFIED', () => {
  it('fires on a Stripe webhook that never calls constructEvent', async () => {
    const ctx = makeRepoContext({
      'pages/api/webhook.ts': `import {stripe} from '../s'; export async function POST(req){ const event = req.body; if(event.type==='x'){} }`,
    });
    expect((await webhookVerification.run(ctx)).length).toBe(1);
  });
  it('does not fire when constructEvent is used', async () => {
    const ctx = makeRepoContext({
      'pages/api/webhook.ts': `export async function POST(req){ const event = stripe.webhooks.constructEvent(body, sig, secret); }`,
    });
    expect((await webhookVerification.run(ctx)).length).toBe(0);
  });
});

describe('API_MASS_ASSIGNMENT', () => {
  it('fires when privileged fields come from req.body', async () => {
    const ctx = makeRepoContext({
      'api/u.ts': `await db.update({ isAdmin: req.body.isAdmin, tier: req.body.tier });`,
    });
    const findings = await massAssignment.run(ctx);
    expect(findings.length).toBe(1);
    expect(findings[0]!.evidence).toContain('isAdmin');
  });
  it('does not fire on safe field writes', async () => {
    const ctx = makeRepoContext({ 'api/u.ts': `await db.update({ displayName: req.body.name });` });
    expect((await massAssignment.run(ctx)).length).toBe(0);
  });
});
