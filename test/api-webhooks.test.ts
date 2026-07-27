import { describe, it, expect } from 'vitest';
import { webhookVerification } from '../src/rules/api-webhooks/webhook-verification.js';
import { webhookIdempotency } from '../src/rules/api-webhooks/webhook-idempotency.js';
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
  it('does NOT fire on a React page that only mentions stripe webhooks in text', async () => {
    const ctx = makeRepoContext({
      'src/app/docs/scanners/page.tsx': `export default function Page(){ return (<div><p>Stripe webhook handlers must verify signatures. Never pass req.body straight to your database.</p></div>); }`,
    });
    expect((await webhookVerification.run(ctx)).length).toBe(0);
  });
  it('still fires on a real webhook handler outside pages/api', async () => {
    const ctx = makeRepoContext({
      'src/server/stripeWebhook.ts': `import {stripe} from '../s'; export async function POST(req){ const event = req.body; if(event.type==='x'){} }`,
    });
    expect((await webhookVerification.run(ctx)).length).toBe(1);
  });
});

describe('API_WEBHOOK_NO_IDEMPOTENCY', () => {
  it('fires on a signed webhook that credits an account with no dedupe', async () => {
    const ctx = makeRepoContext({
      'app/api/webhook/route.ts': `export async function POST(req){
        const event = stripe.webhooks.constructEvent(req.body, sig, secret);
        if (event.type === 'checkout.session.completed') {
          await db.user.update({ where: { id: uid }, data: { credits: { increment: 100 } } });
        }
        return new Response('ok');
      }`,
    });
    const findings = await webhookIdempotency.run(ctx);
    expect(findings.length).toBe(1);
    expect(findings[0]!.ruleId).toBe('API_WEBHOOK_NO_IDEMPOTENCY');
  });

  it('does NOT fire when the event id is looked up before acting', async () => {
    const ctx = makeRepoContext({
      'app/api/webhook/route.ts': `export async function POST(req){
        const event = stripe.webhooks.constructEvent(req.body, sig, secret);
        const seen = await db.processedEvents.findUnique({ where: { eventId: event.id } });
        if (seen) return new Response('ok');
        await db.processedEvents.create({ data: { eventId: event.id } });
        await db.user.update({ where: { id: uid }, data: { credits: { increment: 100 } } });
        return new Response('ok');
      }`,
    });
    expect((await webhookIdempotency.run(ctx)).length).toBe(0);
  });

  it('does NOT fire when a unique-constraint insert on the event id guards it', async () => {
    const ctx = makeRepoContext({
      'app/api/webhook/route.ts': `export async function POST(req){
        const event = stripe.webhooks.constructEvent(req.body, sig, secret);
        await db.query('INSERT INTO webhook_events (id) VALUES ($1) ON CONFLICT DO NOTHING', [event.id]);
        await db.user.update({ where: { id: uid }, data: { credits: { increment: 100 } } });
        return new Response('ok');
      }`,
    });
    expect((await webhookIdempotency.run(ctx)).length).toBe(0);
  });

  it('does NOT fire on a pure logging/analytics webhook', async () => {
    const ctx = makeRepoContext({
      'app/api/webhook/route.ts': `export async function POST(req){
        const event = req.body;
        await db.analyticsLogs.insert({ type: event.type, at: Date.now() });
        return new Response('ok');
      }`,
    });
    expect((await webhookIdempotency.run(ctx)).length).toBe(0);
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
