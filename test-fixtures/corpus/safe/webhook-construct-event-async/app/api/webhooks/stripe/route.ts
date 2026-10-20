import Stripe from 'stripe';
const stripeClient = new Stripe(process.env.STRIPE_SECRET_KEY!);
export async function POST(req: Request) {
  const body = await req.text();
  const sig = req.headers.get('stripe-signature')!;
  const event = await stripeClient.webhooks.constructEventAsync(body, sig, process.env.STRIPE_WEBHOOK_SECRET!);
  if (event.type === 'checkout.session.completed') {
    await supabase.from('subscriptions').upsert({ id: event.data.object.id, status: 'active' });
  }
  return new Response('ok');
}
