import Stripe from 'stripe';
const stripe = new Stripe(process.env.STRIPE_SECRET_KEY!);
export async function POST(req: Request) {
  const event = stripe.webhooks.constructEvent(await req.text(), req.headers.get('stripe-signature')!, process.env.WH!);
  if (event.type === 'invoice.paid') {
    await db.credits.create({ data: { userId: event.data.object.customer, amount: 100 } });
  }
  return new Response('ok');
}
