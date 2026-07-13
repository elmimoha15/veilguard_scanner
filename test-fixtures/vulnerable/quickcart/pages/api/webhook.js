import { stripe } from '../../lib/stripe';

// Stripe webhook handler that never verifies the signature.
export default async function handler(req, res) {
  const event = req.body; // trusting the body as-is — no constructEvent()

  if (event.type === 'checkout.session.completed') {
    // grant the purchase...
    await fulfillOrder(event.data.object);
  }

  res.status(200).json({ received: true });
}

async function fulfillOrder(_session) {
  // ...
}
