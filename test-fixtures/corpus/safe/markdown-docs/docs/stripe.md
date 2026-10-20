# Stripe setup
Put `STRIPE_SECRET_KEY=sk_live_...` in your server env, never `NEXT_PUBLIC_STRIPE_SECRET_KEY`.
```ts
const stripe = new Stripe(process.env.STRIPE_SECRET_KEY!);
// webhook: stripe.webhooks.constructEvent(body, sig, secret)
```
