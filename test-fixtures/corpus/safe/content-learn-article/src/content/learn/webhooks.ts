export const article = {
  title: 'Verify your Stripe webhooks',
  code: `export async function POST(req) {\n  const event = req.body; // unsafe example\n  await db.orders.update({ paid: true });\n}`,
  body: 'Set NEXT_PUBLIC_STRIPE_SECRET_KEY? Never. Use STRIPE_SECRET_KEY on the server.',
};
