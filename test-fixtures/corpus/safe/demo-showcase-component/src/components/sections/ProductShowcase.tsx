const FAKE = [
  { sev: 'CRITICAL', title: '"NEXT_PUBLIC_STRIPE_SECRET_KEY" is a secret exposed to the browser', where: '.env' },
  { sev: 'WARNING', title: '"VITE_POLAR_ACCESS_TOKEN" is exposed', where: 'frontend/.env.example' },
  { sev: 'CRITICAL', title: 'Stripe key sk_live_51Mrt8K2eZv... found', where: 'lib/stripe.ts' },
];
export function ProductShowcase() { return <ul>{FAKE.map((f) => <li key={f.title}>{f.title}</li>)}</ul>; }
