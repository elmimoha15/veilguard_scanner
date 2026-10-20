export function Faq() {
  return (<section>
    <h2>Why is NEXT_PUBLIC_STRIPE_SECRET_KEY dangerous?</h2>
    <p>Anything behind NEXT_PUBLIC_ or VITE_ (like VITE_POLAR_ACCESS_TOKEN) ships to the browser.</p>
    <p>{"Never name a server secret NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY."}</p>
  </section>);
}
