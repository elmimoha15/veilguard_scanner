export async function POST(req: Request) {
  const event = await req.json(); // trusts the body
  if (event.type === 'checkout.session.completed') await grantAccess(event.data.object);
  return new Response('ok');
}
// uses stripe events
