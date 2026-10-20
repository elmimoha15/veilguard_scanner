import { Webhook } from 'svix';
export async function POST(req: Request) {
  const payload = await req.text();
  const wh = new Webhook(process.env.CLERK_WEBHOOK_SECRET!);
  const evt = wh.verify(payload, Object.fromEntries(req.headers)) as any;
  // github users sync
  await db.users.upsert({ where: { id: evt.data.id }, create: {}, update: {} });
  return new Response('ok');
}
