export async function POST(req: any) {
  const session = await getServerSession();
  if (!session) return new Response('no', { status: 401 });
  const msg = { role: req.body.role, content: req.body.content };
  await db.messages.create({ data: msg });
  return Response.json({ ok: true });
}
