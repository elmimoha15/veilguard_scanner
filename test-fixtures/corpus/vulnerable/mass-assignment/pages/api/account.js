export default async function handler(req, res) {
  const session = await getServerSession(req, res);
  await db.users.update({ where: { id: session.user.id }, data: { isAdmin: req.body.isAdmin } });
  res.json({ ok: true });
}
