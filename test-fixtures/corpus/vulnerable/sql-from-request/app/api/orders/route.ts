export async function GET(req: any) {
  return db.query(`SELECT * FROM orders WHERE id = ${req.query.id}`);
}
