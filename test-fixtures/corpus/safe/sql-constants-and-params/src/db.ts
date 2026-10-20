const TABLE = 'orders';
const LIMIT = 50;
export async function list(db: any, userId: string) {
  return db.query(`SELECT * FROM ${TABLE} WHERE user_id = $1 LIMIT ${LIMIT}`, [userId]);
}
export async function raw(prisma: any, id: string) {
  return prisma.$queryRawUnsafe('SELECT * FROM orders WHERE id = $1', id);
}
