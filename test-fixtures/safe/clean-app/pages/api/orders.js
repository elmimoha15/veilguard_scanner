import { getServerSession } from 'next-auth';
import { Pool } from 'pg';

const pool = new Pool({ connectionString: process.env.DATABASE_URL });

export default async function handler(req, res) {
  const session = await getServerSession(req, res);
  if (!session) return res.status(401).json({ error: 'unauthorized' });

  // Parameterized query — user input is a bound parameter, never concatenated.
  const { rows } = await pool.query('SELECT * FROM orders WHERE user_id = $1', [session.user.id]);
  res.status(200).json(rows);
}
