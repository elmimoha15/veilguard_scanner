const { Pool } = require('pg');

const pool = new Pool({ connectionString: process.env.DATABASE_URL });

// SQL injection: user input concatenated straight into the query string.
async function getOrdersByUser(userId) {
  const sql = 'SELECT * FROM orders WHERE user_id = ' + userId;
  const { rows } = await pool.query(sql);
  return rows;
}

// Also unsafe: template literal with interpolation.
async function searchProducts(term) {
  return pool.query(`SELECT * FROM products WHERE name LIKE '%${term}%'`);
}

module.exports = { getOrdersByUser, searchProducts };
