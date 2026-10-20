export const config = {
  db: 'postgres://user:password@localhost:5432/app',
  dbDocker: 'postgres://postgres:postgres@db:5432/postgres',
  stripe: process.env.STRIPE_SECRET_KEY ?? 'sk_live_xxxxxxxxxxxxxxxxxxxxxxxxxxxx',
  aws: 'AKIAIOSFODNN7EXAMPLE',
  apiKey: 'YOUR_API_KEY_HERE',
  token: '<your-token>',
  password: 'changeme',
};
