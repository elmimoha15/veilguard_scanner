// Marketing / educational CONTENT shown to users. These are EXAMPLE snippets in
// copy, not live configuration — a scanner must not flag them as leaked secrets.

export const EXAMPLES = {
  // Example connection strings we show in a "what a leaked DB URL looks like" guide.
  postgres: 'postgres://user:password@host:5432/mydb',
  mongo: 'mongodb+srv://username:password@cluster0.mongodb.net/test',
  interpolated: 'DATABASE_URL=postgres://app:${DB_PASSWORD}@db.internal/app',
};

// The copy-paste fix we teach for missing Supabase RLS (a code sample, not our config).
export const FIX_CLIPBOARD =
  'create policy "read orders" on orders for select using ( auth.uid() = user_id );';

export const HEADLINE = 'Your AI-built app might be leaking data right now.';
