import { createClient } from '@supabase/supabase-js';

// Only public values are used client-side; the URL + anon key come from env.
export const supabase = createClient(
  process.env.NEXT_PUBLIC_SUPABASE_URL,
  process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY,
);
