import { createClient } from '@supabase/supabase-js';

// service_role JWT hardcoded in a client-importable module (bypasses RLS).
// (payload role claim = "service_role")
const SERVICE_ROLE =
  'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJyb2xlIjoic2VydmljZV9yb2xlIiwiaXNzIjoic3VwYWJhc2UiLCJpYXQiOjE2MDAwMDAwMDB9.3sVQ0Xm1zJfq0tV8m0m0m0m0m0m0m0m0m0m0m0m0m0';

export const supabase = createClient('https://abcdefghijklmnopqrst.supabase.co', SERVICE_ROLE);
