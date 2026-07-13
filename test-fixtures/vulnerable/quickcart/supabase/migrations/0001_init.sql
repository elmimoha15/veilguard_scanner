-- QuickCart schema

create table public.orders (
  id uuid primary key default gen_random_uuid(),
  user_id uuid,
  total numeric,
  created_at timestamptz default now()
);

-- 'profiles' gets RLS + a broken, over-permissive policy.
create table public.profiles (
  id uuid primary key,
  email text,
  is_admin boolean default false
);

alter table public.profiles enable row level security;

create policy "profiles are viewable by logged in users"
  on public.profiles
  for select
  using (auth.uid() is not null);

-- NOTE: public.orders never gets `enable row level security` — wide open.
