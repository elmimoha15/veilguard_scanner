create table public.customers (id uuid primary key, full_name text, phone text, plan text);
alter table public.customers enable row level security;
create policy "signed in can read" on public.customers for select to authenticated using (true);
