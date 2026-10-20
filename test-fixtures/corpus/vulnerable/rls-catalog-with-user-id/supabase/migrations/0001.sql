create table public.products (id uuid primary key, name text, user_id uuid, cost numeric);
alter table public.products enable row level security;
create policy "Public products" on public.products for select using (true);
