create table public.orders (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null,
  total numeric
);

alter table public.orders enable row level security;

create policy "users read their own orders"
  on public.orders
  for select
  using (auth.uid() = user_id);

create policy "users insert their own orders"
  on public.orders
  for insert
  with check (auth.uid() = user_id);
