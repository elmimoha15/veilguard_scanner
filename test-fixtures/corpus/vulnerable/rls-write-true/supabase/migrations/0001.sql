create table public.orders (id uuid primary key);
alter table public.orders enable row level security;
create policy "anyone can write" on public.orders for all using (true);
