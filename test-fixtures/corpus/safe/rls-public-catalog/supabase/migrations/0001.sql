create table public.products (id uuid primary key, name text);
alter table public.products enable row level security;
create policy "Allow public read-only access." on public.products for select using (true);
create table public.prices (id uuid primary key, amount int);
alter table public.prices enable row level security;
create policy "Public prices" on public.prices for select using (true);
