create table public.profiles (id uuid primary key, email text);
alter table public.profiles enable row level security;
create policy "read all" on public.profiles for select using (true);
