create table public.profiles (id uuid primary key, email text);
alter table public.profiles enable row level security;
create policy "staff read" on public.profiles for select using (auth.uid() is not null);
