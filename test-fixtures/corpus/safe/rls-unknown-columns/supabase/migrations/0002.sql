alter table public.widgets enable row level security;
create policy "read" on public.widgets for select using (true);
