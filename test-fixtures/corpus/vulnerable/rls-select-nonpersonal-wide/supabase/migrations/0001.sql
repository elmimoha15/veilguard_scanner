create table public.invoices_summary (id uuid primary key, total int, status text);
alter table public.invoices_summary enable row level security;
create policy "read all" on public.invoices_summary for select using (true);
