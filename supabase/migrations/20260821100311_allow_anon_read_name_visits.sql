grant select on table public.name_visits to anon;

create policy "Anonymous visitors can read name visits"
  on public.name_visits
  for select
  to anon
  using (true);
