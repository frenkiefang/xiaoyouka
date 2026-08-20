-- Records the name shown from the URL and the server-side visit time.
-- Client roles have no access to this table; only the Edge Function can invoke
-- the security-definer RPC below through the service_role key.
create table public.name_visits (
  id bigint generated always as identity primary key,
  name text not null,
  visitor_id uuid not null,
  page_path text not null default '/',
  visited_at timestamp not null default (now() at time zone 'Asia/Shanghai'),
  constraint name_visits_name_valid check (
    char_length(name) between 1 and 80
    and name = btrim(name)
    and name !~ '[[:cntrl:]]'
  ),
  constraint name_visits_page_path_valid check (
    char_length(page_path) between 1 and 512
    and left(page_path, 1) = '/'
    and page_path !~ '[[:cntrl:]]'
  )
);

create index name_visits_visitor_name_visited_at_idx
  on public.name_visits (visitor_id, name, visited_at desc);

alter table public.name_visits enable row level security;
revoke all on table public.name_visits from public, anon, authenticated;

-- A transaction-scoped advisory lock makes the 30-minute rule safe even when
-- the same page is opened in several tabs at the same time.
create or replace function public.record_name_visit(
  p_name text,
  p_visitor_id uuid,
  p_page_path text default '/'
)
returns boolean
language plpgsql
security definer
set search_path = public, pg_temp
as $$
declare
  v_name text := btrim(p_name);
  v_page_path text := coalesce(nullif(btrim(p_page_path), ''), '/');
  v_now timestamp := now() at time zone 'Asia/Shanghai';
begin
  if p_visitor_id is null
    or v_name = ''
    or char_length(v_name) > 80
    or v_name ~ '[[:cntrl:]]'
    or char_length(v_page_path) > 512
    or left(v_page_path, 1) <> '/'
    or v_page_path ~ '[[:cntrl:]]' then
    raise exception 'Invalid visit payload' using errcode = '22023';
  end if;

  perform pg_advisory_xact_lock(hashtext(p_visitor_id::text || chr(31) || v_name));

  if exists (
    select 1
    from public.name_visits
    where visitor_id = p_visitor_id
      and name = v_name
      and visited_at > v_now - interval '30 minutes'
  ) then
    return false;
  end if;

  insert into public.name_visits (name, visitor_id, page_path, visited_at)
  values (v_name, p_visitor_id, v_page_path, v_now);

  return true;
end;
$$;

-- SECURITY DEFINER functions are executable by PUBLIC by default. Keep this
-- RPC private so an unauthenticated browser cannot invoke it directly.
revoke all on function public.record_name_visit(text, uuid, text)
  from public, anon, authenticated;
grant execute on function public.record_name_visit(text, uuid, text)
  to service_role;
