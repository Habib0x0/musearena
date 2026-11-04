-- Templates + scenario sharing (follow-on platform F-1).
create table if not exists templates (
  id uuid primary key default gen_random_uuid(),
  org_id text not null,
  name text not null,
  family text not null,
  version int not null default 1,
  spec jsonb not null,
  digest text not null,
  shared boolean not null default false,
  share_token text unique,
  created_at timestamptz not null default now()
);
alter table templates enable row level security;
create policy tpl_org_isolation on templates
  for all using (org_id = (auth.jwt() -> 'o' ->> 'id'));
create policy tpl_shared_read on templates
  for select using (shared = true);
