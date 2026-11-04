-- MuseArena core schema. Clerk owns identity/orgs; Supabase enforces isolation.
-- RLS keys on Clerk JWT claims: sub (user) and o.id (org) via auth.jwt().
-- Requires Clerk registered as Supabase third-party auth provider first.

create table if not exists environments (
  id uuid primary key default gen_random_uuid(),
  org_id text not null,
  created_by text not null,
  spec jsonb not null,
  spec_digest text not null,
  status text not null default 'draft',
  created_at timestamptz not null default now()
);
alter table environments enable row level security;
create policy env_org_isolation on environments
  for all using (org_id = (auth.jwt() -> 'o' ->> 'id'));

create table if not exists deployments (
  id uuid primary key default gen_random_uuid(),
  org_id text not null,
  environment_id uuid not null references environments(id),
  stack_id text not null,
  status text not null default 'pending',
  access_info jsonb not null default '{}',
  cost_estimate_per_hour numeric,
  drift_status text,
  created_at timestamptz not null default now()
);
alter table deployments enable row level security;
create policy dep_org_isolation on deployments
  for all using (org_id = (auth.jwt() -> 'o' ->> 'id'));

create table if not exists runs (
  run_id text primary key,
  org_id text not null,
  deployment_id uuid not null references deployments(id),
  mode text not null,
  spec_digest text not null,
  technique_pack_version text not null,
  truth_layer text not null,
  backend text not null,
  score jsonb,
  created_at timestamptz not null default now()
);
alter table runs enable row level security;
create policy run_org_isolation on runs
  for all using (org_id = (auth.jwt() -> 'o' ->> 'id'));

create table if not exists datasets (
  id uuid primary key default gen_random_uuid(),
  org_id text not null,
  name text not null,
  content_hash text not null,
  format_version int not null default 1,
  split text not null,
  redaction_policy_version text not null,
  storage_path text not null,
  created_at timestamptz not null default now()
);
alter table datasets enable row level security;
create policy ds_org_isolation on datasets
  for all using (org_id = (auth.jwt() -> 'o' ->> 'id'));

-- Audit log: append-only (no update/delete policy), hash-chained by trigger.
create table if not exists audit_log (
  id bigserial primary key,
  org_id text not null,
  actor text not null,
  action text not null,
  subject_type text not null,
  subject_id text not null,
  detail jsonb not null default '{}',
  entry_hash text not null,
  prev_hash text,
  created_at timestamptz not null default now()
);
alter table audit_log enable row level security;
create policy audit_read_own_org on audit_log
  for select using (org_id = (auth.jwt() -> 'o' ->> 'id'));

create or replace function audit_chain_link() returns trigger as $$
begin
  select entry_hash into new.prev_hash from audit_log
    where org_id = new.org_id order by id desc limit 1;
  return new;
end;
$$ language plpgsql security definer;

drop trigger if exists audit_chain_trigger on audit_log;
create trigger audit_chain_trigger
  before insert on audit_log
  for each row execute function audit_chain_link();
