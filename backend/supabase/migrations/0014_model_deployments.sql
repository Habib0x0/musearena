-- 0014: model deployments (F-11).
--
-- One active deployment per (org, alias, environment), enforced by a partial
-- unique index. Promotion is gated in the API on a passing evaluation; this
-- schema keeps the previous target row so rollback is a status change, not a
-- reconstruction. Exercise start pins {alias, modelId, trafficPct} into the
-- run record (`runs.deployments`).

create table if not exists model_deployments (
  id uuid primary key default gen_random_uuid(),
  org_id text not null,
  model_id uuid not null references models(id),
  evaluation_id uuid references evaluations(id) on delete set null,
  role text not null check (role in ('red', 'blue', 'persona', 'judge')),
  alias text not null,
  environment text not null check (environment in ('staging', 'production')),
  status text not null default 'pending'
    check (status in ('pending', 'active', 'rolled_back', 'retired')),
  traffic_pct int not null default 100 check (traffic_pct between 0 and 100),
  approved_by text,
  approved_at timestamptz,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);
alter table model_deployments enable row level security;
create policy model_deployment_org_read on model_deployments
  for select to authenticated using (org_id = (auth.jwt() -> 'o' ->> 'id'));
revoke insert, update, delete on model_deployments from public, anon, authenticated;
grant select on model_deployments to authenticated;
grant select, insert, update on model_deployments to service_role;
create unique index if not exists model_deployments_one_active
  on model_deployments (org_id, alias, environment) where status = 'active';
create index if not exists model_deployments_org_created
  on model_deployments (org_id, created_at desc);
create index if not exists model_deployments_role_env
  on model_deployments (org_id, role, environment, status);

alter table runs add column if not exists deployments jsonb not null default '{}'::jsonb;

create or replace function model_deployment_touch() returns trigger as $$
begin
  new.updated_at := now();
  return new;
end;
$$ language plpgsql;

drop trigger if exists model_deployment_touch_trigger on model_deployments;
create trigger model_deployment_touch_trigger
  before update on model_deployments
  for each row execute function model_deployment_touch();
