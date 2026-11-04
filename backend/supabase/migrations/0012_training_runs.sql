-- 0012: training runs (F-9).
--
-- A training run pins its dataset snapshot, base model, role, method, config,
-- requester and budget before anything runs. No configured trainer means the
-- run parks in `awaiting_trainer` with its manifest; only a `succeeded` run
-- may point at a `ready` output model. Spend over budget is a cancellation.

alter table models add column if not exists artifact_hash text;

create table if not exists training_runs (
  id uuid primary key default gen_random_uuid(),
  org_id text not null,
  dataset_id uuid not null references datasets(id),
  base_model_id uuid not null references models(id),
  output_model_id uuid references models(id) on delete set null,
  role text not null check (role in ('red', 'blue')),
  method text not null check (method in ('sft', 'dpo', 'lora', 'grpo')),
  config jsonb not null default '{}',
  manifest jsonb not null default '{}',
  status text not null default 'queued'
    check (status in ('queued', 'running', 'succeeded', 'failed', 'cancelled', 'awaiting_trainer')),
  metrics jsonb not null default '{}',
  error text,
  budget_usd numeric not null check (budget_usd > 0),
  spent_usd numeric not null default 0 check (spent_usd >= 0),
  requested_by text not null,
  target_alias text,
  target_environment text check (target_environment in ('staging', 'production')),
  trainer_job_id text,
  approved_by text,
  approved_at timestamptz,
  started_at timestamptz,
  finished_at timestamptz,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);
alter table training_runs enable row level security;
create policy training_run_org_read on training_runs
  for select to authenticated using (org_id = (auth.jwt() -> 'o' ->> 'id'));
-- Writes are the service-role learning API after Clerk role checks.
revoke insert, update, delete on training_runs from public, anon, authenticated;
grant select on training_runs to authenticated;
grant select, insert, update on training_runs to service_role;
create index if not exists training_runs_org_created on training_runs (org_id, created_at desc);
create index if not exists training_runs_org_status on training_runs (org_id, status, created_at desc);
create index if not exists training_runs_dataset on training_runs (org_id, dataset_id);

-- The registry row can now name the run that produced it (0008 left the
-- column deliberately plain until this table existed).
do $$
begin
  if not exists (
    select 1 from pg_constraint where conname = 'models_training_run_fk'
  ) then
    alter table models
      add constraint models_training_run_fk
      foreign key (training_run_id) references training_runs(id) on delete set null;
  end if;
end $$;

create or replace function training_run_touch() returns trigger as $$
begin
  new.updated_at := now();
  return new;
end;
$$ language plpgsql;

drop trigger if exists training_run_touch_trigger on training_runs;
create trigger training_run_touch_trigger
  before update on training_runs
  for each row execute function training_run_touch();
