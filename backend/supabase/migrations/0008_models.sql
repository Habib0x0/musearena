-- 0008: model registry (F-8).
--
-- One row per model artefact. `served_model` is the exact ID handed to the Meta
-- surface (design §12.19): for a base model it equals `base_model`; a training
-- run must return it before the model may become `ready`. Members read the
-- registry; only the service role writes it.

create table if not exists models (
  id uuid primary key default gen_random_uuid(),
  org_id text not null,
  name text not null,
  version int not null default 1,
  base_model text not null,
  served_model text not null,
  provider text not null check (provider in ('meta', 'meta-modal')),
  status text not null default 'available'
    check (status in ('available', 'training', 'ready', 'failed', 'deprecated')),
  artifact_path text,
  metrics jsonb not null default '{}',
  role text[] not null default '{}'
    check (role <@ array['red', 'blue', 'persona', 'judge']::text[]),
  -- FK to training_runs lands with F-9; this column is deliberately plain.
  training_run_id uuid,
  created_at timestamptz not null default now(),
  unique (org_id, name, version)
);
alter table models enable row level security;
create policy model_org_read on models
  for select to authenticated using (org_id = (auth.jwt() -> 'o' ->> 'id'));
grant select on models to authenticated;
create index if not exists models_org_status on models (org_id, status, created_at desc);
create index if not exists models_org_role on models using gin (role);
