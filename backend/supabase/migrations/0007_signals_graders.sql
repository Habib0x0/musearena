-- 0007: signals and graders (F-6).
--
-- A signal is a versioned definition (rule | model | human); a hit is one
-- (signal, trace) pair, unique so re-running an unchanged signal cannot
-- duplicate it. Graders are versioned definitions too; a model grader records
-- the judge model ID in every result, which lives in the hit/result label.

create table if not exists signals (
  id uuid primary key default gen_random_uuid(),
  org_id text not null,
  name text not null,
  kind text not null check (kind in ('rule', 'model', 'human')),
  definition jsonb not null default '{}',
  version int not null default 1,
  enabled boolean not null default true,
  created_at timestamptz not null default now(),
  unique (org_id, name, version)
);
alter table signals enable row level security;
create policy signal_org_read on signals
  for select to authenticated using (org_id = (auth.jwt() -> 'o' ->> 'id'));
create policy signal_org_insert on signals
  for insert to authenticated with check (org_id = (auth.jwt() -> 'o' ->> 'id'));
create policy signal_org_update on signals
  for update to authenticated using (org_id = (auth.jwt() -> 'o' ->> 'id'))
  with check (org_id = (auth.jwt() -> 'o' ->> 'id'));
grant select, insert, update on signals to authenticated;
revoke delete on signals from authenticated;
create index if not exists signals_org_enabled on signals (org_id, enabled, created_at desc);

create table if not exists signal_hits (
  id uuid primary key default gen_random_uuid(),
  org_id text not null,
  signal_id uuid not null references signals(id) on delete cascade,
  trace_id uuid not null references traces(id) on delete cascade,
  label jsonb not null default '{}',
  score double precision,
  created_at timestamptz not null default now(),
  unique (signal_id, trace_id)
);
alter table signal_hits enable row level security;
create policy signal_hit_org_read on signal_hits
  for select to authenticated using (org_id = (auth.jwt() -> 'o' ->> 'id'));
-- Hits are produced by the worker; members read them.
grant select on signal_hits to authenticated;
create index if not exists signal_hits_trace on signal_hits (org_id, trace_id);

create table if not exists graders (
  id uuid primary key default gen_random_uuid(),
  org_id text not null,
  name text not null,
  kind text not null check (kind in ('rubric', 'deterministic', 'model')),
  spec jsonb not null default '{}',
  version int not null default 1,
  enabled boolean not null default true,
  created_at timestamptz not null default now(),
  unique (org_id, name, version)
);
alter table graders enable row level security;
create policy grader_org_read on graders
  for select to authenticated using (org_id = (auth.jwt() -> 'o' ->> 'id'));
create policy grader_org_insert on graders
  for insert to authenticated with check (org_id = (auth.jwt() -> 'o' ->> 'id'));
create policy grader_org_update on graders
  for update to authenticated using (org_id = (auth.jwt() -> 'o' ->> 'id'))
  with check (org_id = (auth.jwt() -> 'o' ->> 'id'));
grant select, insert, update on graders to authenticated;
revoke delete on graders from authenticated;
create index if not exists graders_org_enabled on graders (org_id, enabled, created_at desc);
