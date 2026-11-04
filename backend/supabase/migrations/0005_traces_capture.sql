-- 0005: traces + capture keys (F-4).
--
-- A trace is the queryable record of one agent step, joined with the
-- ground-truth outcome it earned. Capture keys let an external harness submit a
-- trace without a Clerk session. Both tables are written only by the service
-- role; members read them, and a capture key's hash is never readable.

create table if not exists traces (
  id uuid primary key default gen_random_uuid(),
  org_id text not null,
  -- Deliberately not a foreign key: an external harness may submit a run the
  -- platform never provisioned, and capture must not require a runs row.
  run_id text not null,
  dataset_id uuid references datasets(id) on delete set null,
  step_index int not null,
  at timestamptz not null,
  host_id text not null default '',
  technique_id text,
  actor text,
  action text,
  observation text,
  reasoning text,
  tool_call text,
  outcome text,
  matched boolean not null default false,
  split text not null default 'train' check (split in ('train', 'val', 'test')),
  payload jsonb not null default '{}',
  created_at timestamptz not null default now(),
  unique (org_id, run_id, step_index)
);
alter table traces enable row level security;
create policy trace_org_read on traces
  for select to authenticated using (org_id = (auth.jwt() -> 'o' ->> 'id'));
-- Explicit, not inherited from ambient defaults: a member may read traces and
-- nothing else. Writes are service-role only (no insert/update policy).
grant select on traces to authenticated;
create index if not exists traces_org_created on traces (org_id, created_at desc);
create index if not exists traces_run on traces (org_id, run_id, step_index);
create index if not exists traces_signal on traces (org_id, technique_id, actor, outcome);

create table if not exists capture_keys (
  id uuid primary key default gen_random_uuid(),
  org_id text not null,
  name text not null,
  -- Display prefix only; the raw key is shown once and never stored.
  key_prefix text not null,
  key_hash text not null unique,
  last_used_at timestamptz,
  revoked_at timestamptz,
  created_at timestamptz not null default now()
);
alter table capture_keys enable row level security;
create policy capture_key_org_read on capture_keys
  for select to authenticated using (org_id = (auth.jwt() -> 'o' ->> 'id'));
-- Members may see what a key is and whether it is revoked, never its hash.
revoke select on capture_keys from authenticated;
grant select (id, org_id, name, key_prefix, last_used_at, revoked_at, created_at)
  on capture_keys to authenticated;
create index if not exists capture_keys_org on capture_keys (org_id, created_at desc);
