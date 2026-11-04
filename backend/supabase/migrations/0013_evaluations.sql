-- 0013: held-out evaluations (F-10).
--
-- Every row pins its candidate, its registered baseline, and a digest-pinned
-- test-split suite. Metrics/comparison stay empty until real trials produce
-- them; a missing runner is a failed evaluation, never fabricated numbers.

create table if not exists evaluations (
  id uuid primary key default gen_random_uuid(),
  org_id text not null,
  model_id uuid not null references models(id),
  baseline_model_id uuid not null references models(id),
  role text not null check (role in ('red', 'blue')),
  suite jsonb not null,
  config jsonb not null default '{}',
  status text not null default 'queued' check (status in ('queued', 'running', 'succeeded', 'failed')),
  metrics jsonb not null default '{}',
  comparison jsonb not null default '{}',
  error text,
  requested_by text not null,
  started_at timestamptz,
  finished_at timestamptz,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);
alter table evaluations enable row level security;
create policy evaluation_org_read on evaluations
  for select to authenticated using (org_id = (auth.jwt() -> 'o' ->> 'id'));
revoke insert, update, delete on evaluations from public, anon, authenticated;
grant select on evaluations to authenticated;
grant select, insert, update on evaluations to service_role;
create index if not exists evaluations_org_created on evaluations (org_id, created_at desc);
create index if not exists evaluations_org_status on evaluations (org_id, status, created_at desc);
create index if not exists evaluations_model on evaluations (org_id, model_id, created_at desc);

create or replace function evaluation_touch() returns trigger as $$
begin
  new.updated_at := now();
  return new;
end;
$$ language plpgsql;

drop trigger if exists evaluation_touch_trigger on evaluations;
create trigger evaluation_touch_trigger
  before update on evaluations
  for each row execute function evaluation_touch();
