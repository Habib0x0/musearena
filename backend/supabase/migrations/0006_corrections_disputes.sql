-- 0006: reviewer corrections and versioned label disputes (F-5).
--
-- A correction is append-only: an edit is a new row, and the action it
-- corrects is never overwritten. A label dispute is unique per
-- (org, run, step instant); adjudicating it bumps the version, and the
-- adjudicated label supersedes the auto-label in every later export.

create table if not exists corrections (
  id uuid primary key default gen_random_uuid(),
  org_id text not null,
  trace_id uuid not null references traces(id) on delete cascade,
  reviewer text not null,
  kind text not null check (kind in ('approve', 'reject', 'edit', 'reprompt', 'label')),
  before jsonb not null default '{}',
  after jsonb not null default '{}',
  note text,
  created_at timestamptz not null default now()
);
alter table corrections enable row level security;
create policy correction_org_read on corrections
  for select to authenticated using (org_id = (auth.jwt() -> 'o' ->> 'id'));
create policy correction_org_insert on corrections
  for insert to authenticated with check (org_id = (auth.jwt() -> 'o' ->> 'id'));
-- Append-only: members may read and append, never rewrite history.
grant select, insert on corrections to authenticated;
revoke update, delete on corrections from authenticated;
create index if not exists corrections_trace on corrections (org_id, trace_id, created_at desc);
create index if not exists corrections_kind on corrections (org_id, kind, created_at desc);

create table if not exists label_disputes (
  id uuid primary key default gen_random_uuid(),
  org_id text not null,
  -- No FK: a captured trace may name a run the platform never provisioned.
  run_id text not null,
  step_at timestamptz not null,
  auto_label jsonb not null,
  adjudicated_label jsonb,
  version int not null default 1,
  status text not null default 'pending' check (status in ('pending', 'adjudicated')),
  filed_by text not null,
  adjudicated_by text,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  unique (org_id, run_id, step_at)
);
alter table label_disputes enable row level security;
create policy label_dispute_org_read on label_disputes
  for select to authenticated using (org_id = (auth.jwt() -> 'o' ->> 'id'));
create policy label_dispute_org_insert on label_disputes
  for insert to authenticated with check (org_id = (auth.jwt() -> 'o' ->> 'id'));
create policy label_dispute_org_update on label_disputes
  for update to authenticated using (org_id = (auth.jwt() -> 'o' ->> 'id'))
  with check (org_id = (auth.jwt() -> 'o' ->> 'id'));
grant select, insert, update on label_disputes to authenticated;
revoke delete on label_disputes from authenticated;
create index if not exists label_disputes_run on label_disputes (org_id, run_id, status, created_at desc);
create index if not exists label_disputes_pending on label_disputes (org_id, status, created_at desc);

create or replace function label_dispute_touch() returns trigger as $$
begin
  new.updated_at := now();
  if new.adjudicated_label is not null then
    new.status := 'adjudicated';
  end if;
  return new;
end;
$$ language plpgsql;

drop trigger if exists label_dispute_touch_trigger on label_disputes;
create trigger label_dispute_touch_trigger
  before update on label_disputes
  for each row execute function label_dispute_touch();
