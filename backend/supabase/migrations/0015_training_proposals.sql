-- 0015: continual-improvement training proposals (F-12).
--
-- A trigger proposes; it never starts training. Approval converts exactly one
-- proposal into a queued training run (which still needs its own training
-- approval before any spend).

create table if not exists training_proposals (
  id uuid primary key default gen_random_uuid(),
  org_id text not null,
  trigger text not null check (trigger in ('new_traces', 'corrections', 'regression', 'schedule')),
  role text not null check (role in ('red', 'blue')),
  dataset_id uuid references datasets(id) on delete set null,
  dataset_selection jsonb not null default '{}',
  base_model_id uuid references models(id) on delete set null,
  method text not null default 'sft' check (method in ('sft', 'dpo', 'lora', 'grpo')),
  config jsonb not null default '{}',
  budget_usd numeric check (budget_usd is null or budget_usd > 0),
  status text not null default 'proposed' check (status in ('proposed', 'converted', 'rejected')),
  reason text not null,
  detail jsonb not null default '{}',
  training_run_id uuid references training_runs(id) on delete set null,
  created_by text not null,
  decided_by text,
  decided_at timestamptz,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);
alter table training_proposals enable row level security;
create policy training_proposal_org_read on training_proposals
  for select to authenticated using (org_id = (auth.jwt() -> 'o' ->> 'id'));
revoke insert, update, delete on training_proposals from public, anon, authenticated;
grant select on training_proposals to authenticated;
grant select, insert, update on training_proposals to service_role;
create index if not exists training_proposals_org_status
  on training_proposals (org_id, status, created_at desc);

create or replace function training_proposal_touch() returns trigger as $$
begin
  new.updated_at := now();
  return new;
end;
$$ language plpgsql;

drop trigger if exists training_proposal_touch_trigger on training_proposals;
create trigger training_proposal_touch_trigger
  before update on training_proposals
  for each row execute function training_proposal_touch();
