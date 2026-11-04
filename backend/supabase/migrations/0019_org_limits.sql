-- 0019: per-org budgets and quotas (admin).
--
-- One row per org. A null column means "no limit". The worker enforces these
-- when it claims a pending deployment, so every run path (console, API, CLI
-- workflow) is covered; a refused deployment is failed with the limit named.
-- Members read their org's limits; only the service role writes them.

create table if not exists org_limits (
  org_id text primary key,
  max_concurrent_labs int check (max_concurrent_labs is null or max_concurrent_labs >= 0),
  max_vms_per_lab int check (max_vms_per_lab is null or max_vms_per_lab >= 0),
  max_dollars_per_hour numeric(10, 2) check (max_dollars_per_hour is null or max_dollars_per_hour >= 0),
  monthly_budget_usd numeric(12, 2) check (monthly_budget_usd is null or monthly_budget_usd >= 0),
  max_ttl_hours numeric(6, 2) check (max_ttl_hours is null or max_ttl_hours > 0),
  -- Emergency stop: while true, no new deployment is claimed for this org.
  paused boolean not null default false,
  updated_by text,
  updated_at timestamptz not null default now()
);
alter table org_limits enable row level security;
create policy org_limits_org_read on org_limits
  for select to authenticated using (org_id = (auth.jwt() -> 'o' ->> 'id'));
grant select on org_limits to authenticated;
