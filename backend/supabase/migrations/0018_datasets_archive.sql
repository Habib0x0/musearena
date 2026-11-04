-- 0018: curation lifecycle (CRUD closure) without breaking append-only evidence.
--
-- Traces are hash-chained and append-only (0011): physically deleting one
-- would break prev_hash linkage for the rest of the run. Curation therefore
-- tombstones: a tombstoned trace is excluded from dataset builds and signal
-- runs but stays stored, readable and chained. Dataset rename/archive are
-- metadata operations on immutable snapshots and go through the audited
-- service-role routes, never a member client (members keep read-only, matching
-- the storage objects' own no-update/no-delete posture from 0004).

alter table traces add column if not exists tombstoned_at timestamptz;
alter table traces add column if not exists tombstone_reason text;
create index if not exists traces_org_tombstoned on traces (org_id, tombstoned_at);

alter table datasets add column if not exists archived_at timestamptz;
create index if not exists datasets_org_archived on datasets (org_id, archived_at);

drop policy if exists ds_org_isolation on datasets;
create policy ds_org_read on datasets
  for select to authenticated using (org_id = (auth.jwt() -> 'o' ->> 'id'));
revoke insert, update, delete on datasets from authenticated;
