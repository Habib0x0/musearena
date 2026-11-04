-- 0010: role-aware dataset builder (F-7, design §3.4).
--
-- A built snapshot names the scenario family it came from, the selection that
-- produced it, and the roles it carries. One family may not straddle splits, so
-- the builder refuses a family that already has a snapshot in another split.
alter table datasets add column if not exists family text;
alter table datasets add column if not exists selection jsonb not null default '{}'::jsonb;
alter table datasets add column if not exists roles text[] not null default '{}';
create index if not exists datasets_org_family on datasets (org_id, family);

-- The model IDs a run pinned, so a built dataset can emit its lineage.
alter table runs add column if not exists model_ids jsonb not null default '{}'::jsonb;
