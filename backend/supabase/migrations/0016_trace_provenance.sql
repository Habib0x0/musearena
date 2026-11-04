-- 0011: trace provenance and blended datasets (real operations, not only
-- synthetic exercises).
--
-- synthetic = produced by a platform exercise; imported = an exported run from
-- an external agentic framework; field = a real, operator-provided observation.
alter table traces add column if not exists source text not null default 'synthetic'
  check (source in ('synthetic', 'imported', 'field'));
alter table traces add column if not exists framework text;
create index if not exists traces_org_source on traces (org_id, source);

-- The sources a snapshot actually carries, so the mix is inspectable without
-- re-deriving it from traces.
alter table datasets add column if not exists sources text[] not null default '{}';
