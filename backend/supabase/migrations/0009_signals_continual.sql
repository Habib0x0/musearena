-- 0009: continual grading (F-6 acceptance 3, Req §2.3.4 + §2.9.1).
--
-- A signal marked continual is applied to every newly persisted trace for the
-- org. Off by default: an operator opts in per signal, so a model signal opts
-- in to the judge cost of one call per new trace.
alter table signals add column if not exists continual boolean not null default false;
create index if not exists signals_org_continual on signals (org_id, continual) where continual;
