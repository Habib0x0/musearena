-- F-1: a template version is unique within its owning org. Version allocation
-- reads the current maximum and retries on this constraint when two writers
-- race; without it, that race can silently persist two rows for one version.
create unique index if not exists templates_org_name_version_key
  on templates (org_id, name, version);

create index if not exists templates_org_family_name_version_idx
  on templates (org_id, family, name, version desc);
