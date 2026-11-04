-- 0004: dataset artifact storage (Req §4.4, §11.3).
-- Private bucket; objects live under <org_id>/... and are readable only by
-- members of that org (Clerk org claim). Writes are service-role only
-- (workers), and objects are immutable: no update/delete policy exists.

insert into storage.buckets (id, name, public)
values ('datasets', 'datasets', false)
on conflict (id) do nothing;

drop policy if exists datasets_org_read on storage.objects;
create policy datasets_org_read on storage.objects
  for select to authenticated
  using (bucket_id = 'datasets' and (storage.foldername(name))[1] = (auth.jwt() -> 'o' ->> 'id'));

-- One dataset row per (org, content hash): immutable snapshots, no duplicates.
create unique index if not exists datasets_org_hash on datasets (org_id, content_hash);
