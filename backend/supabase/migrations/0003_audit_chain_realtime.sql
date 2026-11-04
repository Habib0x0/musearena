-- 0003: verifiable audit chain + Realtime (Req §6.2, §6.5).
--
-- Before: entry_hash was computed client-side over a timestamp that is never
-- stored (unrecomputable), did not cover prev_hash, and the service role could
-- UPDATE/DELETE rows. Now the database computes the hash over the stored row
-- AND the previous hash, serializes per-org inserts, and refuses mutation.

create or replace function audit_entry_hash(
  p_prev text, p_org text, p_actor text, p_action text, p_subject_type text,
  p_subject_id text, p_detail jsonb, p_created_at timestamptz
) returns text language sql immutable as $$
  select encode(sha256(convert_to(concat_ws('|',
    coalesce(p_prev, ''), p_org, p_actor, p_action, p_subject_type, p_subject_id,
    p_detail::text, (extract(epoch from p_created_at) * 1000000)::bigint::text
  ), 'UTF8')), 'hex');
$$;

create or replace function audit_chain_link() returns trigger as $$
begin
  -- One writer per org at a time, so two inserts never link to the same prev.
  perform pg_advisory_xact_lock(hashtext('audit:' || new.org_id));
  select entry_hash into new.prev_hash from audit_log
    where org_id = new.org_id order by id desc limit 1;
  new.created_at := coalesce(new.created_at, now());
  new.entry_hash := audit_entry_hash(new.prev_hash, new.org_id, new.actor, new.action,
    new.subject_type, new.subject_id, new.detail, new.created_at);
  return new;
end;
$$ language plpgsql security definer;

create or replace function audit_append_only() returns trigger as $$
begin
  raise exception 'audit_log is append-only (% refused)', tg_op;
end;
$$ language plpgsql;

-- Re-seal existing rows once (their old hashes were not recomputable), in id
-- order per org, before the append-only guard is installed.
do $$
declare r record; prev text; cur_org text := null;
begin
  for r in select * from audit_log order by org_id, id loop
    if cur_org is distinct from r.org_id then prev := null; cur_org := r.org_id; end if;
    update audit_log set prev_hash = prev,
      entry_hash = audit_entry_hash(prev, r.org_id, r.actor, r.action, r.subject_type, r.subject_id, r.detail, r.created_at)
      where id = r.id returning entry_hash into prev;
  end loop;
end $$;

drop trigger if exists audit_append_only_trigger on audit_log;
create trigger audit_append_only_trigger
  before update or delete on audit_log
  for each row execute function audit_append_only();

-- Verification: returns the first row whose link or hash does not recompute
-- (empty result = chain intact for that org).
create or replace function audit_verify(p_org text)
returns table (broken_id bigint, reason text) language plpgsql stable security definer as $$
declare r record; prev text := null;
begin
  for r in select * from audit_log where org_id = p_org order by id loop
    if r.prev_hash is distinct from prev then
      broken_id := r.id; reason := 'prev_hash does not link to previous entry'; return next; return;
    end if;
    if r.entry_hash <> audit_entry_hash(r.prev_hash, r.org_id, r.actor, r.action, r.subject_type, r.subject_id, r.detail, r.created_at) then
      broken_id := r.id; reason := 'entry_hash does not recompute'; return next; return;
    end if;
    prev := r.entry_hash;
  end loop;
end;
$$;
revoke all on function audit_verify(text) from public, anon, authenticated;
grant execute on function audit_verify(text) to service_role;

-- Realtime: deployment/run progress streams to clients (RLS still applies).
do $$
begin
  if not exists (select 1 from pg_publication_tables where pubname = 'supabase_realtime' and tablename = 'deployments') then
    alter publication supabase_realtime add table deployments;
  end if;
  if not exists (select 1 from pg_publication_tables where pubname = 'supabase_realtime' and tablename = 'runs') then
    alter publication supabase_realtime add table runs;
  end if;
end $$;
