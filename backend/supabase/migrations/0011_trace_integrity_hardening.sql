-- 0011: trace raw-chain integrity + direct-client write hardening.
--
-- The raw trajectory of a trace is append-only and hash-linked per
-- (org, run). Ground-truth labels may still be superseded by the platform's
-- adjudication path (the builder overlays them), but no client may rewrite
-- the trajectory evidence itself. Corrections are fully append-only. Direct
-- authenticated writes are removed: all writes go through the service-role
-- API, which enforces session role and org scoping before it writes.

alter table traces add column if not exists chain_seq bigint;
alter table traces add column if not exists prev_hash text;
alter table traces add column if not exists entry_hash text;

create or replace function trace_entry_hash(
  p_prev text, p_org text, p_run text, p_step int, p_at timestamptz,
  p_host text, p_actor text, p_action text, p_observation text,
  p_reasoning text, p_tool_call text, p_split text, p_payload jsonb,
  p_created_at timestamptz
) returns text language sql immutable as $$
  select encode(sha256(convert_to(concat_ws('|',
    coalesce(p_prev, ''), p_org, p_run, p_step::text,
    (extract(epoch from p_at) * 1000000)::bigint::text,
    coalesce(p_host, ''), coalesce(p_actor, ''), coalesce(p_action, ''),
    coalesce(p_observation, ''), coalesce(p_reasoning, ''),
    coalesce(p_tool_call, ''), p_split,
    coalesce(p_payload -> 'trajectory', 'null'::jsonb)::text,
    (extract(epoch from p_created_at) * 1000000)::bigint::text
  ), 'UTF8')), 'hex');
$$;

create or replace function trace_chain_link() returns trigger as $$
declare
  prev_hash text := null;
  prev_seq bigint := 0;
begin
  perform pg_advisory_xact_lock(hashtext('traces:' || new.org_id || ':' || new.run_id));
  select entry_hash, chain_seq into prev_hash, prev_seq from traces
    where org_id = new.org_id and run_id = new.run_id
    order by chain_seq desc limit 1;
  new.prev_hash := prev_hash;
  new.chain_seq := coalesce(prev_seq, 0) + 1;
  new.created_at := coalesce(new.created_at, now());
  new.entry_hash := trace_entry_hash(
    new.prev_hash, new.org_id, new.run_id, new.step_index, new.at,
    new.host_id, new.actor, new.action, new.observation, new.reasoning,
    new.tool_call, new.split, new.payload, new.created_at);
  return new;
end;
$$ language plpgsql security definer;

-- Seal existing rows once, in a deterministic per-run order, before guards.
do $$
declare
  r record;
  prev text := null;
  seq bigint := 0;
  cur_org text := null;
  cur_run text := null;
begin
  for r in select * from traces order by org_id, run_id, step_index, created_at, id loop
    if cur_org is distinct from r.org_id or cur_run is distinct from r.run_id then
      prev := null;
      seq := 0;
      cur_org := r.org_id;
      cur_run := r.run_id;
    end if;
    seq := seq + 1;
    update traces
      set chain_seq = seq,
          prev_hash = prev,
          entry_hash = trace_entry_hash(
            prev, r.org_id, r.run_id, r.step_index, r.at, r.host_id, r.actor,
            r.action, r.observation, r.reasoning, r.tool_call, r.split,
            r.payload, r.created_at)
      where id = r.id
      returning entry_hash into prev;
  end loop;
end $$;

alter table traces alter column chain_seq set not null;
alter table traces alter column entry_hash set not null;
create unique index if not exists traces_chain_seq on traces (org_id, run_id, chain_seq);

drop trigger if exists trace_chain_link_trigger on traces;
create trigger trace_chain_link_trigger
  before insert on traces
  for each row execute function trace_chain_link();

create or replace function trace_raw_append_only() returns trigger as $$
begin
  if tg_op = 'DELETE' then
    raise exception 'traces are append-only (DELETE refused)';
  end if;
  if old.org_id is distinct from new.org_id
     or old.run_id is distinct from new.run_id
     or old.step_index is distinct from new.step_index
     or old.at is distinct from new.at
     or old.host_id is distinct from new.host_id
     or old.actor is distinct from new.actor
     or old.action is distinct from new.action
     or old.observation is distinct from new.observation
     or old.reasoning is distinct from new.reasoning
     or old.tool_call is distinct from new.tool_call
     or old.split is distinct from new.split
     or old.chain_seq is distinct from new.chain_seq
     or old.prev_hash is distinct from new.prev_hash
     or old.entry_hash is distinct from new.entry_hash
     or old.created_at is distinct from new.created_at
     or (old.payload -> 'trajectory') is distinct from (new.payload -> 'trajectory') then
    raise exception 'the raw trace trajectory is append-only';
  end if;
  return new;
end;
$$ language plpgsql;

drop trigger if exists trace_raw_append_only_trigger on traces;
create trigger trace_raw_append_only_trigger
  before update or delete on traces
  for each row execute function trace_raw_append_only();

-- Verification: returns the first broken link/hash for one run.
create or replace function trace_chain_verify(p_org text, p_run text)
returns table (broken_id uuid, reason text) language plpgsql stable security definer as $$
declare r record; prev text := null;
begin
  for r in select * from traces where org_id = p_org and run_id = p_run order by chain_seq loop
    if r.prev_hash is distinct from prev then
      broken_id := r.id; reason := 'prev_hash does not link to previous trace'; return next; return;
    end if;
    if r.entry_hash <> trace_entry_hash(
        r.prev_hash, r.org_id, r.run_id, r.step_index, r.at, r.host_id,
        r.actor, r.action, r.observation, r.reasoning, r.tool_call,
        r.split, r.payload, r.created_at) then
      broken_id := r.id; reason := 'entry_hash does not recompute'; return next; return;
    end if;
    prev := r.entry_hash;
  end loop;
end;
$$;
revoke all on function trace_chain_verify(text, text) from public, anon, authenticated;
grant execute on function trace_chain_verify(text, text) to service_role;

create or replace function append_only_refuse() returns trigger as $$
begin
  raise exception '% is append-only (% refused)', tg_table_name, tg_op;
end;
$$ language plpgsql;

drop trigger if exists corrections_append_only_trigger on corrections;
create trigger corrections_append_only_trigger
  before update or delete on corrections
  for each row execute function append_only_refuse();

drop trigger if exists label_disputes_no_delete_trigger on label_disputes;
create trigger label_disputes_no_delete_trigger
  before delete on label_disputes
  for each row execute function append_only_refuse();

-- Direct PostgREST clients are readers. Every write is service-role API code
-- after Clerk session/role checks (review) or capture-key checks (capture).
drop policy if exists correction_org_insert on corrections;
drop policy if exists label_dispute_org_insert on label_disputes;
drop policy if exists label_dispute_org_update on label_disputes;
revoke insert, update, delete on traces from public, anon, authenticated;
revoke insert, update, delete on corrections from public, anon, authenticated;
revoke insert, update, delete on label_disputes from public, anon, authenticated;
grant select on traces, corrections, label_disputes to authenticated;

grant select, insert, update on traces to service_role;
grant select, insert on corrections to service_role;
grant select, insert, update on label_disputes to service_role;
revoke delete on traces, corrections, label_disputes from service_role;
